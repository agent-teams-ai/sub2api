-- Additive protected staging only. 241/242 bytes and API-key custody are immutable.
-- Identity is a verified upstream principal, never RR owner authority. Reservation
-- uniqueness is service-wide and retained after erase; reconnect is not implemented.
CREATE TABLE gateway_oauth_identity_reservations (
 issuer text COLLATE "C" NOT NULL CHECK (issuer = 'https://auth.openai.com'),
 subject text COLLATE "C" NOT NULL CHECK (octet_length(subject) BETWEEN 1 AND 200 AND subject=btrim(subject) AND subject !~ '[[:cntrl:]]'),
 consumer text COLLATE "C" NOT NULL,
 owner_ref text COLLATE "C" NOT NULL,
 account_ref text COLLATE "C" NOT NULL,
 generation text COLLATE "C" NOT NULL UNIQUE,
 operation_ref text COLLATE "C" NOT NULL,
 intent_mac text NOT NULL CHECK (intent_mac ~ '^[0-9a-f]{64}$'),
 account_id bigint UNIQUE REFERENCES accounts(id),
 created_at timestamptz NOT NULL DEFAULT NOW(),
 PRIMARY KEY (issuer,subject),
 UNIQUE (consumer,operation_ref)
);
CREATE FUNCTION gateway_oauth_reservation_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'oauth reservation must be retained' USING ERRCODE='23514'; END IF;
 IF NEW.account_id IS NULL OR OLD.account_id IS NOT NULL
  OR (to_jsonb(NEW)-'account_id') IS DISTINCT FROM (to_jsonb(OLD)-'account_id')
  OR NOT EXISTS(SELECT 1 FROM accounts a WHERE a.id=NEW.account_id
   AND a.extra->>'gateway_generation_v1'=NEW.generation
   AND a.extra->>'gateway_profile_v1'='openai-oidc-oauth-staging-v1'
   AND a.extra->'gateway_credential_scope_v1'->>'consumer'=NEW.consumer
   AND a.extra->'gateway_credential_scope_v1'->>'owner'=NEW.owner_ref
   AND a.extra->'gateway_credential_scope_v1'->>'account'=NEW.account_ref) THEN
  RAISE EXCEPTION 'oauth reservation is immutable' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER gateway_oauth_reservation_guard BEFORE UPDATE OR DELETE ON gateway_oauth_identity_reservations
 FOR EACH ROW EXECUTE FUNCTION gateway_oauth_reservation_guard();

-- The transaction must leave exactly one linked inert birth. A crash before
-- commit rolls back both reservation and candidate; a lost commit ACK reads it.
CREATE FUNCTION gateway_oauth_reservation_complete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM gateway_oauth_identity_reservations r
  WHERE r.issuer=NEW.issuer AND r.subject=NEW.subject AND r.account_id IS NOT NULL) THEN
  RAISE EXCEPTION 'oauth reservation requires a durable candidate' USING ERRCODE='23514';
 END IF;
 RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER gateway_oauth_reservation_complete AFTER INSERT OR UPDATE ON gateway_oauth_identity_reservations
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION gateway_oauth_reservation_complete();

CREATE FUNCTION public.gateway_oauth_envelope_valid(value jsonb) RETURNS boolean
 LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE parts text[]; nonce bytea; sealed bytea;
BEGIN
 IF jsonb_typeof(value) IS DISTINCT FROM 'string' THEN RETURN false; END IF;
 parts := string_to_array(value #>> '{}','.');
 IF array_length(parts,1) IS DISTINCT FROM 4 OR parts[1]<>'gco1'
  OR parts[2] !~ '^[A-Za-z0-9_-]{1,64}$' OR parts[3] !~ '^[A-Za-z0-9_-]{16}$'
  OR length(parts[4]) NOT BETWEEN 23 AND 87403 OR parts[4] !~ '^[A-Za-z0-9_-]+$'
  OR length(parts[4]) % 4 = 1 THEN RETURN false; END IF;
 nonce := decode(translate(parts[3],'-_','+/'),'base64');
 sealed := decode(translate(parts[4],'-_','+/') || repeat('=',(4-length(parts[4])%4)%4),'base64');
 RETURN octet_length(nonce)=12 AND octet_length(sealed) BETWEEN 17 AND 65552
  AND translate(rtrim(replace(encode(sealed,'base64'), E'\n',''),'='),'+/','-_')=parts[4];
EXCEPTION WHEN OTHERS THEN RETURN false;
END;
$$;

CREATE OR REPLACE FUNCTION public.gateway_native_account_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE marked boolean; old_marked boolean; erasing boolean := false;
BEGIN

 -- The original 242 API-key branch below is retained verbatim.
 IF TG_OP <> 'DELETE' AND (NEW.extra ->> 'gateway_profile_v1' = 'openai-oidc-oauth-staging-v1'
  OR (TG_OP = 'UPDATE' AND OLD.extra ->> 'gateway_profile_v1' = 'openai-oidc-oauth-staging-v1')) THEN
  IF TG_OP = 'UPDATE' AND (
   OLD.extra ->> 'gateway_profile_v1' IS DISTINCT FROM 'openai-oidc-oauth-staging-v1'
   OR NEW.id IS DISTINCT FROM OLD.id OR NEW.created_at IS DISTINCT FROM OLD.created_at
   OR NEW.extra IS DISTINCT FROM OLD.extra OR NEW.platform IS DISTINCT FROM OLD.platform
   OR NEW.type IS DISTINCT FROM OLD.type
   OR (OLD.deleted_at IS NOT NULL AND NEW.deleted_at IS DISTINCT FROM OLD.deleted_at)
   OR (NEW.credentials IS DISTINCT FROM OLD.credentials AND NOT (
    NEW.credentials = '{}'::jsonb AND OLD.credentials ? 'oauth_bundle' AND NEW.deleted_at IS NOT NULL))) THEN
   RAISE EXCEPTION 'gateway oauth birth and custody are immutable' USING ERRCODE = '23514';
  END IF;
  IF NEW.platform <> 'openai' OR NEW.type <> 'oauth' OR NEW.status <> 'disabled'
   OR NEW.schedulable OR NEW.proxy_id IS NOT NULL OR NEW.parent_account_id IS NOT NULL
   OR jsonb_typeof(NEW.extra) IS DISTINCT FROM 'object'
   OR (NEW.extra - ARRAY['gateway_generation_v1','gateway_profile_v1','gateway_credential_scope_v1']) <> '{}'::jsonb
   OR jsonb_typeof(NEW.extra -> 'gateway_generation_v1') IS DISTINCT FROM 'string'
   OR COALESCE(NEW.extra ->> 'gateway_generation_v1','') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
   OR NEW.extra ->> 'gateway_generation_v1' = '00000000-0000-0000-0000-000000000000'
   OR NEW.extra -> 'gateway_credential_scope_v1' -> 'purpose' IS DISTINCT FROM '"provider-oauth-bundle-v1"'::jsonb
   OR public.gateway_native_scope_valid(
    jsonb_set(NEW.extra -> 'gateway_credential_scope_v1','{purpose}','"provider-authorization-v1"'),
    NEW.extra ->> 'gateway_generation_v1') IS DISTINCT FROM TRUE
   OR jsonb_typeof(NEW.credentials) IS DISTINCT FROM 'object'
   OR (NEW.credentials - 'oauth_bundle') <> '{}'::jsonb
   OR (NEW.credentials ? 'oauth_bundle' AND public.gateway_oauth_envelope_valid(NEW.credentials -> 'oauth_bundle') IS DISTINCT FROM TRUE)
   OR (NOT (NEW.credentials ? 'oauth_bundle') AND (TG_OP = 'INSERT' OR NEW.deleted_at IS NULL))
   OR (TG_OP = 'INSERT' AND NEW.deleted_at IS NOT NULL)
   OR EXISTS(SELECT 1 FROM account_groups g WHERE g.account_id=NEW.id)
   OR NOT EXISTS(SELECT 1 FROM gateway_oauth_identity_reservations r
    WHERE r.generation=NEW.extra ->> 'gateway_generation_v1'
    AND r.consumer=NEW.extra -> 'gateway_credential_scope_v1' ->> 'consumer'
    AND r.owner_ref=NEW.extra -> 'gateway_credential_scope_v1' ->> 'owner'
    AND r.account_ref=NEW.extra -> 'gateway_credential_scope_v1' ->> 'account'
    AND (r.account_id IS NULL OR r.account_id=NEW.id)) THEN
   RAISE EXCEPTION 'invalid protected oauth staging candidate' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
 END IF;
 IF TG_OP = 'DELETE' THEN
  IF COALESCE(OLD.extra, '{}'::jsonb) ?| ARRAY['gateway_generation_v1','gateway_profile_v1','gateway_credential_scope_v1'] THEN
   RAISE EXCEPTION 'gateway generation tombstone must be retained' USING ERRCODE = '23514';
  END IF;
  RETURN OLD;
 END IF;
 marked := COALESCE(NEW.extra, '{}'::jsonb) ?| ARRAY['gateway_generation_v1','gateway_profile_v1','gateway_credential_scope_v1'];
 IF TG_OP = 'UPDATE' THEN
  old_marked := COALESCE(OLD.extra, '{}'::jsonb) ?| ARRAY['gateway_generation_v1','gateway_profile_v1','gateway_credential_scope_v1'];
  IF old_marked THEN
   IF NEW.id IS DISTINCT FROM OLD.id OR NEW.created_at IS DISTINCT FROM OLD.created_at
    OR NEW.extra IS DISTINCT FROM OLD.extra
    OR NEW.platform IS DISTINCT FROM OLD.platform OR NEW.type IS DISTINCT FROM OLD.type
    OR (OLD.deleted_at IS NOT NULL AND NEW.deleted_at IS DISTINCT FROM OLD.deleted_at) THEN
    RAISE EXCEPTION 'gateway native generation and custody scope are immutable' USING ERRCODE = '23514';
   END IF;
   IF NEW.credentials IS DISTINCT FROM OLD.credentials THEN
    erasing := OLD.status = 'disabled' AND NEW.status = 'disabled'
     AND NEW.deleted_at IS NOT NULL AND NEW.credentials = OLD.credentials - 'api_key'
     AND OLD.credentials ? 'api_key';
    IF erasing IS DISTINCT FROM TRUE THEN
     RAISE EXCEPTION 'gateway credential replacement is forbidden' USING ERRCODE = '23514';
    END IF;
   END IF;
  ELSIF marked THEN
   RAISE EXCEPTION 'gateway native identity requires a new candidate' USING ERRCODE = '23514';
  END IF;
 END IF;
 IF marked THEN
  IF jsonb_typeof(NEW.extra) IS DISTINCT FROM 'object'
   OR jsonb_typeof(NEW.extra -> 'gateway_generation_v1') IS DISTINCT FROM 'string'
   OR COALESCE(NEW.extra ->> 'gateway_generation_v1', '') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
   OR NEW.extra ->> 'gateway_generation_v1' = '00000000-0000-0000-0000-000000000000'
   OR public.gateway_native_scope_valid(NEW.extra -> 'gateway_credential_scope_v1', NEW.extra ->> 'gateway_generation_v1') IS DISTINCT FROM TRUE
   OR (
    (NEW.extra ->> 'gateway_profile_v1' = 'openai-responses-apikey-v1'
     AND NEW.extra ->> 'openai_responses_mode' = 'force_responses'
     AND NEW.extra -> 'openai_passthrough' = 'true'::jsonb)
    OR (NEW.extra ->> 'gateway_profile_v1' = 'mimo-token-plan-responses-chat-bridge-v1'
     AND NEW.extra ->> 'openai_responses_mode' = 'force_chat_completions'
     AND NEW.extra -> 'openai_passthrough' = 'false'::jsonb)
   ) IS DISTINCT FROM TRUE
   OR NEW.extra -> 'native_api_key_cancel_on_disconnect' IS DISTINCT FROM 'true'::jsonb
   OR NEW.extra -> 'openai_preserve_compatible_reasoning' IS DISTINCT FROM 'true'::jsonb
   OR jsonb_typeof(NEW.extra -> 'gateway_model_v1') IS DISTINCT FROM 'string'
   OR COALESCE(length(btrim(NEW.extra ->> 'gateway_model_v1')), 0) = 0
   OR (NEW.extra - ARRAY['gateway_generation_v1','gateway_profile_v1','gateway_model_v1','gateway_credential_scope_v1','openai_responses_mode','openai_passthrough','native_api_key_cancel_on_disconnect','openai_preserve_compatible_reasoning']) <> '{}'::jsonb
   OR NEW.platform <> 'openai' OR NEW.type <> 'apikey' OR NEW.schedulable
   OR NEW.parent_account_id IS NOT NULL OR NEW.proxy_id IS NOT NULL
   OR jsonb_typeof(NEW.credentials) IS DISTINCT FROM 'object'
   OR (NEW.credentials ? 'api_key' AND public.gateway_native_envelope_valid(NEW.credentials -> 'api_key') IS DISTINCT FROM TRUE)
   OR (NOT (NEW.credentials ? 'api_key') AND (TG_OP = 'INSERT' OR NEW.status <> 'disabled' OR NEW.deleted_at IS NULL))
   OR jsonb_typeof(NEW.credentials -> 'base_url') IS DISTINCT FROM 'string'
   OR COALESCE(length(btrim(NEW.credentials ->> 'base_url')), 0) = 0
   OR (NEW.credentials - ARRAY['api_key','base_url']) <> '{}'::jsonb THEN
   RAISE EXCEPTION 'invalid encrypted gateway native candidate' USING ERRCODE = '23514';
  END IF;
  IF NEW.deleted_at IS NOT NULL AND NEW.status <> 'disabled' THEN
   RAISE EXCEPTION 'gateway tombstone must stay disabled' USING ERRCODE = '23514';
  END IF;
  IF TG_OP = 'INSERT' AND (NEW.status <> 'disabled' OR NEW.deleted_at IS NOT NULL) THEN
   RAISE EXCEPTION 'gateway native creation must be inert' USING ERRCODE = '23514';
  END IF;
 END IF;
 RETURN NEW;
END;
$$;
