-- F2 is nonexecutable protected staging only. Reservation 243 stays immutable.
-- Version lives in the engine's whole encrypted credential snapshot, never in
-- physical birth generation or owner authorizationEpoch. No existing rows migrate.
CREATE FUNCTION public.gateway_oauth_refresh_envelope_valid(value jsonb, version bigint)
 RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE parts text[];
BEGIN
 IF version < 2 OR jsonb_typeof(value) IS DISTINCT FROM 'string' THEN RETURN false; END IF;
 parts := string_to_array(value #>> '{}','.');
 RETURN array_length(parts,1)=5 AND parts[1]='gco2' AND parts[3]=version::text
  AND public.gateway_oauth_envelope_valid(to_jsonb('gco1.'||parts[2]||'.'||parts[4]||'.'||parts[5]));
EXCEPTION WHEN OTHERS THEN RETURN false;
END;
$$;
CREATE FUNCTION public.gateway_oauth_credential_version(value jsonb)
 RETURNS bigint LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE version bigint;
BEGIN
 IF jsonb_typeof(value) IS DISTINCT FROM 'object' THEN RETURN 0; END IF;
 IF value - 'oauth_bundle' = '{}'::jsonb AND public.gateway_oauth_envelope_valid(value->'oauth_bundle') THEN RETURN 1; END IF;
 IF value - ARRAY['oauth_bundle','credential_version'] <> '{}'::jsonb
  OR jsonb_typeof(value->'credential_version') IS DISTINCT FROM 'string'
  OR value->>'credential_version' !~ '^[1-9][0-9]{0,18}$' THEN RETURN 0; END IF;
 version := (value->>'credential_version')::bigint;
 IF public.gateway_oauth_refresh_envelope_valid(value->'oauth_bundle',version) IS DISTINCT FROM TRUE THEN RETURN 0; END IF;
 RETURN version;
EXCEPTION WHEN OTHERS THEN RETURN 0;
END;
$$;
CREATE TABLE gateway_oauth_refresh_attempts (
 account_id bigint NOT NULL REFERENCES gateway_oauth_identity_reservations(account_id),
 native_created_at timestamptz NOT NULL CHECK (isfinite(native_created_at)),
 consumer text COLLATE "C" NOT NULL,
 owner_ref text COLLATE "C" NOT NULL,
 account_ref text COLLATE "C" NOT NULL,
 generation text COLLATE "C" NOT NULL,
 operation_ref text COLLATE "C" NOT NULL CHECK (octet_length(operation_ref) BETWEEN 1 AND 200 AND operation_ref=btrim(operation_ref) AND operation_ref !~ '[[:cntrl:]]'),
 intent_ref text COLLATE "C" NOT NULL CHECK (octet_length(intent_ref) BETWEEN 1 AND 200 AND intent_ref=btrim(intent_ref) AND intent_ref !~ '[[:cntrl:]]'),
 expected_version bigint NOT NULL CHECK (expected_version BETWEEN 1 AND 9223372036854775806),
 fence bigint NOT NULL CHECK (fence > 0),
 state text NOT NULL CHECK (state IN ('prepared','entered','completed','unknown')),
 deadline timestamptz NOT NULL CHECK (isfinite(deadline)),
 result_version bigint,
 publication_xid xid8,
 PRIMARY KEY (consumer,operation_ref),
 UNIQUE (account_id,expected_version),
 UNIQUE (account_id,fence),
 CHECK (CASE WHEN state='completed' THEN result_version IS NOT NULL AND result_version=expected_version+1 AND publication_xid IS NOT NULL
  ELSE result_version IS NULL AND publication_xid IS NULL END)
);
CREATE FUNCTION public.gateway_oauth_refresh_attempt_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'refresh attempt must be retained' USING ERRCODE='23514'; END IF;
 IF TG_OP='UPDATE' THEN
  IF (to_jsonb(NEW)-ARRAY['fence','state','deadline','result_version','publication_xid']) IS DISTINCT FROM
     (to_jsonb(OLD)-ARRAY['fence','state','deadline','result_version','publication_xid'])
   OR OLD.state IN ('completed','unknown') THEN
   RAISE EXCEPTION 'refresh identity and terminal facts are immutable' USING ERRCODE='23514';
  END IF;
  IF NOT (
   (OLD.state='prepared' AND NEW.state='prepared' AND OLD.deadline<=clock_timestamp()
    AND NEW.fence=OLD.fence+1 AND NEW.deadline>clock_timestamp() AND NEW.deadline<=clock_timestamp()+interval '15 seconds')
   OR (NEW.fence=OLD.fence AND NEW.deadline=OLD.deadline AND (
    (OLD.state='prepared' AND NEW.state='entered' AND OLD.deadline>clock_timestamp())
    OR (NEW.state='unknown' AND OLD.state IN ('prepared','entered'))
    OR (OLD.state='entered' AND NEW.state='completed' AND OLD.deadline>clock_timestamp()
     AND NEW.publication_xid=pg_current_xact_id())))) THEN
   RAISE EXCEPTION 'invalid refresh fence or transition' USING ERRCODE='23514';
  END IF;
 ELSE
  IF NEW.state<>'prepared' OR NEW.fence IS DISTINCT FROM (SELECT COALESCE(max(fence),0)+1 FROM gateway_oauth_refresh_attempts WHERE account_id=NEW.account_id) OR NEW.deadline<=clock_timestamp()
   OR NEW.deadline>clock_timestamp()+interval '15 seconds' THEN
   RAISE EXCEPTION 'invalid refresh preparation' USING ERRCODE='23514';
  END IF;
 END IF;
 -- UNKNOWN records retain ambiguity even after erasure. Every transition that
 -- can authorize entry/publication must match this exact inert engine snapshot.
 IF NEW.state<>'unknown' AND NOT EXISTS (
  SELECT 1 FROM accounts a JOIN gateway_oauth_identity_reservations r ON r.account_id=a.id
  WHERE a.id=NEW.account_id AND a.created_at=NEW.native_created_at
   AND r.consumer=NEW.consumer AND r.owner_ref=NEW.owner_ref AND r.account_ref=NEW.account_ref AND r.generation=NEW.generation
   AND a.extra->>'gateway_generation_v1'=r.generation
   AND a.extra->>'gateway_profile_v1'='openai-oidc-oauth-staging-v1'
   AND a.extra->'gateway_credential_scope_v1'=jsonb_build_object('consumer',r.consumer,'owner',r.owner_ref,'account',r.account_ref,'generation',r.generation,'purpose','provider-oauth-bundle-v1')
   AND a.platform='openai' AND a.type='oauth' AND a.status='disabled' AND NOT a.schedulable
   AND a.proxy_id IS NULL AND a.parent_account_id IS NULL AND a.deleted_at IS NULL
   AND NOT EXISTS(SELECT 1 FROM account_groups g WHERE g.account_id=a.id)
   AND public.gateway_oauth_credential_version(a.credentials)=NEW.expected_version) THEN
  RAISE EXCEPTION 'refresh requires exact birth and credential version' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER gateway_oauth_refresh_attempt_guard BEFORE INSERT OR UPDATE OR DELETE ON gateway_oauth_refresh_attempts
 FOR EACH ROW EXECUTE FUNCTION public.gateway_oauth_refresh_attempt_guard();
-- Completion and whole-bundle publication must commit together. The account
-- guard below requires this transaction's exact completed fenced attempt.
CREATE FUNCTION public.gateway_oauth_refresh_publication_complete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.state='completed' AND NOT EXISTS(SELECT 1 FROM accounts a
  WHERE a.id=NEW.account_id AND a.created_at=NEW.native_created_at
   AND public.gateway_oauth_credential_version(a.credentials)>=NEW.result_version) THEN
  RAISE EXCEPTION 'refresh completion requires atomic publication' USING ERRCODE='23514';
 END IF;
 RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER gateway_oauth_refresh_publication_complete AFTER UPDATE ON gateway_oauth_refresh_attempts
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.gateway_oauth_refresh_publication_complete();

CREATE OR REPLACE FUNCTION public.gateway_native_account_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE marked boolean; old_marked boolean; erasing boolean := false;
BEGIN

 -- The original 242 API-key branch below is retained verbatim; only OAuth changes.
 IF TG_OP <> 'DELETE' AND (NEW.extra ->> 'gateway_profile_v1' = 'openai-oidc-oauth-staging-v1'
  OR (TG_OP = 'UPDATE' AND OLD.extra ->> 'gateway_profile_v1' = 'openai-oidc-oauth-staging-v1')) THEN
  IF TG_OP = 'UPDATE' AND (
   OLD.extra ->> 'gateway_profile_v1' IS DISTINCT FROM 'openai-oidc-oauth-staging-v1'
   OR NEW.id IS DISTINCT FROM OLD.id OR NEW.created_at IS DISTINCT FROM OLD.created_at
   OR NEW.extra IS DISTINCT FROM OLD.extra OR NEW.platform IS DISTINCT FROM OLD.platform
   OR NEW.type IS DISTINCT FROM OLD.type
   OR (OLD.deleted_at IS NOT NULL AND NEW.deleted_at IS DISTINCT FROM OLD.deleted_at)
   OR (NEW.credentials IS DISTINCT FROM OLD.credentials AND NOT (
    NEW.credentials = '{}'::jsonb AND OLD.credentials ? 'oauth_bundle' AND NEW.deleted_at IS NOT NULL)
    AND NOT (
     OLD.deleted_at IS NULL AND NEW.deleted_at IS NULL
     AND (to_jsonb(NEW)-ARRAY['credentials','updated_at'])=(to_jsonb(OLD)-ARRAY['credentials','updated_at'])
     AND public.gateway_oauth_credential_version(NEW.credentials)=public.gateway_oauth_credential_version(OLD.credentials)+1
     AND EXISTS(SELECT 1 FROM gateway_oauth_refresh_attempts f
      WHERE f.account_id=OLD.id AND f.native_created_at=OLD.created_at
       AND f.consumer=OLD.extra->'gateway_credential_scope_v1'->>'consumer'
       AND f.owner_ref=OLD.extra->'gateway_credential_scope_v1'->>'owner'
       AND f.account_ref=OLD.extra->'gateway_credential_scope_v1'->>'account'
       AND f.generation=OLD.extra->>'gateway_generation_v1'
       AND f.expected_version=public.gateway_oauth_credential_version(OLD.credentials)
       AND f.result_version=public.gateway_oauth_credential_version(NEW.credentials)
       AND f.state='completed' AND f.deadline>clock_timestamp()
       AND f.publication_xid=pg_current_xact_id())))) THEN
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
   OR (NEW.credentials ? 'oauth_bundle' AND public.gateway_oauth_credential_version(NEW.credentials)=0)
   OR (TG_OP='INSERT' AND public.gateway_oauth_credential_version(NEW.credentials)<>1)
   OR (NOT (NEW.credentials ? 'oauth_bundle') AND NEW.credentials <> '{}'::jsonb)
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
