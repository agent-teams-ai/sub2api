-- Additive custody checkpoint; migration 241 remains byte-for-byte unchanged.
-- This unused opt-in service must start with no reserved native rows. In
-- particular, legacy/plaintext rows are refused, never adopted or re-encrypted.
DO $$ BEGIN
 IF EXISTS (SELECT 1 FROM public.accounts WHERE COALESCE(extra, '{}'::jsonb)
   ?| ARRAY['gateway_generation_v1','gateway_profile_v1','gateway_credential_scope_v1']) THEN
  RAISE EXCEPTION 'native custody requires reserved-row quarantine before migration' USING ERRCODE = '23514';
 END IF;
END $$;

-- Structural validation only: the server-only AES key is never supplied to SQL.
-- Authenticity and exact AAD are checked at provider Authorization construction.
CREATE FUNCTION public.gateway_native_envelope_valid(value jsonb) RETURNS boolean
 LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE parts text[]; nonce bytea; sealed bytea; encoded text;
BEGIN
 IF jsonb_typeof(value) IS DISTINCT FROM 'string' THEN RETURN false; END IF;
 parts := string_to_array(value #>> '{}', '.');
 IF array_length(parts, 1) IS DISTINCT FROM 4 OR parts[1] <> 'gcn1'
  OR parts[2] !~ '^[A-Za-z0-9_-]{1,64}$'
  OR parts[3] !~ '^[A-Za-z0-9_-]{16}$'
  OR length(parts[4]) NOT BETWEEN 23 AND 5483 OR parts[4] !~ '^[A-Za-z0-9_-]+$'
  OR length(parts[4]) % 4 = 1 THEN RETURN false; END IF;
 nonce := decode(translate(parts[3], '-_', '+/'), 'base64');
 sealed := decode(translate(parts[4], '-_', '+/') || repeat('=', (4 - length(parts[4]) % 4) % 4), 'base64');
 IF octet_length(nonce) <> 12 OR octet_length(sealed) NOT BETWEEN 17 AND 4112 THEN RETURN false; END IF;
 encoded := translate(rtrim(replace(encode(sealed, 'base64'), E'\n', ''), '='), '+/', '-_');
 RETURN encoded = parts[4];
EXCEPTION WHEN OTHERS THEN RETURN false;
END;
$$;

CREATE FUNCTION public.gateway_native_scope_valid(scope jsonb, generation text) RETURNS boolean
 LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE ref text; member text;
BEGIN
 IF jsonb_typeof(scope) IS DISTINCT FROM 'object'
  OR NOT (scope ?& ARRAY['consumer','owner','account','generation','purpose'])
  OR (scope - ARRAY['consumer','owner','account','generation','purpose']) <> '{}'::jsonb
  OR jsonb_typeof(scope -> 'generation') IS DISTINCT FROM 'string'
  OR scope ->> 'generation' IS DISTINCT FROM generation
  OR scope -> 'purpose' IS DISTINCT FROM '"provider-authorization-v1"'::jsonb THEN RETURN false; END IF;
 FOREACH member IN ARRAY ARRAY['consumer','owner','account'] LOOP
  IF jsonb_typeof(scope -> member) IS DISTINCT FROM 'string' THEN RETURN false; END IF;
  ref := scope ->> member;
  IF octet_length(ref) NOT BETWEEN 1 AND 200 OR ref <> btrim(ref) OR ref ~ '[[:cntrl:]]' THEN RETURN false; END IF;
 END LOOP;
 RETURN true;
END;
$$;

-- Replace the function under its existing trigger, retaining all 241 identity,
-- staging, group, mutation and tombstone invariants. Custody scope is part of
-- the immutable Extra object. Credentials can only be removed by exact erasure;
-- rotation creates a new generation, rather than replacing a physical key.
CREATE OR REPLACE FUNCTION public.gateway_native_account_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE marked boolean; old_marked boolean; erasing boolean := false;
BEGIN
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

CREATE OR REPLACE FUNCTION public.gateway_native_group_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE descriptor jsonb;
BEGIN
 SELECT extra INTO descriptor FROM public.accounts WHERE id = NEW.account_id FOR SHARE;
 IF COALESCE(descriptor, '{}'::jsonb) ?| ARRAY['gateway_generation_v1','gateway_profile_v1','gateway_credential_scope_v1'] THEN
  RAISE EXCEPTION 'gateway native accounts must remain group-free' USING ERRCODE = '23514';
 END IF;
 RETURN NEW;
END;
$$;

DROP TRIGGER accounts_enforce_openai_long_context_billing_extra ON public.accounts;
CREATE TRIGGER accounts_enforce_openai_long_context_billing_extra
 BEFORE INSERT OR UPDATE OF platform, extra, parent_account_id, quota_dimension ON public.accounts
 FOR EACH ROW
 WHEN (NOT (COALESCE(NEW.extra, '{}'::jsonb) ?| ARRAY['gateway_generation_v1','gateway_profile_v1','gateway_credential_scope_v1']))
 EXECUTE FUNCTION public.enforce_openai_long_context_billing_extra();
