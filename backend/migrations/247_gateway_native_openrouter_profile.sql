-- Add the fixed OpenRouter tuple to the current 244 guard. All other guards
-- remain unchanged; existing rows and migration history are not rewritten.
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
    OR (NEW.extra ->> 'gateway_profile_v1' = 'openrouter-openai-responses-apikey-v1'
     AND NEW.extra ->> 'openai_responses_mode' = 'force_responses'
     AND NEW.extra -> 'openai_passthrough' = 'true'::jsonb
     AND NEW.credentials ->> 'base_url' = 'https://openrouter.ai/api/v1'
     AND NEW.extra ->> 'gateway_model_v1' = 'openai/gpt-5.4-mini')
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
