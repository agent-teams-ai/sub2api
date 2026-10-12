-- Optional private gateway prerequisite. Existing JSONB extra remains authority.
-- Refuse legacy reserved markers: migration is not an adoption/backfill tool.
DO $$ BEGIN
 IF EXISTS (SELECT 1 FROM accounts WHERE extra ? 'gateway_generation_v1' OR extra ? 'gateway_profile_v1') THEN
  RAISE EXCEPTION 'reserved gateway markers require quarantine before migration';
 END IF;
END $$;
-- Compose migration 175's BEFORE trigger with private opt-in. Its alphabetically
-- earlier name would otherwise add an eighth extra before the native guard.
-- Key presence (including malformed values) reserves the private boundary;
-- gateway_native_account_guard still validates every marked insert/update.
-- Keep the stock function/events for ordinary mixed-version writers. Native
-- maintainers must requalify this composition when upstream changes that trigger.
DROP TRIGGER accounts_enforce_openai_long_context_billing_extra ON accounts;
CREATE TRIGGER accounts_enforce_openai_long_context_billing_extra
 BEFORE INSERT OR UPDATE OF platform, extra, parent_account_id, quota_dimension ON accounts
 FOR EACH ROW
 WHEN (NOT (COALESCE(NEW.extra, '{}'::jsonb) ?| ARRAY['gateway_generation_v1','gateway_profile_v1']))
 EXECUTE FUNCTION public.enforce_openai_long_context_billing_extra();

CREATE UNIQUE INDEX accounts_gateway_generation_v1_unique
 ON accounts ((extra ->> 'gateway_generation_v1')) WHERE extra ? 'gateway_generation_v1';

CREATE FUNCTION gateway_native_account_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE marked boolean; erasing boolean := false;
BEGIN
 IF TG_OP = 'DELETE' THEN
  IF OLD.extra ? 'gateway_generation_v1' OR OLD.extra ? 'gateway_profile_v1' THEN
   RAISE EXCEPTION 'gateway generation tombstone must be retained' USING ERRCODE = '23514';
  END IF;
  RETURN OLD;
 END IF;
 marked := COALESCE(NEW.extra ? 'gateway_generation_v1', false) OR COALESCE(NEW.extra ? 'gateway_profile_v1', false);
 IF TG_OP = 'UPDATE' THEN
  IF COALESCE(OLD.extra ? 'gateway_generation_v1', false) OR COALESCE(OLD.extra ? 'gateway_profile_v1', false) THEN
   IF NEW.id IS DISTINCT FROM OLD.id OR NEW.created_at IS DISTINCT FROM OLD.created_at
      OR NEW.extra IS DISTINCT FROM OLD.extra
      OR NEW.platform IS DISTINCT FROM OLD.platform OR NEW.type IS DISTINCT FROM OLD.type
      OR (OLD.deleted_at IS NOT NULL AND NEW.deleted_at IS DISTINCT FROM OLD.deleted_at) THEN
    RAISE EXCEPTION 'gateway native generation is immutable' USING ERRCODE = '23514';
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
  IF jsonb_typeof(NEW.extra -> 'gateway_generation_v1') IS DISTINCT FROM 'string'
   OR COALESCE(NEW.extra ->> 'gateway_generation_v1', '') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
   OR NEW.extra ->> 'gateway_generation_v1' = '00000000-0000-0000-0000-000000000000'
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
   OR (NEW.extra - ARRAY['gateway_generation_v1','gateway_profile_v1','gateway_model_v1','openai_responses_mode','openai_passthrough','native_api_key_cancel_on_disconnect','openai_preserve_compatible_reasoning']) <> '{}'::jsonb
   OR NEW.platform <> 'openai' OR NEW.type <> 'apikey' OR NEW.schedulable
   OR NEW.parent_account_id IS NOT NULL OR NEW.proxy_id IS NOT NULL
   OR (NEW.credentials ? 'api_key' AND (jsonb_typeof(NEW.credentials -> 'api_key') IS DISTINCT FROM 'string'
   OR COALESCE(length(btrim(NEW.credentials ->> 'api_key')), 0) = 0
   OR NEW.credentials ->> 'api_key' IS DISTINCT FROM btrim(NEW.credentials ->> 'api_key')
   ))
   OR (NOT (NEW.credentials ? 'api_key') AND (TG_OP = 'INSERT' OR NEW.status <> 'disabled' OR NEW.deleted_at IS NULL))
   OR jsonb_typeof(NEW.credentials -> 'base_url') IS DISTINCT FROM 'string'
   OR COALESCE(length(btrim(NEW.credentials ->> 'base_url')), 0) = 0
   OR (NEW.credentials - ARRAY['api_key','base_url']) <> '{}'::jsonb THEN
   RAISE EXCEPTION 'invalid gateway native candidate' USING ERRCODE = '23514';
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
CREATE TRIGGER gateway_native_account_guard BEFORE INSERT OR UPDATE OR DELETE ON accounts
 FOR EACH ROW EXECUTE FUNCTION gateway_native_account_guard();

CREATE FUNCTION gateway_native_group_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE descriptor jsonb;
BEGIN
 SELECT extra INTO descriptor FROM accounts WHERE id = NEW.account_id FOR SHARE;
 IF COALESCE(descriptor ? 'gateway_generation_v1', false) OR COALESCE(descriptor ? 'gateway_profile_v1', false) THEN
  RAISE EXCEPTION 'gateway native accounts must remain group-free' USING ERRCODE = '23514';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER gateway_native_group_guard BEFORE INSERT OR UPDATE ON account_groups
 FOR EACH ROW EXECUTE FUNCTION gateway_native_group_guard();
