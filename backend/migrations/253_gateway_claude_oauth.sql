-- Claude owns independent lifecycle journals; the Codex journals and guards are unchanged.
CREATE TABLE gateway_claude_principal_claims (
 account_uuid uuid NOT NULL, organization_uuid uuid NOT NULL,
 consumer text COLLATE "C" NOT NULL, owner_ref text COLLATE "C" NOT NULL, account_ref text COLLATE "C" NOT NULL,
 PRIMARY KEY(account_uuid,organization_uuid), UNIQUE(consumer,account_ref)
);
CREATE TABLE gateway_claude_connect_intents (
 consumer text COLLATE "C" NOT NULL, operation_ref text COLLATE "C" NOT NULL,
 owner_ref text COLLATE "C" NOT NULL, account_ref text COLLATE "C" NOT NULL,
 generation uuid NOT NULL UNIQUE, purpose text NOT NULL CHECK(purpose='provider-oauth-bundle-v1'),
 state_hash text NOT NULL UNIQUE CHECK(state_hash ~ '^[0-9a-f]{64}$'),
 material_envelope text NOT NULL, deadline timestamptz NOT NULL CHECK(isfinite(deadline)),
 recovery_uncertain boolean NOT NULL DEFAULT false,
 state text NOT NULL DEFAULT 'prepared' CHECK(state IN ('prepared','exchanging','completed','erased')),
 account_id bigint UNIQUE REFERENCES accounts(id), native_created_at timestamptz,
 account_uuid uuid, organization_uuid uuid, refresh_operation text, refresh_state text NOT NULL DEFAULT 'idle' CHECK(refresh_state IN ('idle','exchanging','completed')),
 credential_revision bigint NOT NULL DEFAULT 1 CHECK(credential_revision>0),
 PRIMARY KEY(consumer,operation_ref),
 FOREIGN KEY(account_uuid,organization_uuid) REFERENCES gateway_claude_principal_claims(account_uuid,organization_uuid),
 CHECK ((account_id IS NULL AND native_created_at IS NULL AND account_uuid IS NULL AND organization_uuid IS NULL) OR
 (account_id IS NOT NULL AND native_created_at IS NOT NULL AND account_uuid IS NOT NULL AND organization_uuid IS NOT NULL)),
 CHECK(state<>'completed' OR account_id IS NOT NULL),
 CHECK((state IN ('completed','erased') AND material_envelope='') OR
 (state IN ('prepared','exchanging') AND public.gateway_oauth_envelope_valid(to_jsonb(material_envelope))))
);
CREATE TABLE gateway_claude_refresh_attempts (
 consumer text COLLATE "C" NOT NULL, operation_ref text COLLATE "C" NOT NULL,
 account_id bigint NOT NULL REFERENCES gateway_claude_connect_intents(account_id),
 generation uuid NOT NULL, expected_revision bigint NOT NULL CHECK(expected_revision>0),
 state text NOT NULL CHECK(state IN ('exchanging','completed')),
 PRIMARY KEY(consumer,operation_ref)
);
CREATE TABLE gateway_claude_limits_snapshots (
 account_id bigint PRIMARY KEY REFERENCES gateway_claude_connect_intents(account_id),
 native_created_at timestamptz NOT NULL CHECK(isfinite(native_created_at)), generation uuid NOT NULL,
 principal_version text NOT NULL CHECK(principal_version ~ '^[0-9a-f]{64}$'),
 revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 9007199254740991),
 observed_at timestamptz NOT NULL CHECK(isfinite(observed_at)),
 raw_snapshot jsonb NOT NULL CHECK(jsonb_typeof(raw_snapshot)='object' AND octet_length(raw_snapshot::text)<=8192)
);
CREATE FUNCTION gateway_claude_claim_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'Claude principal ownership is permanent' USING ERRCODE='23514'; END;
$$;
CREATE TRIGGER gateway_claude_claim_guard BEFORE UPDATE OR DELETE ON gateway_claude_principal_claims FOR EACH ROW EXECUTE FUNCTION gateway_claude_claim_guard();
CREATE FUNCTION gateway_claude_intent_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Claude intent must be retained' USING ERRCODE='23514'; END IF;
 IF (to_jsonb(NEW)-ARRAY['state','material_envelope','account_id','native_created_at','account_uuid','organization_uuid','refresh_operation','refresh_state','credential_revision','recovery_uncertain']) IS DISTINCT FROM
 (to_jsonb(OLD)-ARRAY['state','material_envelope','account_id','native_created_at','account_uuid','organization_uuid','refresh_operation','refresh_state','credential_revision','recovery_uncertain'])
 OR (OLD.account_id IS NOT NULL AND ROW(NEW.account_id,NEW.native_created_at,NEW.account_uuid,NEW.organization_uuid) IS DISTINCT FROM ROW(OLD.account_id,OLD.native_created_at,OLD.account_uuid,OLD.organization_uuid))
 OR (OLD.state='erased' AND NEW IS DISTINCT FROM OLD)
 OR NOT (NEW.state=OLD.state OR OLD.state='prepared' AND NEW.state IN ('exchanging','erased') OR OLD.state='exchanging' AND NEW.state IN ('completed','erased') OR OLD.state='completed' AND NEW.state='erased')
 OR (NEW.material_envelope IS DISTINCT FROM OLD.material_envelope AND NEW.material_envelope<>'')
 OR (NEW.recovery_uncertain IS DISTINCT FROM OLD.recovery_uncertain AND NOT (OLD.state='exchanging' AND NEW.state='erased' AND NEW.recovery_uncertain))
 OR (NEW.credential_revision IS DISTINCT FROM OLD.credential_revision AND NOT (OLD.state='completed' AND NEW.state='completed' AND OLD.refresh_state='exchanging' AND NEW.refresh_state='completed' AND NEW.credential_revision=OLD.credential_revision+1))
 THEN RAISE EXCEPTION 'immutable Claude intent' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER gateway_claude_intent_guard BEFORE UPDATE OR DELETE ON gateway_claude_connect_intents FOR EACH ROW EXECUTE FUNCTION gateway_claude_intent_guard();
CREATE FUNCTION gateway_claude_account_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE marked boolean; old_marked boolean := false;
BEGIN
 IF TG_OP<>'INSERT' THEN old_marked := COALESCE(OLD.extra,'{}'::jsonb) ? 'gateway_claude_profile_v1'; END IF;
 IF TG_OP='DELETE' THEN
  IF old_marked THEN RAISE EXCEPTION 'retain Claude native birth' USING ERRCODE='23514'; END IF; RETURN OLD;
 END IF;
 marked := COALESCE(NEW.extra,'{}'::jsonb) ? 'gateway_claude_profile_v1';
 IF NOT marked AND NOT old_marked THEN RETURN NEW; END IF;
 IF NOT marked OR NEW.platform<>'anthropic' OR NEW.type<>'oauth' OR NEW.status<>'disabled' OR NEW.schedulable
 OR NEW.proxy_id IS NOT NULL OR NEW.parent_account_id IS NOT NULL
 OR NEW.extra->>'gateway_claude_profile_v1' IS DISTINCT FROM 'anthropic-claude-oauth-messages-v1'
 OR NEW.extra->>'gateway_claude_generation_v1' !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
 OR (NEW.extra-ARRAY['gateway_claude_profile_v1','gateway_claude_generation_v1','gateway_claude_scope_v1'])<>'{}'::jsonb
 OR NEW.extra->'gateway_claude_scope_v1'->>'purpose' IS DISTINCT FROM 'provider-oauth-bundle-v1'
 OR public.gateway_native_scope_valid(jsonb_set(NEW.extra->'gateway_claude_scope_v1','{purpose}','"provider-authorization-v1"'),NEW.extra->>'gateway_claude_generation_v1') IS DISTINCT FROM TRUE
 OR (NEW.credentials-'oauth_bundle')<>'{}'::jsonb
 OR (NEW.deleted_at IS NULL AND public.gateway_oauth_envelope_valid(NEW.credentials->'oauth_bundle') IS DISTINCT FROM TRUE)
 OR (NEW.deleted_at IS NOT NULL AND NEW.credentials<>'{}'::jsonb)
 OR EXISTS(SELECT 1 FROM account_groups WHERE account_id=NEW.id)
 OR (TG_OP='INSERT' AND NOT EXISTS(SELECT 1 FROM gateway_claude_connect_intents c
 WHERE c.consumer=NEW.extra->'gateway_claude_scope_v1'->>'consumer'
 AND c.owner_ref=NEW.extra->'gateway_claude_scope_v1'->>'owner'
 AND c.account_ref=NEW.extra->'gateway_claude_scope_v1'->>'account'
 AND c.generation::text=NEW.extra->>'gateway_claude_generation_v1' AND c.state='exchanging' AND c.account_id IS NULL))
 OR (TG_OP='UPDATE' AND NEW.credentials IS DISTINCT FROM OLD.credentials AND NEW.deleted_at IS NULL AND NOT EXISTS(
 SELECT 1 FROM gateway_claude_connect_intents c JOIN gateway_claude_refresh_attempts r ON r.consumer=c.consumer AND r.operation_ref=c.refresh_operation
 WHERE c.account_id=NEW.id AND c.refresh_state='exchanging' AND r.account_id=NEW.id AND r.generation=c.generation AND r.expected_revision=c.credential_revision AND r.state='completed'))
 OR (TG_OP='UPDATE' AND (NOT old_marked OR ROW(NEW.id,NEW.created_at,NEW.extra,NEW.platform,NEW.type) IS DISTINCT FROM ROW(OLD.id,OLD.created_at,OLD.extra,OLD.platform,OLD.type)
  OR OLD.deleted_at IS NOT NULL AND NEW IS DISTINCT FROM OLD))
 THEN RAISE EXCEPTION 'invalid Claude native birth' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER gateway_claude_account_guard BEFORE INSERT OR UPDATE OR DELETE ON accounts FOR EACH ROW EXECUTE FUNCTION gateway_claude_account_guard();
CREATE FUNCTION gateway_claude_group_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM accounts WHERE id=NEW.account_id AND extra ? 'gateway_claude_profile_v1' FOR SHARE) THEN
 RAISE EXCEPTION 'Claude native birth cannot join scheduler' USING ERRCODE='23514'; END IF; RETURN NEW;
END;
$$;
CREATE TRIGGER gateway_claude_group_guard BEFORE INSERT OR UPDATE ON account_groups FOR EACH ROW EXECUTE FUNCTION gateway_claude_group_guard();
-- Erasure through any authorized retained-custody route also removes passive quota.
CREATE FUNCTION gateway_claude_erase_limits() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.deleted_at IS NOT NULL OR NEW.credentials='{}'::jsonb THEN DELETE FROM gateway_claude_limits_snapshots WHERE account_id=NEW.id; END IF;
 RETURN NULL;
END;
$$;
CREATE TRIGGER gateway_claude_erase_limits AFTER UPDATE ON accounts FOR EACH ROW EXECUTE FUNCTION gateway_claude_erase_limits();

CREATE FUNCTION gateway_claude_refresh_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' OR (to_jsonb(NEW)-'state') IS DISTINCT FROM (to_jsonb(OLD)-'state')
 OR OLD.state<>'exchanging' OR NEW.state<>'completed' THEN
 RAISE EXCEPTION 'immutable Claude refresh attempt' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER gateway_claude_refresh_guard BEFORE UPDATE OR DELETE ON gateway_claude_refresh_attempts FOR EACH ROW EXECUTE FUNCTION gateway_claude_refresh_guard();

CREATE FUNCTION gateway_claude_intent_insert_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.state<>'prepared' OR NEW.account_id IS NOT NULL OR NEW.refresh_operation IS NOT NULL OR NEW.refresh_state<>'idle' OR NEW.credential_revision<>1 OR NEW.recovery_uncertain
 OR NEW.deadline<=clock_timestamp() OR NEW.deadline>clock_timestamp()+interval '10 minutes'
 OR NOT public.gateway_native_scope_valid(jsonb_build_object('consumer',NEW.consumer,'owner',NEW.owner_ref,'account',NEW.account_ref,'generation',NEW.generation::text,'purpose','provider-authorization-v1'),NEW.generation::text)
 THEN RAISE EXCEPTION 'invalid Claude intent birth' USING ERRCODE='23514';END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER gateway_claude_intent_insert_guard BEFORE INSERT ON gateway_claude_connect_intents FOR EACH ROW EXECUTE FUNCTION gateway_claude_intent_insert_guard();
