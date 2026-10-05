-- F3 only: durable one-use connect capability, not dispatch or refresh authority.
-- The material key is server-owned, outside DB/backup; no code/token columns.
CREATE TABLE gateway_oauth_connect_intents (
 consumer text COLLATE "C" NOT NULL,
 owner_ref text COLLATE "C" NOT NULL,
 account_ref text COLLATE "C" NOT NULL,
 generation text COLLATE "C" NOT NULL CHECK (generation ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' AND generation<>'00000000-0000-0000-0000-000000000000'),
 purpose text NOT NULL CHECK (purpose='provider-oauth-bundle-v1'),
 operation_ref text COLLATE "C" NOT NULL,
 -- Fresh private F1 operation, distinct from the caller's stable operation.
 enrollment_operation text COLLATE "C" NOT NULL CHECK (enrollment_operation ~ '^connect-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' AND enrollment_operation<>'connect-00000000-0000-0000-0000-000000000000'),
 enrollment_mac text CHECK (enrollment_mac ~ '^[0-9a-f]{64}$'),
 recovery_denied boolean NOT NULL DEFAULT false,
 client_id text NOT NULL CHECK (client_id='app_EMoamEEZ73f0CkXaXp7hrann'),
 redirect_uri text NOT NULL CHECK (redirect_uri='http://localhost:1455/auth/callback'),
 deadline timestamptz NOT NULL,
 state_hash text NOT NULL UNIQUE CHECK (state_hash ~ '^[0-9a-f]{64}$'),
 material_envelope text NOT NULL,
 state text NOT NULL DEFAULT 'prepared' CHECK (state IN ('prepared','entered','unknown','completed','expired')),
 entered_at timestamptz,
 outcome_operation text,
 outcome_account_id bigint,
 outcome_generation text,
 outcome_state text,
 PRIMARY KEY (consumer,operation_ref),
 UNIQUE (consumer,enrollment_operation),
 CHECK (enrollment_operation<>operation_ref),
 CHECK (NOT recovery_denied OR state='unknown'),
 CHECK (state NOT IN ('prepared','expired') OR enrollment_mac IS NULL),
 CHECK (octet_length(consumer) BETWEEN 1 AND 800 AND consumer=btrim(consumer) AND consumer !~ '[[:cntrl:]]'),
 CHECK (octet_length(owner_ref) BETWEEN 1 AND 800 AND owner_ref=btrim(owner_ref) AND owner_ref !~ '[[:cntrl:]]'),
 CHECK (octet_length(account_ref) BETWEEN 1 AND 800 AND account_ref=btrim(account_ref) AND account_ref !~ '[[:cntrl:]]'),
 CHECK (octet_length(operation_ref) BETWEEN 1 AND 800 AND operation_ref=btrim(operation_ref) AND operation_ref !~ '[[:cntrl:]]'),
 CHECK ((state IN ('prepared','entered') AND material_envelope ~ '^gcc1\.[A-Za-z0-9_-]{60,1019}$') OR (state IN ('unknown','completed','expired') AND material_envelope='')),
 CHECK ((state IN ('prepared','expired') AND entered_at IS NULL) OR (state IN ('entered','unknown','completed') AND entered_at IS NOT NULL)),
 CHECK ((state='completed' AND enrollment_mac IS NOT NULL AND outcome_operation IS NOT NULL AND outcome_operation=enrollment_operation
  AND outcome_account_id IS NOT NULL AND outcome_account_id>0 AND outcome_generation IS NOT NULL
  AND outcome_generation=generation AND outcome_state IS NOT NULL AND outcome_state='staged')
  OR (state<>'completed' AND outcome_operation IS NULL AND outcome_account_id IS NULL AND outcome_generation IS NULL AND outcome_state IS NULL))
);

-- Replay tombstones/unknown evidence are retained, never TTL-deleted or rearmed.
CREATE FUNCTION gateway_oauth_connect_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'connect evidence must be retained' USING ERRCODE='23514'; END IF;
 IF TG_OP='INSERT' THEN
  -- Shared with the F1 insertion guard below: a preexisting enrollment cannot
  -- be appropriated by a connect, even at a private-operation collision.
  PERFORM pg_advisory_xact_lock(hashtextextended(NEW.consumer || chr(1) || NEW.enrollment_operation,245));
  IF EXISTS(SELECT 1 FROM gateway_oauth_identity_reservations r
   WHERE r.consumer=NEW.consumer AND r.operation_ref=NEW.enrollment_operation) THEN
   RAISE EXCEPTION 'connect enrollment operation is already owned' USING ERRCODE='23514';
  END IF;
  IF NEW.state<>'prepared' OR NEW.entered_at IS NOT NULL OR NEW.enrollment_mac IS NOT NULL OR NEW.recovery_denied OR NEW.deadline<=clock_timestamp()
   OR NEW.deadline>clock_timestamp()+interval '10 minutes' THEN
   RAISE EXCEPTION 'invalid prepared connect' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
 END IF;
 IF (to_jsonb(NEW)-ARRAY['state','material_envelope','entered_at','outcome_operation','outcome_account_id','outcome_generation','outcome_state','enrollment_mac','recovery_denied'])
  IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['state','material_envelope','entered_at','outcome_operation','outcome_account_id','outcome_generation','outcome_state','enrollment_mac','recovery_denied']) THEN
  RAISE EXCEPTION 'connect intent is immutable' USING ERRCODE='23514';
 END IF;
 IF OLD.recovery_denied OR (OLD.enrollment_mac IS NOT NULL AND NEW.enrollment_mac IS DISTINCT FROM OLD.enrollment_mac) THEN
  RAISE EXCEPTION 'connect custody binding is sealed' USING ERRCODE='23514';
 END IF;
 IF NEW.enrollment_mac IS DISTINCT FROM OLD.enrollment_mac THEN
  IF OLD.state NOT IN ('entered','unknown') OR NEW.state IS DISTINCT FROM OLD.state
   OR NEW.material_envelope IS DISTINCT FROM OLD.material_envelope OR NEW.entered_at IS DISTINCT FROM OLD.entered_at
   OR NEW.recovery_denied IS DISTINCT FROM OLD.recovery_denied
   OR EXISTS(SELECT 1 FROM gateway_oauth_identity_reservations r WHERE r.consumer=NEW.consumer AND r.operation_ref=NEW.enrollment_operation) THEN
   RAISE EXCEPTION 'connect binding denied' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
 END IF;
 IF NEW.state='completed' AND NOT EXISTS(
  SELECT 1 FROM gateway_oauth_identity_reservations r JOIN accounts a ON a.id=r.account_id
  WHERE r.consumer=NEW.consumer AND r.owner_ref=NEW.owner_ref AND r.account_ref=NEW.account_ref
   AND r.generation=NEW.generation AND r.operation_ref=NEW.enrollment_operation AND r.intent_mac=NEW.enrollment_mac
   AND r.account_id=NEW.outcome_account_id
   AND a.extra->>'gateway_generation_v1'=NEW.generation
   AND a.extra->>'gateway_profile_v1'='openai-oidc-oauth-staging-v1'
   AND a.extra->'gateway_credential_scope_v1'->>'consumer'=NEW.consumer
   AND a.extra->'gateway_credential_scope_v1'->>'owner'=NEW.owner_ref
   AND a.extra->'gateway_credential_scope_v1'->>'account'=NEW.account_ref
   AND a.extra->'gateway_credential_scope_v1'->>'purpose'=NEW.purpose
   AND a.status='disabled' AND NOT a.schedulable
   AND NOT EXISTS(SELECT 1 FROM account_groups g WHERE g.account_id=a.id)) THEN
  RAISE EXCEPTION 'connect completion requires exact custody birth' USING ERRCODE='23514';
 END IF;
 IF OLD.state IN ('completed','expired') THEN
  RAISE EXCEPTION 'connect terminal result is immutable' USING ERRCODE='23514';
 ELSIF OLD.state='prepared' THEN
  IF NEW.state='entered' THEN
   IF NEW.deadline<=clock_timestamp() OR NEW.entered_at IS NULL OR NEW.material_envelope IS DISTINCT FROM OLD.material_envelope THEN
    RAISE EXCEPTION 'connect entry denied' USING ERRCODE='23514';
   END IF;
  ELSIF NEW.state='expired' THEN
   IF NEW.deadline>clock_timestamp() OR NEW.entered_at IS NOT NULL OR NEW.material_envelope<>'' THEN
    RAISE EXCEPTION 'connect expiry denied' USING ERRCODE='23514';
   END IF;
  ELSE RAISE EXCEPTION 'connect transition denied' USING ERRCODE='23514';
  END IF;
 ELSIF OLD.state IN ('entered','unknown') THEN
  IF NEW.state NOT IN ('unknown','completed') OR NEW.entered_at IS DISTINCT FROM OLD.entered_at OR NEW.material_envelope<>'' THEN
   RAISE EXCEPTION 'spent connect cannot rearm' USING ERRCODE='23514';
  END IF;
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER gateway_oauth_connect_guard BEFORE INSERT OR UPDATE OR DELETE ON gateway_oauth_connect_intents
 FOR EACH ROW EXECUTE FUNCTION gateway_oauth_connect_guard();

-- F3-owned additive guard; F1 Stage and its existing transaction stay unchanged.
-- The private operation is exclusive to the bound connect commitment and scope.
CREATE FUNCTION gateway_oauth_connect_enrollment_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE intent gateway_oauth_connect_intents%ROWTYPE;
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended(NEW.consumer || chr(1) || NEW.operation_ref,245));
 SELECT * INTO intent FROM gateway_oauth_connect_intents
  WHERE consumer=NEW.consumer AND enrollment_operation=NEW.operation_ref FOR UPDATE;
 IF FOUND AND (intent.enrollment_mac IS NULL OR intent.enrollment_mac IS DISTINCT FROM NEW.intent_mac
  OR intent.owner_ref IS DISTINCT FROM NEW.owner_ref OR intent.account_ref IS DISTINCT FROM NEW.account_ref
  OR intent.generation IS DISTINCT FROM NEW.generation OR intent.recovery_denied
  OR intent.state NOT IN ('entered','unknown')) THEN
  RAISE EXCEPTION 'enrollment does not belong to connect' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER gateway_oauth_connect_enrollment_guard BEFORE INSERT ON gateway_oauth_identity_reservations
 FOR EACH ROW EXECUTE FUNCTION gateway_oauth_connect_enrollment_guard();
