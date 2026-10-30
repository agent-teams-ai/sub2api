-- Device capabilities stay in the existing encrypted connect material. The
-- separate phase/revision fences own provider effects before any HTTP request.
ALTER TABLE gateway_oauth_connect_intents
 ADD COLUMN method text NOT NULL DEFAULT 'browser' CHECK (method IN ('browser','device_code')),
 ADD COLUMN device_phase text NOT NULL DEFAULT '' CHECK (device_phase IN ('','starting','pending','polling')),
 ADD COLUMN device_revision bigint NOT NULL DEFAULT 0 CHECK (device_revision>=0),
 ADD COLUMN device_poll_after timestamptz,
 ADD COLUMN device_deadline timestamptz,
 ADD CONSTRAINT gateway_oauth_connect_device_shape CHECK (
  (method='browser' AND device_phase='' AND device_revision=0 AND device_poll_after IS NULL AND device_deadline IS NULL)
  OR (method='device_code' AND ((device_phase='' AND device_revision=0 AND device_poll_after IS NULL AND device_deadline IS NULL)
   OR (device_phase='starting' AND device_revision=1 AND device_poll_after IS NULL AND device_deadline IS NULL)
   OR (device_phase IN ('pending','polling') AND device_revision>=1 AND device_poll_after IS NOT NULL AND device_deadline IS NOT NULL AND device_deadline<=deadline))));

-- The original fixed browser callback is retained; device exchange uses only
-- OpenAI's own fixed callback. Neither is supplied by ingress.
ALTER TABLE gateway_oauth_connect_intents DROP CONSTRAINT gateway_oauth_connect_intents_redirect_uri_check;
ALTER TABLE gateway_oauth_connect_intents ADD CONSTRAINT gateway_oauth_connect_redirect_method CHECK (
 (method='browser' AND redirect_uri='http://localhost:1455/auth/callback')
 OR (method='device_code' AND redirect_uri='https://auth.openai.com/deviceauth/callback'));

CREATE OR REPLACE FUNCTION gateway_oauth_connect_guard() RETURNS trigger LANGUAGE plpgsql AS $$
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
   OR NEW.deadline>clock_timestamp()+interval '10 minutes' OR NEW.device_phase<>'' OR NEW.device_revision<>0 OR NEW.device_poll_after IS NOT NULL OR NEW.device_deadline IS NOT NULL THEN
   RAISE EXCEPTION 'invalid prepared connect' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
 END IF;
 IF (to_jsonb(NEW)-ARRAY['state','material_envelope','entered_at','outcome_operation','outcome_account_id','outcome_generation','outcome_state','enrollment_mac','recovery_denied','device_phase','device_revision','device_poll_after','device_deadline'])
  IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['state','material_envelope','entered_at','outcome_operation','outcome_account_id','outcome_generation','outcome_state','enrollment_mac','recovery_denied','device_phase','device_revision','device_poll_after','device_deadline']) THEN
  RAISE EXCEPTION 'connect intent is immutable' USING ERRCODE='23514';
 END IF;
 -- Device request and poll claims are bounded extensions of prepared state.
 -- They cannot alter authority or enter custody. A spent/terminal intent still
 -- follows the existing one-way entry and exact F1 commitment transitions.
 IF NEW.state='prepared' AND OLD.state='prepared' AND OLD.method='device_code' THEN
  IF (to_jsonb(NEW)-ARRAY['material_envelope','device_phase','device_revision','device_poll_after','device_deadline'])
   IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['material_envelope','device_phase','device_revision','device_poll_after','device_deadline'])
   OR NEW.deadline<=clock_timestamp() THEN
   RAISE EXCEPTION 'device prepared transition denied' USING ERRCODE='23514';
  END IF;
  IF OLD.device_phase='' AND NEW.device_phase='starting' THEN
   IF NEW.device_revision<>OLD.device_revision+1 OR NEW.material_envelope IS DISTINCT FROM OLD.material_envelope
    OR NEW.device_poll_after IS DISTINCT FROM OLD.device_poll_after OR NEW.device_deadline IS DISTINCT FROM OLD.device_deadline THEN
    RAISE EXCEPTION 'device begin claim denied' USING ERRCODE='23514';
   END IF;
  ELSIF OLD.device_phase='pending' AND NEW.device_phase='polling' THEN
   IF NEW.device_revision<>OLD.device_revision+1 OR OLD.device_poll_after>clock_timestamp()
    OR NEW.device_deadline IS DISTINCT FROM OLD.device_deadline OR NEW.device_poll_after IS DISTINCT FROM OLD.device_poll_after OR NEW.material_envelope IS DISTINCT FROM OLD.material_envelope THEN
    RAISE EXCEPTION 'device poll claim denied' USING ERRCODE='23514';
   END IF;
  ELSIF OLD.device_phase IN ('starting','polling') AND NEW.device_phase='pending' THEN
   IF NEW.device_revision<>OLD.device_revision OR NEW.device_poll_after IS NULL
    OR NEW.device_poll_after<=clock_timestamp() OR NEW.device_poll_after>clock_timestamp()+interval '301 seconds'
    OR NEW.device_deadline IS NULL OR NEW.device_deadline<=clock_timestamp() OR NEW.device_deadline>NEW.deadline
    OR (OLD.device_phase='polling' AND (NEW.material_envelope IS DISTINCT FROM OLD.material_envelope OR NEW.device_deadline IS DISTINCT FROM OLD.device_deadline)) THEN
    RAISE EXCEPTION 'device pending result denied' USING ERRCODE='23514';
   END IF;
  ELSE RAISE EXCEPTION 'device replay denied' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
 END IF;
 IF NEW.device_phase IS DISTINCT FROM OLD.device_phase OR NEW.device_revision IS DISTINCT FROM OLD.device_revision
  OR NEW.device_poll_after IS DISTINCT FROM OLD.device_poll_after OR NEW.device_deadline IS DISTINCT FROM OLD.device_deadline THEN
  RAISE EXCEPTION 'device claim is immutable outside prepared transition' USING ERRCODE='23514';
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
   IF (NEW.deadline>clock_timestamp() AND (NEW.method<>'device_code' OR NEW.device_deadline IS NULL OR NEW.device_deadline>clock_timestamp())) OR NEW.entered_at IS NOT NULL OR NEW.material_envelope<>'' THEN
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
