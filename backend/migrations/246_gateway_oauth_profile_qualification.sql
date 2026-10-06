-- F1 birth remains disabled/unschedulable; F2 alone writes credential versions.
-- This receipt is controlled source qualification, never a live capability/grant.
CREATE TABLE gateway_oauth_profile_qualifications (
 account_id bigint PRIMARY KEY REFERENCES gateway_oauth_identity_reservations(account_id),
 native_created_at timestamptz NOT NULL CHECK (isfinite(native_created_at)),
 consumer text COLLATE "C" NOT NULL,
 owner_ref text COLLATE "C" NOT NULL,
 account_ref text COLLATE "C" NOT NULL,
 generation text COLLATE "C" NOT NULL,
 operation_ref text COLLATE "C" NOT NULL,
 issuer text COLLATE "C" NOT NULL CHECK (issuer='https://auth.openai.com'),
 subject text COLLATE "C" NOT NULL,
 provider_account_id text COLLATE "C" NOT NULL UNIQUE CHECK (
  provider_account_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
  AND provider_account_id<>'00000000-0000-0000-0000-000000000000'),
 profile text NOT NULL CHECK (profile='openai-codex-oauth-responses-v1'),
 base_url text NOT NULL CHECK (base_url='https://chatgpt.com/backend-api/codex'),
 model text NOT NULL CHECK (model='gpt-6.1-sol'),
 qualification text NOT NULL CHECK (qualification='controlled-source-v1'),
 qualified_at timestamptz NOT NULL CHECK (isfinite(qualified_at)),
 UNIQUE (consumer,operation_ref),
 UNIQUE (consumer,account_ref),
 UNIQUE (generation)
);
CREATE FUNCTION public.gateway_oauth_profile_qualification_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP<>'INSERT' THEN
  RAISE EXCEPTION 'oauth qualification identity must be retained immutable' USING ERRCODE='23514';
 END IF;
 IF NEW.qualified_at>clock_timestamp() OR NOT EXISTS (
  SELECT 1 FROM accounts a JOIN gateway_oauth_identity_reservations r ON r.account_id=a.id
  JOIN gateway_oauth_connect_intents c ON c.consumer=r.consumer AND c.owner_ref=r.owner_ref
  AND c.account_ref=r.account_ref AND c.generation=r.generation AND c.purpose='provider-oauth-bundle-v1'
  AND c.enrollment_operation=r.operation_ref AND c.enrollment_mac=r.intent_mac
  AND c.outcome_operation=r.operation_ref AND c.outcome_account_id=r.account_id
  AND c.outcome_generation=r.generation AND c.outcome_state='staged'
  AND c.state='completed' AND NOT c.recovery_denied
  WHERE a.id=NEW.account_id AND a.created_at=NEW.native_created_at AND a.deleted_at IS NULL
  AND a.platform='openai' AND a.type='oauth' AND a.status='disabled' AND NOT a.schedulable
  AND a.proxy_id IS NULL AND a.parent_account_id IS NULL
  AND a.extra->>'gateway_profile_v1'='openai-oidc-oauth-staging-v1'
  AND a.extra->>'gateway_generation_v1'=NEW.generation
  AND r.consumer=NEW.consumer AND r.owner_ref=NEW.owner_ref AND r.account_ref=NEW.account_ref
  AND r.generation=NEW.generation AND c.operation_ref=NEW.operation_ref
  AND r.issuer=NEW.issuer AND r.subject=NEW.subject
  AND gateway_oauth_credential_version(a.credentials)>0
  AND NOT EXISTS(SELECT 1 FROM account_groups g WHERE g.account_id=a.id)
  AND NOT EXISTS(SELECT 1 FROM gateway_oauth_refresh_attempts f WHERE f.account_id=a.id
   AND (f.state='unknown' OR f.state IN ('prepared','entered') AND f.deadline<=clock_timestamp()))
  FOR SHARE OF a,r,c) THEN
  RAISE EXCEPTION 'oauth qualification requires exact inert reserved birth' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER gateway_oauth_profile_qualification_guard
 BEFORE INSERT OR UPDATE OR DELETE ON gateway_oauth_profile_qualifications
 FOR EACH ROW EXECUTE FUNCTION public.gateway_oauth_profile_qualification_guard();
