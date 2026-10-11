-- Reconnect keeps permanent verified ownership separate from append-only births.
-- Existing reservations, credentials, qualification receipts and outcomes remain
-- byte exact. Conflicting historical ownership fails the whole migration.
CREATE TABLE gateway_oauth_principal_claims (
 issuer text COLLATE "C" NOT NULL CHECK (issuer='https://auth.openai.com'),
 subject text COLLATE "C" NOT NULL CHECK (octet_length(subject) BETWEEN 1 AND 200 AND subject=btrim(subject) AND subject !~ '[[:cntrl:]]'),
 consumer text COLLATE "C" NOT NULL,
 owner_ref text COLLATE "C" NOT NULL,
 account_ref text COLLATE "C" NOT NULL,
 PRIMARY KEY (issuer,subject),
 UNIQUE (consumer,account_ref),
 UNIQUE (issuer,subject,consumer,owner_ref,account_ref)
);
INSERT INTO gateway_oauth_principal_claims (issuer,subject,consumer,owner_ref,account_ref)
 SELECT issuer,subject,consumer,owner_ref,account_ref FROM gateway_oauth_identity_reservations;
CREATE FUNCTION gateway_oauth_claim_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 RAISE EXCEPTION 'oauth ownership claim must be retained immutable' USING ERRCODE='23514';
END;
$$;
CREATE TRIGGER gateway_oauth_principal_claim_immutable BEFORE UPDATE OR DELETE ON gateway_oauth_principal_claims
 FOR EACH ROW EXECUTE FUNCTION gateway_oauth_claim_immutable();
ALTER TABLE gateway_oauth_identity_reservations
 ADD CONSTRAINT gateway_oauth_reservation_principal_claim FOREIGN KEY (issuer,subject,consumer,owner_ref,account_ref)
 REFERENCES gateway_oauth_principal_claims (issuer,subject,consumer,owner_ref,account_ref);
-- Existing operation uniqueness, generation/account-id uniqueness and all refresh
-- and qualification account-id foreign keys remain unchanged.
ALTER TABLE gateway_oauth_identity_reservations DROP CONSTRAINT gateway_oauth_identity_reservations_pkey;
ALTER TABLE gateway_oauth_identity_reservations ADD PRIMARY KEY (consumer,operation_ref);
CREATE OR REPLACE FUNCTION gateway_oauth_reservation_complete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM gateway_oauth_identity_reservations r JOIN accounts a ON a.id=r.account_id
  WHERE r.consumer=NEW.consumer AND r.operation_ref=NEW.operation_ref
   AND r.generation=NEW.generation AND r.issuer=NEW.issuer AND r.subject=NEW.subject
   AND r.owner_ref=NEW.owner_ref AND r.account_ref=NEW.account_ref
   AND a.extra->>'gateway_generation_v1'=r.generation
   AND a.extra->>'gateway_profile_v1'='openai-oidc-oauth-staging-v1'
   AND a.extra->'gateway_credential_scope_v1'->>'consumer'=r.consumer
   AND a.extra->'gateway_credential_scope_v1'->>'owner'=r.owner_ref
   AND a.extra->'gateway_credential_scope_v1'->>'account'=r.account_ref) THEN
  RAISE EXCEPTION 'oauth reservation requires its exact durable candidate' USING ERRCODE='23514';
 END IF;
 RETURN NULL;
END;
$$;

-- A provider account is also a permanent exclusive claim. A new qualification
-- receipt may reuse it only for this same principal and logical owner/account.
CREATE TABLE gateway_oauth_provider_claims (
 provider_account_id text COLLATE "C" PRIMARY KEY CHECK (
  provider_account_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
  AND provider_account_id<>'00000000-0000-0000-0000-000000000000'),
 issuer text COLLATE "C" NOT NULL,
 subject text COLLATE "C" NOT NULL,
 consumer text COLLATE "C" NOT NULL,
 owner_ref text COLLATE "C" NOT NULL,
 account_ref text COLLATE "C" NOT NULL,
 UNIQUE (consumer,account_ref),
 UNIQUE (provider_account_id,issuer,subject,consumer,owner_ref,account_ref),
 FOREIGN KEY (issuer,subject,consumer,owner_ref,account_ref)
 REFERENCES gateway_oauth_principal_claims (issuer,subject,consumer,owner_ref,account_ref)
);
INSERT INTO gateway_oauth_provider_claims (provider_account_id,issuer,subject,consumer,owner_ref,account_ref)
 SELECT provider_account_id,issuer,subject,consumer,owner_ref,account_ref FROM gateway_oauth_profile_qualifications;
CREATE TRIGGER gateway_oauth_provider_claim_immutable BEFORE UPDATE OR DELETE ON gateway_oauth_provider_claims
 FOR EACH ROW EXECUTE FUNCTION gateway_oauth_claim_immutable();
ALTER TABLE gateway_oauth_profile_qualifications
 ADD CONSTRAINT gateway_oauth_qualification_provider_claim FOREIGN KEY (provider_account_id,issuer,subject,consumer,owner_ref,account_ref)
 REFERENCES gateway_oauth_provider_claims (provider_account_id,issuer,subject,consumer,owner_ref,account_ref);
ALTER TABLE gateway_oauth_profile_qualifications DROP CONSTRAINT gateway_oauth_profile_qualifications_provider_account_id_key;
ALTER TABLE gateway_oauth_profile_qualifications DROP CONSTRAINT gateway_oauth_profile_qualifications_consumer_account_ref_key;
CREATE FUNCTION gateway_oauth_qualification_provider_claim() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 INSERT INTO gateway_oauth_provider_claims (provider_account_id,issuer,subject,consumer,owner_ref,account_ref)
  VALUES (NEW.provider_account_id,NEW.issuer,NEW.subject,NEW.consumer,NEW.owner_ref,NEW.account_ref)
  ON CONFLICT DO NOTHING;
 PERFORM 1 FROM gateway_oauth_provider_claims WHERE provider_account_id=NEW.provider_account_id
  AND issuer=NEW.issuer AND subject=NEW.subject AND consumer=NEW.consumer
  AND owner_ref=NEW.owner_ref AND account_ref=NEW.account_ref FOR UPDATE;
 IF NOT FOUND THEN
  RAISE EXCEPTION 'oauth provider claim conflicts with permanent owner' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;
-- This additional guard runs before the unchanged exact-birth qualification
-- guard. Failure of that guard rolls back the inserted claim and receipt too.
CREATE TRIGGER gateway_oauth_profile_claim_guard BEFORE INSERT ON gateway_oauth_profile_qualifications
 FOR EACH ROW EXECUTE FUNCTION gateway_oauth_qualification_provider_claim();
