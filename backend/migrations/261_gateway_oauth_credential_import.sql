-- Selected Codex imports extend the existing one-use connect FSM. Browser and
-- device ciphertext/AAD remain unchanged; no second operation journal exists.
ALTER TABLE gateway_oauth_connect_intents
 ADD COLUMN import_input_mac text CHECK (import_input_mac ~ '^[0-9a-f]{64}$'),
 ADD COLUMN import_claim_mac text CHECK (import_claim_mac ~ '^[0-9a-f]{64}$'),
 ADD COLUMN import_key_commitment text CHECK (import_key_commitment ~ '^[0-9a-f]{64}$');

ALTER TABLE gateway_oauth_connect_intents DROP CONSTRAINT gateway_oauth_connect_intents_method_check;
ALTER TABLE gateway_oauth_connect_intents ADD CONSTRAINT gateway_oauth_connect_method CHECK
 (method IN ('browser','device_code','refresh_token','auth_json'));

ALTER TABLE gateway_oauth_connect_intents DROP CONSTRAINT gateway_oauth_connect_redirect_method;
ALTER TABLE gateway_oauth_connect_intents ADD CONSTRAINT gateway_oauth_connect_redirect_method CHECK (
 (method='browser' AND redirect_uri='http://localhost:1455/auth/callback')
 OR (method='device_code' AND redirect_uri='https://auth.openai.com/deviceauth/callback')
 OR (method IN ('refresh_token','auth_json') AND redirect_uri=''));

ALTER TABLE gateway_oauth_connect_intents DROP CONSTRAINT gateway_oauth_connect_device_shape;
ALTER TABLE gateway_oauth_connect_intents ADD CONSTRAINT gateway_oauth_connect_device_shape CHECK (
 (method<>'device_code' AND device_phase='' AND device_revision=0 AND device_poll_after IS NULL AND device_deadline IS NULL)
 OR (method='device_code' AND ((device_phase='' AND device_revision=0 AND device_poll_after IS NULL AND device_deadline IS NULL)
  OR (device_phase='starting' AND device_revision=1 AND device_poll_after IS NULL AND device_deadline IS NULL)
  OR (device_phase IN ('pending','polling') AND device_revision>=1 AND device_poll_after IS NOT NULL AND device_deadline IS NOT NULL AND device_deadline<=deadline))));

ALTER TABLE gateway_oauth_connect_intents ADD CONSTRAINT gateway_oauth_connect_import_shape CHECK (
 (method IN ('refresh_token','auth_json') AND import_input_mac IS NOT NULL AND import_claim_mac IS NOT NULL AND import_key_commitment IS NOT NULL)
 OR (method IN ('browser','device_code') AND import_input_mac IS NULL AND import_claim_mac IS NULL AND import_key_commitment IS NULL));

-- Migration 245 used an unnamed material check; identify that exact column
-- constraint rather than depending on PostgreSQL's generated ordinal name.
DO $$
DECLARE material_check text;
BEGIN
 SELECT conname INTO STRICT material_check FROM pg_constraint
 WHERE conrelid='gateway_oauth_connect_intents'::regclass AND contype='c'
  AND pg_get_constraintdef(oid) LIKE '%material_envelope%';
 EXECUTE format('ALTER TABLE gateway_oauth_connect_intents DROP CONSTRAINT %I',material_check);
END;
$$;
ALTER TABLE gateway_oauth_connect_intents ADD CONSTRAINT gateway_oauth_connect_material_shape CHECK (
 (state IN ('prepared','entered') AND (
   (method IN ('browser','device_code') AND material_envelope ~ '^gcc1\.[A-Za-z0-9_-]+$' AND octet_length(material_envelope) BETWEEN 65 AND 1024)
   OR (method IN ('refresh_token','auth_json') AND material_envelope ~ '^gci1\.[A-Za-z0-9_-]+$' AND octet_length(material_envelope) BETWEEN 44 AND 49152)))
 OR (state IN ('unknown','completed','expired') AND material_envelope=''));

-- The shared claim ignores consumer, owner, operation and method. PostgreSQL
-- resolves concurrent entry before either loser can exchange. Completed frees
-- an unchanged valid RT; unknown retains the claim until exact reconciliation.
CREATE UNIQUE INDEX gateway_oauth_connect_unresolved_import_claim
 ON gateway_oauth_connect_intents(import_claim_mac)
 WHERE import_claim_mac IS NOT NULL AND state IN ('entered','unknown');

CREATE INDEX gateway_oauth_connect_unresolved_import_key
 ON gateway_oauth_connect_intents(import_key_commitment)
 WHERE import_key_commitment IS NOT NULL AND state IN ('entered','unknown');

-- The existing transition trigger automatically treats the new MAC columns as
-- immutable; all expiry, enrollment binding, terminal and one-use rules remain.
