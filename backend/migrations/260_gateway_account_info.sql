-- Provider facts are a private native read model, never account credentials or
-- a second account lifecycle. The global sequence orders requests before HTTP.
CREATE SEQUENCE gateway_account_info_source_order AS bigint MINVALUE 1 MAXVALUE 9007199254740991 NO CYCLE;
CREATE TABLE gateway_account_info_snapshots (
 account_id bigint PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
 native_created_at timestamptz NOT NULL CHECK (isfinite(native_created_at)),
 generation text COLLATE "C" NOT NULL,
 principal_version text COLLATE "C" NOT NULL CHECK (principal_version ~ '^[0-9a-f]{64}$'),
 revision bigint NOT NULL CHECK (revision BETWEEN 1 AND 9007199254740991),
 sources jsonb NOT NULL CHECK (jsonb_typeof(sources)='object' AND octet_length(sources::text)<=32768
  AND (sources - ARRAY['verified_claims','account_check','plan_quota','credential'])='{}'::jsonb)
);
CREATE FUNCTION gateway_account_info_cleanup() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.deleted_at IS NOT NULL THEN
  DELETE FROM gateway_account_info_snapshots WHERE account_id=NEW.id AND native_created_at=NEW.created_at;
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER gateway_account_info_cleanup AFTER UPDATE OF deleted_at ON accounts
 FOR EACH ROW WHEN (NEW.deleted_at IS NOT NULL) EXECUTE FUNCTION gateway_account_info_cleanup();
