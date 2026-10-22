-- Passive source observations only. Separate from immutable OAuth metadata and
-- the independently rotating encrypted credential. No legacy Extra backfill:
-- those observations have no authenticated physical/principal provenance.
CREATE TABLE gateway_account_limits_snapshots (
 account_id bigint PRIMARY KEY REFERENCES gateway_oauth_profile_qualifications(account_id),
 native_created_at timestamptz NOT NULL CHECK (isfinite(native_created_at)),
 generation text COLLATE "C" NOT NULL,
 principal_version text COLLATE "C" NOT NULL CHECK (principal_version ~ '^[0-9a-f]{64}$'),
 revision bigint NOT NULL CHECK (revision BETWEEN 1 AND 9007199254740991),
 observed_at timestamptz NOT NULL CHECK (isfinite(observed_at)),
 raw_snapshot jsonb NOT NULL CHECK (jsonb_typeof(raw_snapshot)='object' AND octet_length(raw_snapshot::text)<=8192)
);
