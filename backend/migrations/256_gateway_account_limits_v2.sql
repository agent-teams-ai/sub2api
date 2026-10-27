-- New protected key-plan/Grok observations have their own provenance. The v1
-- OAuth-qualified snapshot FK remains unchanged; no backfill or dual write.
CREATE TABLE gateway_account_limits_v2_snapshots (
 account_id bigint PRIMARY KEY REFERENCES accounts(id),
 native_created_at timestamptz NOT NULL CHECK (isfinite(native_created_at)),
 generation text COLLATE "C" NOT NULL,
 principal_version text COLLATE "C" NOT NULL CHECK (principal_version ~ '^[0-9a-f]{64}$'),
 revision bigint NOT NULL CHECK (revision BETWEEN 1 AND 9007199254740991),
 observed_at timestamptz NOT NULL CHECK (isfinite(observed_at)),
 -- Each independent source dimension has its own stale-observation fence.
 source_observations jsonb NOT NULL CHECK (jsonb_typeof(source_observations)='object'
   AND octet_length(source_observations::text)<=512
   AND (source_observations - ARRAY['plan_quota','rate_limit'])='{}'::jsonb),
 snapshot jsonb NOT NULL CHECK (jsonb_typeof(snapshot)='object' AND octet_length(snapshot::text)<=8192
   AND snapshot->>'scope' IN ('account','subscription')
   AND jsonb_typeof(snapshot->'windows')='array' AND jsonb_array_length(snapshot->'windows')<=8)
);
