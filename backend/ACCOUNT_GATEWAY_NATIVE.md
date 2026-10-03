# Private account-gateway native boundary

This opt-in boundary is based on Sub2API v0.2.11, commit
`96f4c115c9749078f90cbf210a01d39baf3f53b6`. It is independently reusable by a
private account gateway; Review Router ownership and CI OIDC policy belong to
the consumer, not this engine. Default route registration does not expose the
new private endpoints. A future private bootstrap must explicitly call
`RegisterGatewayNativeRoutes` and restrict ingress to the gateway service.

## Invariants

- Private account UUID, generation, profile and persisted creation identity are
  checked together; a native numeric account ID is not an authorization token.
- Managed rows are inert in ordinary scheduler/credential projections. Ordinary
  admin mutations reject managed descriptors before their first mutation.
- Candidate creation/readback, activation and one-way erasure retain their
  identity and tombstone constraints. Unknown acknowledgements require readback.
- Native Responses and the legacy MiMo chat bridge preserve tool events and
  require qualified terminal completion; malformed or incomplete streams do
  not become successful final answers. Critical duplicate request policy keys
  are rejected before transport. Reasoning-cache namespaces remain isolated.
- Migration 241 composes with the existing migration 175 billing trigger.
  Ordinary account billing defaults are retained; private descriptors preserve
  their strict seven-key envelope and malformed markers remain denied.

## Qualification and limits

Hosted guarded candidate `1359a3d1` passed native/ordinary Go tests, fresh
HTTP/PostgreSQL with all 12 nested cases, dedicated Redis repository and HTTP
isolation, and PostgreSQL shape/erasure/tombstone/two-session locking tests.
The canonical source is formatted with the pinned Go 1.27.1 toolchain; dependency
locks are unchanged. The focused workflow verifies the committed source against
fresh PostgreSQL 17.10 and Redis 8.10.2 fixtures without provider credentials.

This checkpoint does not implement the private service bootstrap, consumer
HTTP facade, account-global admission, approved output token policy, live
subscription authentication or actual CI publication. Those gates require
separate implementation and E2E evidence before enabling provider traffic.
Ordinary upstream code is retained, and upstream upgrades need focused
compatibility checks for migration ordering, repository writes and SSE behavior.
