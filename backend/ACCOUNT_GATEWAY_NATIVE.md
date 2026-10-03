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

## Primary repaired-source qualification - 2026-10-03

The main controller materialized guarded nine-file packet `0c434893` on exact
`d70ddf46`, applied the separately retained public API-contract stub-only fix,
formatted owned Go files and removed a newly unused gjson import. The original
ten-file export was rejected by the unchanged full-file guard because a public
preexisting synthetic OIDC test fixture matched it. No actual credential was
read or exported; the original raw packet was never declared guard-qualified.

Actual pinned Go1.27.1 checks passed native/service/repository contracts,
ordinary bridge/admin/apicompat compatibility and all API-contract cases.
A NEW PostgreSQL17.10 database passed actual private HTTP plus all12 nested
scenarios. Dedicated new empty Redis8.10.2 fixtures passed repository and
HTTP isolation. The initial main harness retained old target literals and was
corrected in a separate new fixture; its failure is retained, not relabeled.
These receipts do not prove a live model/provider review or facade deployment.

Fresh registry metadata verified Axios1.20.0 and pnpm9.15.9. Primary retained
actual generated Axios importer/package/snapshot only, with every previous
parsed lock node unchanged: 16 generated added lines and one changed line.
Frozen install, typecheck and all302 existing critical frontend cases passed.
Fresh production audit contains zero Axios advisories; the unchanged existing
exception policy passes. Existing non-Axios advisories are not declared fixed.
Final exact-head full CI/security and independent xhigh/default review remain
required. Worker NOT_RUN below is historical worker activity, not this receipt.

## Independent d70 repair handoff (2026-10-03)

Guarded patch: 689 changedLOC (additions + deletions), within the 700-line bound.

Requested PR2 base: `d70ddf464bd5fb029bc9fb9faecaf687346729c9`,
`agent-teams-ai/sub2api`. Linked Git metadata is inaccessible here, so this
worker cannot independently certify HEAD or the supplied exact719 fingerprints.
The patch is measured against initial workspace bytes; the identity-file baseline
was reconstructed from its original read because the first patch overlapped the
snapshot. No commit, push, installation or provider/runtime action was performed.

Owned edits are the native identity/Responses services, a private legacy validator,
the private branches of the CC pipeline/Responses fallback, native review tests,
the repository reasoning review test, the server API-contract fake and this file.
The four request policy names reject decoded case aliases with `strings.EqualFold`;
canonical escaped names and unrelated native bytes/tool names remain supported.
Private buffered legacy replies qualify one explicit index-zero assistant choice,
complete text/reasoning or valid function calls before conversion/output caching.
Private stream terminal objects reject duplicate/aliased choices, index and finish
fields before conversion; final state must qualify before completed/DONE. Sparse
tool fragments retain their identity instead of using converter-generated IDs.
Both private buffered profiles check full writes and delivery-aware flushing.
Delivery failure means effect unknown, even if some completed bytes reached the
client. Ordinary forwarding/cache diagnostics and permissive compatibility remain.
Managed forwarding/cache-error diagnostics are suppressed; provider errors are
not logged. Checked descriptor extraction and controlled-fixture cleanup address
errcheck findings. The API-contract fake now consistently resolves ordinary rows
101/102 through both lookup APIs, preserving the production managed-row guard.

New behavior tests for main's untouched-d70 to patched reproduction:
`TestGatewayNativeRepairPolicyCaseAliases`,
`TestGatewayNativeRepairLegacyBufferedQualification`,
`TestGatewayNativeRepairOrdinaryBufferedCompatibility`,
`TestGatewayNativeRepairBufferedDeliveryFailures`,
`TestGatewayNativeRepairLegacyStreamAmbiguousTerminal`,
`TestGatewayNativeRepairLegacyStreamQualifiedTools`, and
`TestGatewayNativeRepairPrivateDiagnosticPrivacy`. They use the actual HTTP
transport/converter and controlled writers/logger; they contain no source-string
assertions and depend only on seams already present in d70.

Current light checks cover JSON fixture expressions, edited-file delimiter and
whitespace sanity, bounded additions/deletions and unchanged go.mod/go.sum.
Go/PG/Docker/lint/errcheck/gofmt and behavior reproduction are **NOT RUN** here;
Go/gofmt are unavailable. Prior passing native proof does not cover these cases.
Main owns pinned formatting, actual `TestAPIContracts`, full lint, exact final
xhigh/CI review and new sandbox Docker/PG qualification. Run service tests with
`go test -tags=unit ./internal/service -run '^TestGatewayNative(Repair|Review)' -count=1`
and repository `TestGatewayNativeReviewReasoningDomains`; run API contracts with
`go test -tags=unit ./internal/server -run '^TestAPIContracts$' -count=1` from backend.
Token/capacity policy, bootstrap, subscription authentication and live-provider/
live-CI gates remain deferred. This handoff does not claim final qualification.
