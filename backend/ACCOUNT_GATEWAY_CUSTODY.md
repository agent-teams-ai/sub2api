# Native credential custody B3 candidate handoff

Task: `account-gateway-20261003-native-credential-custody-b3`. This is an unused,
opt-in component candidate, not a deployment or production qualification.

The private native route composition now requires an immutable server-owned
AES-256-GCM custody adapter. Authenticated composition must bind a consumer with
`WithGatewayNativeConsumer`; there is no body consumer field or stock-route
fallback. Create retains `generation`, `profile`, `name`, `api_key` and adds
bounded `owner_ref` and `account_ref`. `api_key` is write-only. The response keeps
the existing `GatewayNativeRoute` descriptor, including its numeric account ID
and persisted `created_at` precision, and returns no credential or fingerprint.

`NewGatewayNativeCredentialCustody` copies supplied 32-byte keys and requires an
explicit active key ID. Keys come from trusted composition outside the database
and backup. No host secret, environment/file credential lookup, mutable global
or guessed fallback is added. The existing `api_key` JSONB member holds a compact
`gcn1.<key-id>.<nonce>.<ciphertext-and-tag>` envelope. GCM uses a fresh random
12-byte nonce and authenticates version, key ID, exact consumer, owner, stable
logical account, birth generation and fixed provider-authorization purpose.
Name and Unicode display metadata are excluded from AAD.

The expected scope comes from authenticated consumer context and immutable row
metadata, rather than ciphertext claims. Create seals before durable account
creation and reads back exactly one generation without a second create attempt.
Readback validates envelope shape and key availability without decrypting. The
fresh-row lock compares the original encrypted credentials and scope before the
private provider Authorization boundary decrypts. The one-entry CAS precedes
upstream entry; a wrong key, changed scope or malformed/tampered envelope fails
privately with a sanitized quarantine result and no upstream entry. There is no
plaintext account clone or automatic inference probe, retry or bridge fallback.

Migration 242 is additive. Migration 241 is left intact. The 242 preflight refuses
any existing reserved native row; operators must quarantine such rows separately,
never automatically adopt or re-encrypt plaintext. The guard freezes scope and
credentials, requires an encrypted shape for marked insert/update and retains
241's inert staging, generation uniqueness, group exclusion and tombstone rules.
Exact disabled-row erasure removes only `api_key` while retaining descriptor and
safe metadata; it must remain possible after a key has been retired. Rotation is
explicit: compose a new active key ID with retained read keys and create a new
physical generation through the existing guarded private create/readback path.
In-place credential replacement is forbidden. Retiring a read key quarantines
old live envelopes; restoring encrypted data without the key cannot qualify it.

## Verification status

The continuation inspected the current owned implementation and performed one
Git preflight. Git reported that its linked-worktree metadata target is not a
repository in this sandbox. No Git retry, add, commit or push was attempted.
The installed PATH has no `go`, `gofmt`, `psql` or `pg_dump`. Go compilation,
formatting with gofmt, unit/integration execution and actual migrated PostgreSQL
dump/restore qualification are **NOT_RUN** here. No dependency installation or
runtime/isolation change was attempted. Primary must qualify this candidate with
the pinned Go dependencies and disposable PostgreSQL tools.

The custody tests target authenticated crypto tamper and scope separation, real
HTTP Authorization/zero-entry quarantine, locked encrypted-snapshot mismatch,
ordinary access exclusion, strict private ingress, migrated PostgreSQL JSONB,
dump and restore, immutable scope and exact erasure. Test definitions are coverage
intent, not passing evidence. Fixture admission is not a kernel registry receipt.
Actual MiMo canary is **NOT_RUN** and belongs to primary; no host secret was read.

Primary qualification commands, from `backend` with pinned dependencies already
available (network fetch disabled for the qualification itself):

```sh
GOTOOLCHAIN=local GOPROXY=off go test ./internal/service -run 'GatewayNative' -count=1
GOTOOLCHAIN=local GOPROXY=off go test -tags=integration ./internal/handler/admin -run 'GatewayNative' -count=1
GOTOOLCHAIN=local GOPROXY=off go test -tags=integration ./internal/repository -run 'GatewayNative' -count=1
```

The PostgreSQL tests require new empty, loopback-only, disposable databases with
the documented per-test database prefixes. Supply only synthetic fixture data.
Do not use an existing service database. Review skip output explicitly; a skip
does not qualify the boundary. Run existing ordinary/native tests as well.

## Ownership and remaining integration limits

Owned paths are `internal/service/native_gateway_credentials.go` and its new
tests, `internal/service/native_gateway_identity.go`,
`internal/handler/admin/native_gateway_identity.go`, the minimal custody fixture
adaptation in `native_gateway_review_integration_test.go`, new custody API tests,
`internal/repository/native_gateway_identity.go`, new custody PostgreSQL tests,
`migrations/242_gateway_native_credential_custody.sql`, and this handoff.
No ordinary provider, OAuth, Wire, registry, launcher, root dependency/workflow,
stock export, old pool migration or production setting change is authorized.
The TS kernel and management adapter remain owned by other workers.

Legacy service/PG fixtures outside these owned paths may still describe plaintext
native rows or the old route composition. They must be adapted by their owners
to authenticated consumer context and encrypted custody, preserving behavioral
assertions. Do not add a compatibility plaintext mode to make them pass.
Trusted bootstrap must supply custody and authenticated consumer composition;
this lane intentionally does not implement bootstrap or launcher.

The task cites source `16d621c22385a83e4d068da70ebc280846dd8fb0` and contract53
SHA256 `66a2393e7a55f76df1a78281af44379d0b455a0770d82f34e587dcca284157b0`.
The linked Git metadata is unavailable, so exact-head/base-diff verification
requires primary. No claim of full contract53 or supplied-Q qualification is
made without inspecting those normative inputs and executing the real gates.

## Primary qualification 2026-10-03

Pinned Go1.27.1 and PostgreSQL17.10 isolated disposable fixtures: crypto/authorization4groups+25nested, private API1group+6nested, existing private review1group+12nested passed. Actual PostgreSQL/dump/restore exposed an unqualified SQL242 helper under pg_dump search_path; before-fix receipt retained, schema-qualified repair passed1group+7nested with zero skips. SQL241 unchanged.

The repository test supports the focused gatewaycustody tag as well as integration, so this external fixture runs without stock TestMain provisioning unrelated Docker/Redis. Initial TestMain exit-zero with no selected test is explicitly NOT_RUN. Required native CI now selects the custody restore/private API suites and requires named PASS and zero skips. psql stdin is inherited through the pinned service container.

These are component proofs, not a composed native admit/closure registry, live provider, protected OAuth refresh, production enablement or full CI-to-App acceptance. Source review and final exact-head CI remain required.

## Existing native fixtures after scoped custody

Primary qualification used synthetic server-side AEAD key and trusted consumer context in eight existing/new unit fixture files. Ordinary profile-free accounts keep ordinary plaintext fixture inputs; independent upstream Authorization and replay assertions are preserved. Actual GatewayNative family:32 top-level groups and277 nested cases, zero SKIP, excluding the explicitly separate real Redis case. Fresh empty pinned Redis8.10.2 case:1/1,zero SKIP. The initial missing consumer setup caused replay to reject identity earlier; the corrected fixture preserves the original replay assertion. Earlier no-space build failure is retained as infrastructure failure, not a product test pass.

Crypto/private HTTP and actual migrated PostgreSQL plus pg_dump/restore were qualified before these fixture-only changes. Independent exact-source review/current CI/native bootstrap/facade/CI agent final App publication remain mandatory; this checkpoint is not assembled E2E acceptance.
