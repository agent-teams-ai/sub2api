# Private native bootstrap

Build the separate Linux binary with `go build ./cmd/gateway-native`. Stock
server/Wire, routes, migrations and scheduler remain separate compositions.
This foreground engine uses the existing Ent account repository, private admin
constructor, HTTP upstream, lifetime wrapper, OpenAI gateway, AEAD custody and
one gatewaytransport registry. Its managed candidates remain group-free,
unschedulable and probe-free. No provider call occurs during startup.

The protected launcher supplies its original readonly lock FD 3, ready pipe
FD 4, durable gate FD 5 and optional `Config.BootstrapFile` as FD 6. This binary
requires all four. Origin and canonical incarnation come exclusively from the
reserved launcher environment. It runs under the configured non-root UID/GID,
without supplementary groups or descendants. It checks inherited metadata,
decodes/closes FD 6, waits for exactly G plus EOF, then connects to configured
PostgreSQL and obtains configured Node enrollment before opening its loopback
private listener. It writes exactly R and closes FD 4 after composing valid
private routes. SIGTERM/SIGINT close the listener/connections and cancel retained
transport lifetimes before returning; FD 3 is kept through actual process exit.
Failure never rewrites recovery evidence or releases SQL occupancy.

The supervisor owns its original `BootstrapFile`. Start captures a CLOEXEC
duplicate through the pinned os.File handle, validates root ownership, regular
single-link 0600 mode, readonly access and 1..65536 bytes, and closes its own
duplicate on every return. Exec maps that duplicate to non-CLOEXEC FD 6 after
the existing three handles. Start never closes/reopens the caller file. The
child reads from offset zero independently of caller Seek, Close or pathname
replacement. Trusted root must keep the captured inode's bytes immutable through
decode. This is one fixed-purpose file, not a generic ExtraFiles facility.
Existing launcher callers omitting BootstrapFile keep their existing protocol.

FD 6 contains one strict JSON object with all these required fields:

| Field | Shape and meaning |
| --- | --- |
| `listenAddress` | Fixed `127.0.0.1:port` or `[::1]:port`, port 1..65535 |
| `postgresDSN` | Native database DSN; externally migrated, no automatic migration |
| `authority` | `{origin,credential}`: ONE fixed Node origin/control token |
| `custody` | `{activeKeyId,keys:[{id,key}]}`: 1..32 AES-256 keys, canonical standard base64 |
| `peers` | 1..128 `{consumerId,role,credential}` mappings; roles management/execution/cleanup |
| `profile` | `{model,baseURL,qualificationRef,requestBytes,outputBytes,tokens,providerTokenUpperBound}` |
| `maxEntries` | Integer 1..10000; unresolved entries retain capacity |

The profile ID is the existing `openai-responses-apikey-v1`. The supplied fixed
HTTPS endpoint/model and qualification reference belong to the trusted service
catalog; there is no caller model/URL discovery. These caps are implementation
bounds, not measured product qualification: request bytes <=4 MiB, output <=8
MiB, tokens <=provider upper bound <=10000000. The listener caps 128 connections,
16 KiB headers, five-second header reads, 30-second I/O and one-second idle time.
Authority requests cap 256 KiB bodies, 16 KiB response headers, 1 KiB ACKs and five
seconds, with no retries, redirects or environment proxy. TLS verification is
normal. Explicit fixture transports/certificate trust belong only to outer Go
composition; FD configuration has no insecure-TLS switch.

All config members are exact decoded names: unknown/duplicate/case aliases,
noncanonical integer tokens, invalid UTF-8/lossy surrogates, excessive depth or
bytes deny with a fixed error. Server configuration never enters argv/env,
errors, journal or retirement receipts. AEAD keys stay outside database backups.
Provider BYOK arrives only through authenticated management into encrypted SQL;
decryption remains the existing fresh locked-row upstream Authorization boundary.

The private selector mounts only `/private/native/v1/candidates` and its candidate
children, plus `/private/native/v1/transports` and its exact registered actions.
Candidate routes require management authority. Transport POST and owner closure
require execution authority; delegated read/cancel/ack require cleanup authority.
Authorization must be a singleton exact Bearer credential from the fixed mapping.
Bodies cannot override the configured consumer. The old internally registered
`/private/native/v1/responses` direct-review route is denied by the selector and
its admission callback; it cannot bypass the registry's sole claim.

Node must implement these fixed private authority callbacks, authenticated by the
one configured native-callback credential. Success is ONLY HTTP 200 with a
singleton application/json content type and strict exact `{ok:true}`:

| Path under `/private/native/v1` | Body |
| --- | --- |
| `/enrollment` | `{originRef,engineIncarnation,qualificationRef}` |
| `/dispatch-proof` | `{consumerId,proof,leaseExpiresAt}`; timestamp RFC3339Nano |
| `/cleanup-authority` | `{consumerId,proof,cleanup}` |
| `/owner-closure-authority` | `{consumerId,proof}`; exact original durable proof, valid after worker expiry |
| `/closure-ack` delegated | `{consumerId,proof,cleanup,receipt}` |
| `/closure-ack` original | `{consumerId,proof,receipt}`; cleanup omitted |

Proof, CleanupLease and Receipt are the existing exported Go transport types.
The existing `/admit` callback wire is unchanged. Node validates durable proofs,
current delegated leases/CAS and protected enrollment; Go creates no SQL claims,
cleanup jobs or accounting. Missing/malformed/ambiguous ACK denies and retains
occupancy. Original closure ACK maps to
`kernel.acknowledgeTransportClosed(context,proof.worker,proof)`; delegated ACK
uses the actual current cleanup worker/CAS. Completion effect is not occupancy
proof: SQL effect(completed) does not enqueue cleanup.

The additive native `/transports/read-owner`, `/cancel-owner`, `/ack-owner` paths
accept ONLY `{proof:Proof}`. They never dispatch or accept admission/payload or a
cleanup lease. Every call rechecks explicitly composed owner authority. The
reservation must match consumer/execution/request, original worker/proof and the
full native tuple. Lost-ACK recovery can attach only the authorized original
durable proof to an already sealed reservation. ACK requires positive closed
phase: owned Context Done, forwarding return, known/successfully closed body and
no Close failure. Repeated exact ACK is allowed only under current authority;
socket EOF/expiry/completion alone do not grant closure or another POST. Existing
delegated paths retain their current-lease rules. Old configs with absent owner
ports still construct successfully and deny owner closure.

Targeted checks: `go test -tags=unit ./internal/gatewaybootstrap
./internal/gatewaytransport`, plus launcher Bootstrap tests in a disposable root
Linux environment; `go build ./cmd/gateway-native` and scoped `go vet`. The
optional `-tags=integration` TestNativeProtectedReadyEnrollmentAndShutdown needs
root and GATEWAY_NATIVE_BOOTSTRAP_PG_DSN naming an existing loopback-only
`native_bootstrap_*` disposable database without a password. It checks actual
bootstrap PG connection, configured enrollment denial, R/EOF readiness and
orderly shutdown through the protected launcher, with a synthetic Node peer.
Fixtures
exercise actual HTTP/TLS/service lifetimes and protected real children; synthetic
authority/storage is explicitly not Node+PG qualification. Primary owns root
Docker qualification and actual Node+Go+PG two-request same-open-execution,
concurrency-one regression. No paid provider or real-project agent run is covered
here. Supplied f791 is the owner's mechanical merge of registry700 and accepted
release569. Registry700 is accepted via093 with the same f791 source tree; facade
sourcec56 is independently approved and merged4df. These component approvals
do not qualify this bootstrap candidate or assembled Node+Go+PG behavior.

Primary qualification on 2026-10-04 repaired three observed failures: RE2 startup
panic, cancellation of a blocking inherited gate pipe, and HTTP framing cut off
after successful Forward. Disposable root Docker race checks passed: bootstrap
31 test results, registry/owner transport 57, lifetime 12, and FD6 launcher 8;
all had zero skips. Production build and scoped unit-tag lint passed. Actual
new PostgreSQL 17.10 protected child enrollment/readiness/shutdown passed both
deny and allow scenarios. Before-failure receipts and worker NOT_RUN evidence
remain retained. New native CI runs the same important boundaries. Independent
review and current-commit CI are pending; assembled Node/Go/SQL and paid MiMo
tools/final/parser/App remain unproved.
