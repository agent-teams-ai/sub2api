# Protected Linux private engine launcher — B3b candidate

This opt-in component implements the local process lifetime boundary in
normative Contract 53 §4. It is a candidate requiring primary Linux
qualification. Stock Sub2API main is not a private engine bootstrap.

Supplied accepted source:
`16d621c22385a83e4d068da70ebc280846dd8fb0`.
Observed Git identity: **unverified**. The single Git preflight failed because
the linked worktree's Git metadata is inaccessible in this installed worker.
No Git write, commit, push, history rewrite, deployment or global installation occurs.
Required qualified tools are unpacked only in the private temporary artifact cache.
The controller's actual PR base is `release/account-gateway-v0.2.11`; the worker
materialization alias does not change that base.

The normative input is
`.spike-inputs/53-account-gateway-implementation-contract.md`, SHA256
`66a2393e7a55f76df1a78281af44379d0b455a0770d82f34e587dcca284157b0`,
verified against its actual bytes. Q is applied from `.spike-inputs/q.md`.
The requested writer setting is `gpt-6.1-sol/high/default`, NO FAST; installed
model selection remains controller-owned and is not independently attested here.

## Owned implementation

Only new `internal/gatewaylauncher/**`, new `cmd/gateway-launcher/**` and this
document are owned. The library uses the existing Go module, standard library and already-pinned
`github.com/google/uuid v1.6.0`; test-only pidfds use already-pinned
`golang.org/x/sys v0.47.0`. Module and lock files are unchanged.
Linux is explicit in implementation and test build constraints.

The lifetime policy lives in `launcher_linux.go`; protected filesystem,
process-birth and journal operations live in `storage_linux.go`. The command
is private supervisor composition. This is a small closed component with one
engine contract, not a generic command manager or signing framework. No registry,
admission, native handlers/credentials/identity, Wire, main.go, dependencies,
workflows, TS, SQL, other projects or deployment files are changed.

## Production authority and immutable configuration

The supervisor must run as root. The configured engine UID and GID must both be
non-root and may not be Linux's all-ones no-change sentinel. Supplementary groups
are cleared. There is no same-UID fallback and no production synthetic mode,
test bypass, ambient environment inheritance or test failure-injection option.

The operator configures one fixed opaque originRef, one fixed absolute protected
directory and one fixed root-owned native ELF executable. Configuration is
copied before launch; callers cannot choose incarnation, PID, birth or boot
authority. Public account/execution APIs must never construct this configuration.
The engine environment contains only explicit trusted configured values and
bootstrap FD assignments. The launcher loads no upstream provider keys or
credential file paths. Credential custody/composition remains a separate lane.

Every protected path component is opened relative to a pinned directory FD with
`O_NOFOLLOW`. Ancestors must be root-owned and deny group/other writes; the
authority directory must be root-owned 0700. A production path beneath writable
`/tmp` is rejected, including sticky directories. Files must be root-owned,
regular, 0600 and have one link. Executables must have protected root-owned
ancestors, be regular root-owned executable ELF files, deny group/other writes,
have no setuid/setgid bits or file capabilities, and have one link.

Directory identity and lock device/inode are rechecked during publication and
readback. Root is the trusted local authority. The separate engine credentials
cannot write protected metadata or replace the protected pathname. Do not give
the engine capabilities, supplementary privileged groups or external privilege
escalation authority through its later deployment.

## Fixed inode and private bootstrap FD contract

`origin.lock` is opened without following symlinks and exclusively flocked
nonblocking. Startup conflict denies immediately. No startup kills an old child,
unlocks, truncates, unlinks, replaces or rolls over the lock inode. This is for a
single-host Linux local filesystem supporting flock and directory fsync.

The read-only lock descriptor is passed using `Cmd.ExtraFiles`. Child FD 3 is a
duplicate of the **same open description**, with close-on-exec cleared; it is
not a separately reopened lock. Linux supports this exclusive flock on a local
read-only regular file. Read-only access also prevents the engine from writing
or truncating the inode through the inherited descriptor.

The future accepted private native engine bootstrap MUST:

1. Retain FD 3 unchanged for its entire lifetime. Never close, explicitly unlock,
   replace it or pass it to a detached process. A malicious engine calling
   `LOCK_UN` on the shared description violates the required engine contract.
2. Wait for exactly `G` on FD 5 before entering private transport work, then
   close FD 5. EOF or a different byte denies bootstrap. This gate opens only
   after durable starting metadata records its exact birth identity.
3. Bind the dedicated fixed private origin with its separate private native
   composition. Stock admin/scheduler bootstrap is not an acceptable substitute.
4. Write exactly `R` to FD 4, then close FD 4, only when local private transport
   is ready. This is not an implicit paid probe or provider authentication test.
5. Stay in the foreground, create no surviving descendants, observe SIGTERM,
   and stop its local transport before exiting.

The corresponding environment names are `GATEWAY_LAUNCHER_LOCK_FD`,
`GATEWAY_LAUNCHER_GATE_FD`, `GATEWAY_LAUNCHER_READY_FD` and
`GATEWAY_LAUNCHER_ORIGIN_REF`. FD values are respectively 3, 5 and 4.
`GATEWAY_LAUNCHER_ENGINE_INCARNATION` carries the exact supervisor-generated
lowercase hyphenated UUID recorded before the engine gate opens. Native
composition must use that same value as kernel `engineIncarnation`; request
nonce is a separate future wire identity, never derived from incarnation.
Child stdin/stdout/stderr default to the null device. The launcher does not print
argv, environment, credentials, provider bodies or retained prompts.

Launcher death while the engine survives leaves FD 3 holding the real flock.
A second launcher is denied until every retained holder exits. Startup never
uses a timestamp or an in-memory busy flag as retirement authority.

## Durable lifecycle and exact local retirement

`origin.json` is a bounded root-only journal, atomically replaced using an
exclusive bounded staging slot, `origin.next`, in the protected directory. The file is fsynced
before rename and the directory is fsynced before successful publication.
Canonical supervisor encoding rejects duplicate/aliased/corrupt record fields.
Readback re-establishes file/directory durability before returning facts that
might have become visible during a previous failed fsync.

Each supervisor-generated binding records originRef, kernel boot ID, PID,
`/proc/PID/stat` birth ticks, a fresh random RFC 4122 version-4 canonical UUID incarnation, and lock
device/inode. There is no caller-provided incarnation or identity authority.
The phases are `reserved`, `starting`, `ready`, `start-failed` and `retired`.
Ready is published only after the local bootstrap handshake and durable
replacement. An error never returns successful readiness.

A durable reservation precedes exec. A failed exec records a no-child
`start-failed` fact and creates no retirement receipt. A crash between exec and
durable process identity leaves an unresolved reservation and denies startup;
the missing exact birth cannot be invented. A post-exec durability failure
returns a nonnil launcher handle with the error. Composition MUST retain that
handle and cancel/wait; it must not mistake the error for no child.

On exact `Cmd.Wait` completion the supervisor drops its own lock reference and
tries an independent open description. Another retained holder still blocks
retirement. Once safely reacquired, it compares the protected exact original
binding and durably appends an observed-child-exit receipt. A trusted supervisor
winning the reacquisition race may instead recover that same exact receipt.

After supervisor loss, recovery requires exclusive reacquisition of the fixed
inode and verification of the protected previous incarnation. The old PID must
be absent, or its exact birth must be kernel-reported terminated (Z/X). A reused
PID, live process, wrong boot, wrong origin or wrong inode denies. A new host boot
is not proof. A zombie is already terminated but may await another parent's reap.
Recovery is durably recorded before a fresh boot reservation is written, and
the old receipt is retained in the same journal.

`ReadReceipt` is a root-only private trusted-composition API requiring the whole
original binding. It rejects wrong incarnation, PID/birth, boot, origin, lock or
scope. The only scope is `exact-local-process-transport-teardown-v1`. This proves
local teardown only: never provider NoEffect/nonbilling, replay permission,
spent-budget refund or SQL occupancy release. The kernel separately compares
scope and its original occupied binding under current cleanup authority. This
component performs no DB/TS cleanup or acknowledgement.

The journal retains at most 64 exact receipts and never evicts any. There is
only one staging slot; a crash-abandoned slot is preserved and denies further
publication, bounding orphaned records without unresolved evidence eviction. Saturation
denies new startup. There is deliberately no arbitrary prune or reset API.
Unresolved reservations and cross-boot identity mismatches remain quarantined;
external retention/recovery policy is a separate qualified responsibility.
Never delete a lock inode or discard unresolved evidence to bypass a denial.

## Bounded shutdown and command use

`Shutdown(ctx)` sends SIGTERM only through the exact exec child handle and waits
within the supplied deadline, including after actual child exit while the
lifecycle mutex or durable publication is blocked. One lifetime publication
worker owns all post-start readiness/retirement durability. Unbuffered admission
keeps at most one operation outstanding; retries select their own context and
create no new workers. Cancellation returns `ErrNotReady`/`ErrPending`, retains
the original authority handle, and leaves ongoing publication to finish. A late
successful publication remains available on that handle and protected readback;
only durable receipt success closes its authority. A stubborn child yields
pending/failure with the lock and evidence preserved. No escalation, automatic restart or daemonization
is performed. Receipt success and an uncertain wait timeout are distinct.

The command takes trusted `-protected-dir`, `-origin-ref`, `-engine`,
`-engine-uid`, `-engine-gid`, optional bounded `-ready-timeout` and
`-shutdown-timeout`, followed by `--` and configured engine arguments. Waits
default to 10 seconds and must be positive and at most one minute. Parsing and
runtime errors use fixed safe messages. The command is not wired into stock
main, systemd, deployments or public APIs.

## Qualification and candidate handoff

Actual Go/Linux tests are authored in `launcher_linux_test.go`. Each test states
its regression before execution. They use only newly created
`/run/gatewaylauncher-fixture-*` directories and copies of the test executable.
They require root and actual separate synthetic UID/GID 65534 exec; capability
preflight failures report NOT_RUN. There is no production test hook.

The suite observes inherited FD after exec, same-description flock, non-CLOEXEC
and read-only FD, engine metadata denial, real independent flock contention,
supervisor termination with a surviving old child, exact recovery/readback,
two racing supervisor processes, path/owner/permission/symlink/hardlink/inode
rejection, actual malformed ELF exec failure, actual O_PATH directory fsync
failure, wrong original bindings/scope and recovery birth/boot rejection,
bounded stubborn-child cancellation, a real retained FD holder after child
exit, immutable synthetic configuration, and saturation from 64 actual exits.
Negative identity tests deliberately corrupt only disposable root-owned fixture
metadata. They do not create production evidence or use missing APIs as negatives.

Initial worker execution status: **NOT_RUN** for Go compilation, gofmt, vet, race and
Linux behavioral qualification because Go is not installed. The worker's root
identity does not bypass its filesystem sandbox; /run fixture authority is not
an installed-runtime qualification. No passing behavioral receipt is claimed.
The installed runtime also denies linked Git metadata access. Full Internet
reachability is not qualified here; credential/filesystem isolation was retained.
No credentials, providers, real projects, workers, sessions or accounts are used.

Primary must use pinned Go **1.27.1**, format these new Go files, recompute exact
candidate hashes, and run from `backend` in a disposable root Linux environment:

```text
GOTOOLCHAIN=local go version
GOTOOLCHAIN=local go test ./internal/gatewaylauncher ./cmd/gateway-launcher -count=1 -v -timeout=3m
GOTOOLCHAIN=local go test -race ./internal/gatewaylauncher -count=1 -v -timeout=3m
GOTOOLCHAIN=local go vet ./internal/gatewaylauncher ./cmd/gateway-launcher
```

Retain actual command output, exact source hashes, failed and NOT_RUN cases, and
an independent `gpt-6.1-sol/xhigh/default` exact-source review before acceptance.
The integration controller applies/commits/pushes the guarded new-file packet.
The worker leaves its source diff intact and does not retry Git writes.

External requirements remain the accepted private native bootstrap with gate/
readiness and whole-life FD retention, separate credential custody/composition,
private origin deployment and capability isolation, kernel original-binding
cleanup verification, and assembled TS/Go loss qualification. This launcher
candidate alone does not qualify facade, native dispatch, billing, provider,
SQL occupancy release or product deployment.

## Primary qualification 2026-10-03

The guarded terminal53949833 candidate was materialized only after actual base16d621c2, complete owned pathset and actual hashes were verified. Producer timeout retained candidate; it is not source approval.
Pinned Go1.27.1 from golang image sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414: gofmt on new owned Go files, actual disposable root Linux process tests in isolated container and go vet PASS, zero skips.
Initial host race run skipped synthetic exec because host /run is noexec; it is NOT accepted as a behavioral pass. The same source race binary built using that pinned toolchain and host GCC ran in NEW digest-pinned PG17.10 Debian container ag-launcher-race-NEWTEST-20261003-v1, network none, with real nonroot synthetic exec: PASS, zero skips and no race diagnostics, including actual64-receipt saturation.
Receipts retained under /srv/workers/jobs/account-gateway/first-slice-v1/tmp/qualification-launcher-v1/results/. Exact-source independent xhigh/default review and CI remain pending; native bootstrap composition, SQL acknowledgement, actual provider/E2E/deployment remain NOT_RUN.


## e206 bounded repair handoff — 2026-10-03

This changes only the existing seven-path PR3 component. Supplied repair base:
`e206dc063c07f669373df7f089ff92ae9bdf4c82` (5ca plus qualified lintv5).
The one exclusive Git lock probe returned ENOENT for the linked gitdir; no Git
operation, write, commit, push or history change followed. Exact commit/tree
association remains **UNVERIFIED**, not inferred from the supplied label.
Before-file snapshots and their SHA256s are retained with the exact unified
repair patch and after-file hashes outside the source tree at:
`/srv/worker-state/jobs/account-gateway/first-slice-v1/jobs/account-gateway-20261003-native-launcher-reviewed-fixes-b3b/tmp/agent/launcher-e206-artifacts/`.
Command source and command tests retain their supplied qualified lintv5 bytes.
Only launcher lifecycle/storage, their existing tests, package contract comments
and this existing document are edited; no other component is owned.

Actual inputs read: `.spike-inputs/normative53.md` has the required immutable
SHA256 `66a2393e7a55f76df1a78281af44379d0b455a0770d82f34e587dcca284157b0`;
Q, launcher-review and lean-scope-review were read. Q's smallest cohesive
boundary is one launcher-owned publication worker, with no generic framework,
identity mapper, ledger, new dependency or production test hook.

Both path walkers now Fstat the opened `/` before opening its first child:
root owner, directory type and no group/other writes are mandatory. The owned
root fixture changes only its fresh disposable directory to 0777 then 0755;
a reexecuted child chroots there after loading its image (also usable by the
race binary). Host `/` is never chmod'ed. Both actual walkers must deny 0777
and accept 0755; unavailable chroot authority is explicitly NOT_RUN.

Both orphan cleanup callbacks now acquire a Linux pidfd BEFORE birth-checking
and signal exclusively through that pinned descriptor. No numeric-PID signal
fallback exists. The additional controlled PID/mount namespace fixture adopts
and reaps an actual engine orphan after its birth was checked, creates an
actual same-PID replacement using namespace-local `ns_last_pid`, requires the
old pinned signal to return ESRCH and proves the replacement exits normally
under its own stop marker. Namespace-local proc mount/controlled reuse/pidfd
restrictions are explicit NOT_RUN, never a pass. All processes are owned
synthetic fixtures; the namespace must be PID 1 before any reuse control.

Canonical UUID is generated with the existing UUID primitive, supplied to the
engine environment, and checked on current reservation/birth and every retained
retirement binding/readback. Lowercase hyphenated spelling is required; parsing
alone is insufficient. The existing inherited-FD observable test independently
checks a v4 UUID and exact engine/environment/binding agreement. Existing
recovery denials now include old 64-hex journals, noncanonical spelling and
legacy receipts, and assert denied journal bytes remain unchanged. This is a
fresh unreleased sandbox contract: incompatible journals fail closed without
migration, reset or guessed identity. Exact closure still requires child exit
or protected recovery, original boot/PID birth/inode and scope, all holders
gone and fsync. It proves local teardown only, never NoEffect or refunds.

The deadline regression uses actual fixture R/EOF or child exit before holding
the existing mutex. Readiness, Wait and Shutdown with a concurrent background
Wait must return by their short context before unlock across repeated retries,
retain real flock authority and later expose the same durable exact receipt.
It uses no new production helper or hook, so an old-source overlay can compile
and fail behaviorally. Authored tests are not observed behavioral reds.

| Evidence | Current status |
| --- | --- |
| Protected source inspection, four repair edits, frozen Contract 53 digest and before/after byte hashes | Actually observed in this worker |
| Exact unified patch against retained before-file bytes | Worker GNU patch dry-run PASS; application check only, no Go behavioral qualification |
| Earlier primary Go/Linux/vet/race zeroSkip receipts above | Supplied prior-source evidence only; do not qualify this patch |
| Go1.27.1 compile/typecheck of both packages and all their test contracts, gofmt, safe diagnostic/helper tests, vet | Worker PASS; actual retained logs and source hashes below |
| Race binary compilation and qualified golangci-lint v2.13.0 | Worker PASS; full race invocation also observed below, controlled process behavior remains NOT_RUN |
| Full sandbox launcher/command ordinary and race invocations, including root0777/0755 and same-PID replacement fixtures | Each exited 0 with **41 skipped cases**, all at separate synthetic UID/GID preflight; process/root/PID/race gates are NOT_RUN, not PASS |
| Original production + repaired test overlay | Go1.27.1 compile PASS with retained original production hashes; actual before-red NOT_RUN because synthetic UID/GID qualification is unavailable |
| Pinned source approval/CI and composed bootstrap/kernel/native loss qualification | Pending; no source approval or assembled acceptance claimed |

Primary must first verify the before hashes against exact e206 and preserve
other work/history. Apply only this patch, run pinned Go1.27.1 gofmt and the
existing targeted test/vet/race commands above, plus the already-qualified lint
configuration with pinned golangci-lint v2.13:
`golangci-lint run ./internal/gatewaylauncher/... ./cmd/gateway-launcher/... --timeout=30m`.
Keep actual logs and recompute hashes after formatting. Run the
full launcher and command boundary; zero skips is mandatory for the final Linux
gate. The PID/mount namespace fixture requires controlled disposable container
namespace/proc-mount/reuse authority (including SYS_ADMIN and CHECKPOINT_RESTORE
or SYS_ADMIN for namespace-local `ns_last_pid`); do not grant capabilities to
a deployed engine. No host proc sysctl or unrelated process may be modified.

For a believable before-red, copy the new test file onto a disposable copy of
the exact e206 library while retaining its production files, then run
`go test ./internal/gatewaylauncher -run 'TestPublicationDeadlinesAfterObservation|TestRootDirectoryAuthority|TestInheritedDescriptionAndAuthority|TestRecoveryIdentityDenials' -count=1 -v`
in the same controlled fixture environment. The failure must be reached after
actual exec/readiness/exit or unsafe-root acceptance, not a compiler diagnostic.
The test-only pinned cleanup helper is compiled with that overlay and keeps the
qualification safe even against old production source. Preserve all useful
existing cases, required independent exact-source review and exact-head CI.
No bootstrap, custody, kernel, RR, providers, credentials, real-project tests,
full UI, OAuth or platform changes are part of this handoff.


### Worker verification continuation — 2026-10-03

To complete available checks, the worker unpacked only the required qualified
versions into the private artifact directory, without global/runtime installation.
The official [Go release manifest](https://go.dev/dl/?mode=json&include=all)
and downloaded `go1.27.1.linux-amd64.tar.gz` independently agree on SHA256
`63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445`;
actual version output is `go version go1.27.1 linux/amd64`.
The [official golangci-lint v2.13.0 release](https://github.com/golangci/golangci-lint/releases/tag/v2.13.0)
archive matches its release checksum. That released lint executable was built
with Go1.27.0; its analysis uses this worker's pinned Go1.27.1 executable and the
unchanged repository lint configuration. These are worker observations, not
reuse of the earlier supplied Docker qualification.

Go1.27.1 gofmt, compilation/typechecking of both complete packages and their test
contracts, the existing safe helper/argv diagnostic tests, go vet, race binary
compilation and scoped qualified lint all PASS. The initial lint found two
switch-style diagnostics and one fixture-only G702 taint warning; actual logs
are retained. The test now uses tagged switches and reexecs the controller's
own copied test ELF. G702's remaining argument taint is locally justified on
that test call: owned fixture data is passed as argv inside the private PID
namespace, with no shell/interpreter. No production suppression or lint config
change was made; final lint reports zero issues.

The full `go test ./internal/gatewaylauncher ./cmd/gateway-launcher -count=1 -v
-timeout=3m` invocation exited 0, but **41 fixture cases were skipped** at the
synthetic UID/GID ownership preflight. This is NOT a Linux/process behavioral
PASS and does not clear the required zeroSkip gate. No same-UID fallback,
capability grant, runtime patch or isolation weakening was attempted. Separate
synthetic ownership, root0777/0755, actual same-PID reuse, process race execution
and actual old-code behavioral red still require the controlled primary runner.

The exact original production files were copied into a separate disposable
compile overlay together with the repaired existing test file. Its Go1.27.1
`go test -c ./internal/gatewaylauncher` PASS proves the regression does not rely
on a missing production helper or compilation error; it is not a behavioral
red. The overlay leaves the retained before snapshots and source worktree intact.

All compiler/vet/race/lint invocations disable build VCS stamping and use
read-only module mode (`GOFLAGS=-mod=readonly -buildvcs=false`, `GOVCS=*:off`).
The one earlier Git probe was not repeated. Both module files and both command
files retain their original exact bytes; Contract 53 and review inputs remain
unchanged. No new Node helper was needed.

Retained actual commands, logs, tool/checksum provenance, original-production
compile overlay and race executable live under `worker-qualification/`,
`qualified-go1.27.1/`, `qualified-golangci-lint-v2.13.0/` and
`before-production-test-overlay/` in the artifact directory above.
`worker-qualification/final-results.json`, `full-sandbox-suite-result.json` and
`before-production-compile-result.json` distinguish completed checks from the
remaining privileged gates. Exact patch and seven-file hashes are regenerated
after actual formatting. The full goal remains unverified until controlled
zeroSkip process/root/PID/race execution and the genuine before-red are observed.

The subsequent full pinned Go1.27.1 worker race invocation,
`go test -race ./internal/gatewaylauncher ./cmd/gateway-launcher -count=1 -v -timeout=3m`,
exited 0 with the same **41 skipped fixture cases** at synthetic UID/GID
ownership preflight. The safe helper and argv diagnostics actually ran under
race instrumentation; the launcher lifecycle/root/PID behaviors were never
reached and remain NOT_RUN. Actual output and the false zeroSkip gate are
retained in `worker-qualification/full-sandbox-race-suite.log` and
`full-sandbox-race-suite-result.json`. All six owned Go files retain their
previously qualified exact bytes; only this evidence document changed.
