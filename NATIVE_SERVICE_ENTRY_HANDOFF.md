# Foreground native service entry

Linux command: backend/cmd/account-gateway. Reuses accepted gatewaylauncher and
gatewaybootstrap; no kernel/SQL/SDK/Node/engine transport change.

## Operator contract

Build from backend with pinned Go 1.27.1, readonly modules and VCS stamping off:

    GOTOOLCHAIN=local GOFLAGS='-mod=readonly -buildvcs=false' go build -o /controlled/output/account-gateway ./cmd/account-gateway

Install the exact ELF at a fixed root-owned single-link executable path beneath
protected ancestors, without setuid/setgid or capabilities. Root invokes:

    /usr/local/libexec/account-gateway --bootstrap-file /etc/account-gateway/bootstrap.json --authority-dir /var/lib/account-gateway/authority --origin-ref native-mimo-origin-1 --engine-uid 65534 --engine-gid 65534

The bootstrap is an immutable root-owned regular single-link 0600 file, 1..65536
bytes, opened readonly with O_NOFOLLOW/NONBLOCK. The existing launcher captures
it; no pathname reopen. The authority directory is root-owned 0700 on a local
Linux filesystem; never replace/unlink its lock or journal to force startup.

FD6 uses the existing strict schema in backend/ACCOUNT_GATEWAY_BOOTSTRAP.md:
listenAddress, postgresDSN, authority, custody, peers, profile and maxEntries.
The database must already have the accepted native migrations. Keys and DSN
belong only in the protected bootstrap, never argv, environment or diagnostics.
Profile is server-owned native Responses. The command uses normal system TLS,
fixed GIN_MODE=release and the existing privilege drop/FD3-6 contract. It adds no
migrations, paid startup probe, scheduler, retry, restart or public admin route.

## Lifecycle and safe output

JSON lines expose only state and complete captured binding. PID/birth/device/
inode are decimal strings. After successful Start, starting exposes the original
binding so Node authority can validate enrollment; it grants no readiness or
dispatch. Only successful bounded AwaitReady emits ready. Readiness and exact
handle shutdown each have ten-second bounds; filesystem/output I/O is separate.

Signals and metadata write failures shut down the original handle, including a
nonnil handle returned with post-exec Start failure. SIGPIPE is ignored so broken
output pipes reach this path. retired requires exact ReadReceipt against the
original binding; its scope is only local process/transport teardown. Otherwise
pending retains protected evidence. Child exit, exit code, timeout or credential
erasure never prove provider NoEffect, billing status or SQL occupancy release.
An unexpected engine exit stays nonzero even if exact retirement succeeds.

## Evidence, 2026-10-04

Producer linked Git/compiler/module cache was inaccessible; worker checks were
NOT_RUN. Primary verified exact source725/accepted0a88 and qualified the patch
using the existing pinned host cache: gofmt unchanged, tests/build/vet PASS.

- Actual closed-FD2 test: removing SIGPIPE handling produced signal: broken pipe;
  submitted source passed. No inherited authority or provider effects.
- Actual command + Node authority + PG17.10 + controlled TLS BEFORE failed at
  binding timeout. Adding starting before AwaitReady resolved the enrollment
  cycle. AFTER passed 1/1, zero skips.
- That assembled run proved encrypted enrollment/readback, two requests in the
  SAME OPEN cap1 execution, exact physical close ACK and retirement/readback.
- Unexpected exit: match captured boot/birth, kill only that disposable child,
  require nonzero parent exit with exact original retirement receipt. PASS1/1.
- TLS trust was installed only in the new disposable container. The guarded
  test-only initializer migrated a NEW DB; the production command did not.
  All own containers were removed after receipts. No real provider calls.

Qualified image SHA256:
d92e867145a2fdc9e1acb4e10e03a862d1283596c49a42cf58ef11af853646f9.
Before/after/unexpected logs SHA256 respectively:
bd09357bd748ec1729a6f66e398748af487904bf1954fdad85b25b09b6be7bb9,
7a8273ed5eaf73144eb1c81d1cc688203130774b81a131dadac7fb4fd1df72df,
8bb3cd6919e123f2208682bb3fa05d917599464c932c6c55445ce08d26db718b.

Current CI builds/vets/tests this command and requires both named tests without
SKIP. Independent source review/current CI remain required. This is controlled
service evidence; real MiMo/Codex/T0/parser/App, deployment, full D-final/S/E/F/G
and release are not qualified. Original worker patch/failed receipts are retained
outside source; no credentials were printed or exported.
