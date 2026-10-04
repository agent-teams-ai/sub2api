// Package gatewaylauncher implements the private, single-host Linux engine
// lifetime boundary. Only a trusted root supervisor may compose this package.
// It is deliberately unrelated to public account APIs and provider credentials.
//
// The configured engine must retain inherited FD 3, without closing, unlocking,
// replacing or passing it to detached processes, for its entire lifetime. It
// waits for one byte on FD 5 before doing any transport work, then closes FD 5.
// Once its private transport is ready it writes exactly "R" to FD 4 and closes
// FD 4. GATEWAY_LAUNCHER_ENGINE_INCARNATION contains the supervisor-generated
// canonical UUID also persisted in the original binding and retirement receipt.
// This handshake is local bootstrap readiness, never a provider probe.
// Optional Config.BootstrapFile is a readonly root-owned 0600 regular file,
// 1..65536 bytes, captured without pathname reopen and inherited as FD 6.
// Start owns only its duplicate; the caller retains ownership of its original.
// Configuration bytes never enter environment, journal or retirement receipt.
// The engine must run in the foreground, create no surviving descendants, and
// stop its transport before exiting. Stock sub2api main is NOT this bootstrap.
//
// Receipts attest only to this local lifetime boundary. Trusted kernel
// composition must separately compare the complete original binding. A receipt
// says nothing about upstream effect, billing, replay, refunds or SQL occupancy.
package gatewaylauncher
