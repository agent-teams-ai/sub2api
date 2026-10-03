// Package gatewaylauncher implements the private, single-host Linux engine
// lifetime boundary. Only a trusted root supervisor may compose this package.
// It is deliberately unrelated to public account APIs and provider credentials.
//
// The configured engine must retain inherited FD 3, without closing, unlocking,
// replacing or passing it to detached processes, for its entire lifetime. It
// waits for one byte on FD 5 before doing any transport work, then closes FD 5.
// Once its private transport is ready it writes exactly "R" to FD 4 and closes
// FD 4. This handshake is local bootstrap readiness, never a provider probe.
// The engine must run in the foreground, create no surviving descendants, and
// stop its transport before exiting. Stock sub2api main is NOT this bootstrap.
//
// Receipts attest only to this local lifetime boundary. Trusted kernel
// composition must separately compare the complete original binding. A receipt
// says nothing about upstream effect, billing, replay, refunds or SQL occupancy.
package gatewaylauncher
