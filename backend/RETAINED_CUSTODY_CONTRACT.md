# Native retained-custody readback contract

Contract string: `native-retained-custody/v1`.

This is a private, inert, server-only readback boundary for an already retained
native credential. It is not an admin/public route, secret export, decrypt API,
provider probe, refresh, reconnect, create, activation, erase, or scheduler
action. Existing candidate metadata GET remains unchanged and key-independent.

## API-key route

`GET /private/native/v1/candidates/:generation/custody`

The request is one bounded JSON object. The generation is the path value and is
also bound by the descriptor:

```json
{
  "contract": "native-retained-custody/v1",
  "owner_ref": "workspace/owner",
  "account_ref": "account/logical",
  "descriptor": {
    "account_id": 42,
    "generation": "11111111-1111-4111-8111-111111111111",
    "created_at": "2026-10-19T00:00:00.123456Z",
    "profile": "openai-responses-apikey-v1",
    "base_url": "https://provider.invalid/v1",
    "model": "qualified-model"
  }
}
```

Success is a finite sanitized result:

```json
{
  "contract": "native-retained-custody/v1",
  "generation": "11111111-1111-4111-8111-111111111111",
  "native": {"account_id": 42, "generation": "...", "created_at": "...", "profile": "...", "base_url": "...", "model": "..."},
  "credential_kinds": ["api_key"],
  "retention": {"state": "active", "credential": "retained"},
  "proof": {"authenticated": true}
}
```

`state` is only `active` or `inactive`; it is a retained-row state fact, not a
provider capability claim. The proof authenticates the persisted AES-GCM
material with the exact immutable consumer/owner/account/generation/purpose
scope and exact physical descriptor, including the persisted birth instant.
Wrong composition key, retired key, tampered ciphertext, missing/erased row,
foreign scope, changed descriptor and tombstone restoration all fail closed.

## Codex OAuth route

`POST /private/native/v1/oauth/connect/custody`

The body is bounded and uses the original enrollment scope selector plus the
exact qualified native descriptor:

```json
{
  "contract": "native-retained-custody/v1",
  "operation": "original-connect-operation",
  "owner_ref": "workspace/owner",
  "account_ref": "account/logical",
  "generation": "22222222-2222-4222-8222-222222222222",
  "descriptor": {"account_id": 43, "generation": "...", "created_at": "...", "profile": "openai-codex-oauth-responses-v1", "base_url": "https://chatgpt.com/backend-api/codex", "model": "gpt-5.6-sol"}
}
```

Success has the same shape with `credential_kinds: ["oauth"]` and:

```json
{
  "retention": {"state": "inactive", "credential": "retained"},
  "proof": {"authenticated": true},
  "oauth_policy": {
    "provider_validity": "unasserted",
    "expired_but_refreshable": "eligible-by-existing-policy"
  }
}
```

`expired_but_refreshable` is one of `eligible-by-existing-policy`,
`not-due-by-existing-policy`, or `not-qualified-by-existing-policy`. It reports
only the existing authenticated timing policy over retained bytes. It never
asserts provider validity, performs a token refresh, or makes a network call.
OAuth readback remains inert even when the access token is expired but the
retained bundle is eligible under that trusted policy.

Both responses never contain plaintext, tokens, key IDs, envelopes,
fingerprints, raw diagnostics, or credential equality information. The
repository performs a locked exact physical read; the service decrypts and
authenticates only within the existing native custody boundary and clears
transient plaintext byte buffers where Go permits.
