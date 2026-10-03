# Private native transport component

Owned lane: `internal/gatewaytransport/**`, additive private observation in
`service/native_gateway_identity.go` and `native_gateway_lifetime.go`, this file.
No SDK, SQL, launcher, stock-server or ordinary-path edits. No provider launch,
credential-file access, dependencies, deployment or Git mutations.

Supplied custody source: `4e4e626b57ba6dac938207a85151ea3a16932081`, tree
`df46347f44eac687269459a369ad6bd9d329e167`; receipt records primary crypto/PG/privateAPI
passes; native source remains candidate and old fixture compatibility is pending. Git's linked
worktree metadata is inaccessible here, so these are supplied identities, not an
observed HEAD. Initial observed identity SHA256 matches its custody receipt:
`aeba8b37d6e3710e128697de59bc0f281df8225b5e7b215d834746a97be86d01`.
Norm53 sections 3–4 digest:
`66a2393e7a55f76df1a78281af44379d0b455a0770d82f34e587dcca284157b0`.
Q digest: `fdf2099991d7d7e36f9e636c3029e136104c2c22e5005bb9cbde38c1cd555fa0`.

## Mount and authority

Use the existing OpenAIGatewayService constructor with the existing HTTPUpstream
wrapped by `NewGatewayNativeLifetimeUpstream`. `gatewaytransport.New` refuses an
unobserved service or missing custody, authenticated peer mapping, qualified
static profile/caps, fixed callback authentication/origin, exact enrollment
validation, dispatch proof verification or leased cleanup/SQL-ACK ports.
Mount its `http.Handler` on a dedicated opt-in bounded private net/http listener.
Nothing mounts automatically. Stock scheduler/admin/probe middleware is absent.
An observed service refuses direct `ForwardGatewayRoute` without its private
lifetime and matching encrypted-row consumer/logical account/generation scope.
Ordinary calls on the upstream wrapper delegate unchanged. Only this private
native call passes ordinary account Concurrency as zero; SQL owns occupancy.

The protected accepted launcher must supply/verify the origin and incarnation.
This component generates only the reservation nonce (crypto-random UUIDv4).
It neither invents an incarnation nor certifies process retirement. Verification
ports are trusted server composition, never execution-client HTTP authority.
`VerifyDispatch` verifies the permanent token and exact worker/current lease.
`AuthorizeCleanup` verifies current SQL cleanup lease/CAS and exact original proof.
`AcknowledgeClosure` must return success only after SQL durably ACKs exact closure;
all errors retain the receipt. These ports must be bounded by their contexts.

## Frozen private wire (not SDK v1)

All four routes use POST, application/json, no query/encoding or caller origin:
`/private/native/v1/transports`, `/cancel`, `/read`, `/ack` (suffixes on transports).
Server auth maps execution and cleanup roles separately to opaque consumer IDs.
The TS backend resolves its protected physical mapping BEFORE this native POST.
CI supplies neither consumer nor descriptor. Full kernel admission includes the
issuer and execution fields omitted from the public SDK admission DTO.

Exact native POST example (NEWTEST identifiers only):

```json
{
  "requestRef": "NEWTESTrequest",
  "worker": "44444444-4444-4444-8444-444444444444",
  "admission": {
    "executionRef": "11111111-1111-4111-8111-111111111111",
    "issuerEpoch": "22222222-2222-4222-8222-222222222222",
    "invocationRef": "NEWTESTinvocation", "attemptRef": "NEWTESTattempt",
    "accountRef": "66666666-6666-4666-8666-666666666666",
    "authorizationEpoch": 3, "subjectRef": "NEWTESTsubject",
    "policyRevision": 4, "bindingRevision": 5,
    "profileId": "openai-responses-apikey-v1",
    "limits": {"requests":2,"concurrency":1,"requestBytes":4096,"outputBytes":4096,"tokens":100},
    "expiresAt": "2026-10-04T00:00:00Z"
  },
  "descriptor": {
    "account_id":7,"generation":"33333333-3333-4333-8333-333333333333",
    "created_at":"2026-10-03T01:02:03.123456789Z",
    "profile":"openai-responses-apikey-v1","base_url":"https://NEWTEST.invalid","model":"NEWTESTmodel"
  },
  "payload":{"model":"NEWTESTmodel","input":"NEWTEST","store":false,"stream":true,"service_tier":"default"}
}
```

One fixed-origin, no-retry POST `/private/native/v1/admit` carries exactly:
`{consumerId, requestRef, worker, admission, descriptor, native}`. Admission and
snake-case descriptor are the originals above. `native` is
`{originRef,engineIncarnation,requestNonce,generation}` with server origin,
protected incarnation, fresh canonical UUID nonce and physical generation.
Callback performs the SOLE SQL claim; the native component never preclaims.

The successful callback JSON has exactly `consumerId`, `admission`, `status`,
and these optional first-claim fields: `dispatch`, `nativeDescriptor`,
`leaseExpiresAt`. `status` is kernel `{requestRef,effect,code?}`.
`dispatch` is the actual kernel ClaimResult object:

```json
{
  "descriptor":{"generation":"33333333-3333-4333-8333-333333333333","nativePhysicalIdentity":"33333333-3333-4333-8333-333333333333","profile":"openai-responses-apikey-v1"},
  "executionRef":"11111111-1111-4111-8111-111111111111",
  "requestRef":"NEWTESTrequest",
  "limits":{"requests":2,"concurrency":1,"requestBytes":4096,"outputBytes":4096,"tokens":100},
  "deadline":"2026-10-04T00:00:00Z",
  "closure":{
    "executionRef":"11111111-1111-4111-8111-111111111111","requestRef":"NEWTESTrequest",
    "worker":"44444444-4444-4444-8444-444444444444","token":"NEWTESTproof",
    "native":{"originRef":"NEWTESTorigin","engineIncarnation":"55555555-5555-4555-8555-555555555555","requestNonce":"88888888-8888-4888-8888-888888888888","generation":"33333333-3333-4333-8333-333333333333"}
  }
}
```

`nativeDescriptor` repeats the exact snake-case descriptor; `leaseExpiresAt` is
an explicit current worker lease RFC3339 instant. Every binding is checked, plus
full admission, five limits, deadline and expiry at callback AND final native CAS.
No dispatch means authenticated readback only; omit all three first-claim fields.
Missing/partial/4xx/timeout replies seal the reservation, retaining unknown SQL
facts even though native non-entry may be positively observed.

Cleanup POST body is exactly `{proof,cleanup}`: `proof` is original closure above;
`cleanup` is `{cleanupRef,worker,token,leaseExpiresAt}` from CURRENT SQL cleanup.
A recovered original proof may attach only to a sealed entry; cancel seals first.
Read and repeated ACK return the same binding without admitting or replaying.
Receipts are private `{consumerId,executionRef,requestRef,native,proof?,phase,
effect,status?,sealed,acknowledged,lifetime}`. Phase is reserved/admitted/entered/closed;
observed effect remains unknown unless actual qualified terminal delivery succeeds;
optional status is authenticated kernel callback readback, never another permit. 202 is
readback, never durable SQL ACK or no-effect attestation. SQL settlement reads the
exact receipt/proof; the facade must authenticate its existing effect/rejection
and closure transactions separately. This component creates no native ledger.

## Physical lifetime and bounds

Registry entries use the full consumer/execution/request/generation/origin/
incarnation/nonce identity, with a bounded secondary request index for duplicates.
MaxEntries bounds live plus retained unacknowledged reservations. Saturation
precedes callback/claim; unresolved entries never evict. Only SQL-ACKed closed
receipts may evict under pressure; SQL spent claims remain replay authority.
Raw payload hashes are retained for duplicate intent comparison; payload bytes,
outputs and credentials are not cached. Approved input bytes are enforced both
before and after canonical cap insertion/clamping. Critical parser is reused;
only output-cap bytes change, and unrelated tool/user objects remain opaque.
Original numeric account IDs and caps must be canonical safe integers; decoded
duplicates/case/Unicode aliases, store/stream/tier overrides and previous response
fields deny. Native response repair/terminal validation remains the existing path.
The physical body wrapper enforces approved output bytes before delivery.

Private observation uses the actual owned response body. Cancel and defer share
one physical Close and its cached outcome; error/blocked Close is not closure.
Closure requires context Done + Forward return + body closed (or proved no body).
The receipt also exposes the actual permanent observer seal, including cancellation
before the handler returns. A second fresh per-call CAS cannot reuse that lifetime.
Registry/observer locks never wait on physical Close or Forward. One context
watcher/closer per active bounded entry has owned stop/cleanup; read/duplicate
retries create no watcher. Original net/http ResponseController deadlines interrupt
blocked reads/writes even through Gin, and private FlushError reaches raw writer.
Closure never revises unknown effect or frees SQL occupancy by HTTP inference.

## Qualification and remaining gates

Added component tests use NEWTEST identities and controlled local HTTP callbacks,
real held HTTP bodies, request-context cancellation and blocked downstream writes.
They cover duplicate reservations/HTTP POST readbacks, full callback binding
mutations, saturation, lost/held ACK sealing, caps/aliases, Close failure, current
cleanup ACK loss and repeated exact receipts. Existing native SSE parsing is
exercised through real local HTTP bodies: terminal bytes, partial frames, approved
output overcap, duplicate type and invalid UTF-8. These synthetic peers are NOT
actual SQL integration; parser fixtures supply no native row, provider key or claim.

Actual worker checks pass on checksum-verified official Go1.27.1 linux/amd64:
owned NEWTEST unit and race tests, production gatewaytransport build, unit-tagged
gatewaytransport/service vet, and gofmt. Existing go.mod/go.sum hashes are unchanged.
Linked Git metadata remains inaccessible after the single probe; the exact patch
and inspected SHA256 manifest accompany this handoff. Primary still owns encrypted
mounted-native dual permission POST/callback yielding one upstream entry, actual
migrated SQL B receipts and private/ordinary custody fixture qualification.

Remaining bootstrap/facade/SQL/RR/provider gates: accepted inherited-lock launcher
package and protected main binary/private listener wiring; TS bounded native
adapter using this exact wire; actual migrated PG sole claim, leased settlement
and closure ACK integration; lost ACK/TS loss/Go restart B receipt and verified
old-process retirement; RR membership/fence/preparation and protected publication;
qualified MiMo catalog/endpoint/caps and controlled assembled receipt before any
provider run. Accepted kernel/B2a and management31f/a62 do not prove assembly.
The separate launcher writer and primary custody fixture repair remain untouched.
