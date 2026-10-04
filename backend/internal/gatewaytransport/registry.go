package gatewaytransport

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/google/uuid"
)

type Peer struct {
	ConsumerID string
	Role       string
}
type Enrollment struct{ OriginRef, EngineIncarnation, QualificationRef string }
type QualifiedProfile struct {
	Profile, Model, BaseURL, QualificationRef                  string
	RequestBytes, OutputBytes, Tokens, ProviderTokenUpperBound int64
}

// These are narrow server-owned authority ports to existing composition. They
// never receive authority inferred from the execution client's body. Cleanup
// ACK succeeds only after the existing SQL closure transaction durably ACKs.
type Config struct {
	Gateway                                    *service.OpenAIGatewayService
	Custody                                    *service.GatewayNativeCredentialCustody
	Authorize                                  func(*http.Request) (Peer, error)
	Enrollment                                 Enrollment
	VerifyEnrollment                           func(context.Context, Enrollment) error
	Profile                                    QualifiedProfile
	CallbackOrigin, CallbackCredential         string
	VerifyDispatch                             func(context.Context, string, Proof, time.Time) error
	AuthorizeCleanup                           func(context.Context, string, Proof, CleanupLease) error
	AcknowledgeClosure                         func(context.Context, string, Proof, CleanupLease, Receipt) error
	AuthorizeOwnerClosure                      func(context.Context, string, Proof) error
	AcknowledgeOwnerClosure                    func(context.Context, string, Proof, Receipt) error
	MaxEntries                                 int
	CallbackTimeout, IOTimeout, CleanupTimeout time.Duration
	EnvelopeBytes, CallbackBytes               int64
}

// ownerClosure is separate from delegated cleanup. Exact original proof remains
// closure authority after worker expiry; it is never another dispatch permit.
// Each call rechecks the optional trusted authority, including idempotent ACKs.
func (h *Handler) ownerClosure(ctx context.Context, consumer, action string, p Proof) (Receipt, error) {
	if !p.valid() || h.cfg.AuthorizeOwnerClosure == nil || (action != "read-owner" && action != "cancel-owner" && action != "ack-owner") {
		return Receipt{}, errDenied
	}
	ownerCtx, cancel := context.WithTimeout(ctx, h.cfg.CleanupTimeout)
	defer cancel()
	if h.cfg.AuthorizeOwnerClosure(ownerCtx, consumer, p) != nil || ownerCtx.Err() != nil {
		return Receipt{}, errDenied
	}
	key := transportKey{requestKey{consumer, p.ExecutionRef, p.RequestRef}, p.Native}
	h.mu.Lock()
	e := h.entries[key]
	if ownerCtx.Err() != nil || e == nil || e.native != p.Native || e.request.Worker != p.Worker || (e.proof != nil && *e.proof != p) {
		h.mu.Unlock()
		return Receipt{}, errDenied
	}
	if e.life.Snapshot().Sealed {
		e.sealed = true
	}
	if e.proof == nil {
		// Only a sealed original lost-ACK reservation can recover its durable
		// proof. Never set admitted/entered or reopen its cancellation latch.
		if !e.sealed {
			h.mu.Unlock()
			return Receipt{}, errDenied
		}
		copy := p
		e.proof = &copy
	}
	h.mu.Unlock()
	if action == "cancel-owner" {
		h.seal(e)
	}
	r := h.receipt(consumer, e)
	if action == "ack-owner" {
		if r.Phase != "closed" || h.cfg.AcknowledgeOwnerClosure == nil ||
			h.cfg.AcknowledgeOwnerClosure(ownerCtx, consumer, p, r) != nil || ownerCtx.Err() != nil {
			return Receipt{}, errDenied
		}
		h.mu.Lock()
		e.acknowledged = true
		h.mu.Unlock()
		r = h.receipt(consumer, e)
	}
	return r, nil
}

// Stop seals every retained lifetime and waits only for positive local closure.
// The host closes its listener first. Timeout/error is not a closure receipt.
func (h *Handler) Stop(ctx context.Context) error {
	h.mu.Lock()
	h.stopping = true
	entries := make([]*reservation, 0, len(h.entries))
	for _, e := range h.entries {
		entries = append(entries, e)
	}
	h.mu.Unlock()
	for _, e := range entries {
		h.seal(e)
	}
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	defer h.callback.CloseIdleConnections()
	for {
		all := true
		for _, e := range entries {
			all = all && closed(e.life.Snapshot())
		}
		if all {
			return nil
		}
		select {
		case <-ctx.Done():
			return errDenied
		case <-tick.C:
		}
	}
}

type requestKey struct{ consumer, execution, request string }

// Full protected reservation identity; the request index only detects retries.
type transportKey struct {
	requestKey
	native NativeBinding
}
type reservation struct {
	request                                         Request // payload is deliberately NOT retained
	digest                                          [32]byte
	native                                          NativeBinding
	proof                                           *Proof
	life                                            *service.GatewayNativeLifetime
	admitted, sealed, acknowledged, callbackStarted bool
	status                                          *requestStatus
	effect                                          string
}

type Receipt struct {
	ConsumerID   string                                `json:"consumerId"`
	ExecutionRef string                                `json:"executionRef"`
	RequestRef   string                                `json:"requestRef"`
	Native       NativeBinding                         `json:"native"`
	Proof        *Proof                                `json:"proof,omitempty"`
	Phase        string                                `json:"phase"`
	Effect       string                                `json:"effect"`
	Status       *requestStatus                        `json:"status,omitempty"`
	Sealed       bool                                  `json:"sealed"`
	Acknowledged bool                                  `json:"acknowledged"`
	Lifetime     service.GatewayNativeLifetimeSnapshot `json:"lifetime"`
}

type Handler struct {
	cfg      Config
	mu       sync.Mutex
	entries  map[transportKey]*reservation
	requests map[requestKey]transportKey
	stopping bool
	callback *http.Client
}

func New(ctx context.Context, cfg Config) (*Handler, error) {
	p := cfg.Profile
	u, err := url.Parse(cfg.CallbackOrigin)
	if ctx == nil || err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || len(cfg.CallbackOrigin) > 2048 || u.Path != "" && u.Path != "/" ||
		(u.Scheme != "https" && (u.Scheme != "http" || (u.Hostname() != "127.0.0.1" && u.Hostname() != "::1"))) ||
		cfg.Gateway == nil || !cfg.Gateway.GatewayNativeLifetimeReady() || !service.GatewayNativeCredentialCustodyReady(cfg.Custody) || cfg.Authorize == nil || cfg.VerifyEnrollment == nil ||
		cfg.VerifyDispatch == nil || cfg.AuthorizeCleanup == nil || cfg.AcknowledgeClosure == nil ||
		!identifier.MatchString(cfg.Enrollment.OriginRef) || !identifier.MatchString(cfg.Enrollment.EngineIncarnation) || !identifier.MatchString(cfg.Enrollment.QualificationRef) ||
		p.Profile != service.GatewayMiMoResponsesProfile || !identifier.MatchString(p.QualificationRef) || !qualifiedModel.MatchString(p.Model) || len(p.BaseURL) < 1 || len(p.BaseURL) > 2048 ||
		p.RequestBytes < 1 || p.RequestBytes > 4<<20 || p.OutputBytes < 1 || p.OutputBytes > 8<<20 || p.Tokens < 1 || p.Tokens > 10000000 ||
		p.ProviderTokenUpperBound < p.Tokens || p.ProviderTokenUpperBound > 10000000 ||
		cfg.MaxEntries < 1 || cfg.MaxEntries > 10000 || cfg.EnvelopeBytes < 1 || cfg.EnvelopeBytes > 5<<20 || cfg.CallbackBytes < 1 || cfg.CallbackBytes > 262144 ||
		cfg.CallbackTimeout <= 0 || cfg.CallbackTimeout > 30*time.Second || cfg.IOTimeout <= 0 || cfg.IOTimeout > 30*time.Second ||
		cfg.CleanupTimeout <= 0 || cfg.CleanupTimeout > 30*time.Second || len(cfg.CallbackCredential) < 1 || len(cfg.CallbackCredential) > 2048 || !bearerToken.MatchString(cfg.CallbackCredential) {
		return nil, errDenied
	}
	endpoint, err := url.Parse(p.BaseURL)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return nil, errDenied
	}
	enrollmentCtx, stop := context.WithTimeout(ctx, cfg.CallbackTimeout)
	defer stop()
	if cfg.VerifyEnrollment(enrollmentCtx, cfg.Enrollment) != nil || enrollmentCtx.Err() != nil {
		return nil, errDenied
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, MaxResponseHeaderBytes: 16384,
		DialContext: (&net.Dialer{Timeout: cfg.CallbackTimeout}).DialContext, TLSHandshakeTimeout: cfg.CallbackTimeout, ResponseHeaderTimeout: cfg.CallbackTimeout}
	return &Handler{cfg: cfg, entries: make(map[transportKey]*reservation), requests: make(map[requestKey]transportKey), callback: &http.Client{Transport: transport, Timeout: cfg.CallbackTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

// Reserve before callback/claim. The secondary request identity prevents a new
// generation or nonce from rearming a duplicate while any evidence is retained.
// Only durably acknowledged CLOSED receipts are eligible for bounded eviction.
func (h *Handler) reserve(consumer string, input Request, ctx context.Context, cancel context.CancelFunc, interrupt func()) (*reservation, bool, error) {
	key := requestKey{consumer, input.Admission.ExecutionRef, input.RequestRef}
	digest := sha256.Sum256(input.Payload)
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.stopping {
		return nil, false, errDenied
	}
	if full, exists := h.requests[key]; exists {
		existing := h.entries[full]
		if existing == nil {
			return nil, false, errDenied
		}
		if existing.request.Admission != input.Admission || existing.request.Worker != input.Worker ||
			!service.SameGatewayNativeDescriptor(existing.request.Descriptor, input.Descriptor) || existing.digest != digest {
			return nil, false, errDenied
		}
		return existing, false, nil
	}
	if len(h.entries) >= h.cfg.MaxEntries {
		for k, e := range h.entries {
			if e.acknowledged && closed(e.life.Snapshot()) {
				delete(h.entries, k)
				delete(h.requests, k.requestKey)
				break
			}
		}
	}
	if len(h.entries) >= h.cfg.MaxEntries {
		return nil, false, errDenied
	}
	nonce, err := uuid.NewRandom()
	if err != nil {
		return nil, false, errDenied
	}
	life, err := service.NewGatewayNativeLifetime(ctx, cancel, interrupt, input.Admission.Limits.OutputBytes)
	if err != nil {
		return nil, false, errDenied
	}
	life.BindAccount(consumer, input.Admission.AccountRef, input.Descriptor.Generation)
	input.Payload = nil
	e := &reservation{request: input, digest: digest, life: life, effect: "effect_unknown", native: NativeBinding{h.cfg.Enrollment.OriginRef, h.cfg.Enrollment.EngineIncarnation, nonce.String(), input.Descriptor.Generation}}
	full := transportKey{key, e.native}
	h.entries[full] = e
	h.requests[key] = full
	return e, true, nil
}

func closed(s service.GatewayNativeLifetimeSnapshot) bool {
	return s.ContextDone && s.ForwardingReturned && s.BodyKnown && s.BodyClosed && !s.CloseFailed
}
func (h *Handler) receipt(consumer string, e *reservation) Receipt {
	h.mu.Lock()
	r := Receipt{ConsumerID: consumer, ExecutionRef: e.request.Admission.ExecutionRef, RequestRef: e.request.RequestRef, Native: e.native, Phase: "reserved", Effect: e.effect, Sealed: e.sealed, Acknowledged: e.acknowledged}
	if e.proof != nil {
		p := *e.proof
		r.Proof = &p
	}
	if e.status != nil {
		status := *e.status
		r.Status = &status
	}
	if e.admitted {
		r.Phase = "admitted"
	}
	h.mu.Unlock()
	r.Lifetime = e.life.Snapshot()
	r.Sealed = r.Sealed || r.Lifetime.Sealed
	if r.Lifetime.Entered {
		r.Phase = "entered"
	}
	if r.Lifetime.Completed {
		r.Effect = "completed"
	}
	if closed(r.Lifetime) {
		r.Phase = "closed"
	}
	return r
}

func (h *Handler) seal(e *reservation) {
	h.mu.Lock()
	e.sealed = true
	h.mu.Unlock()
	e.life.Cancel()
}

func (h *Handler) admit(ctx context.Context, consumer string, e *reservation) (bool, error) {
	h.mu.Lock()
	if e.callbackStarted {
		h.mu.Unlock()
		return false, nil
	}
	if e.sealed || ctx.Err() != nil {
		h.mu.Unlock()
		return false, errDenied
	}
	e.callbackStarted = true
	h.mu.Unlock()
	input := admitRequest{consumer, e.request.RequestRef, e.request.Worker, e.request.Admission, e.request.Descriptor, e.native}
	body, err := json.Marshal(input)
	if err != nil {
		return false, errDenied
	}
	callbackCtx, cancel := context.WithTimeout(ctx, h.cfg.CallbackTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(callbackCtx, http.MethodPost, strings.TrimSuffix(h.cfg.CallbackOrigin, "/")+"/private/native/v1/admit", strings.NewReader(string(body)))
	if err != nil {
		return false, errDenied
	}
	req.Header.Set("Authorization", "Bearer "+h.cfg.CallbackCredential)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	// There is one POST, no redirect, no automatic retry and no caller URL.
	resp, err := h.callback.Do(req)
	if err != nil {
		return false, errDenied
	}
	// Callback body cleanup is best effort; it does not attest provider closure.
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK || strings.Split(resp.Header.Get("Content-Type"), ";")[0] != "application/json" {
		return false, errDenied
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, h.cfg.CallbackBytes+1))
	if err != nil || int64(len(data)) > h.cfg.CallbackBytes {
		return false, errDenied
	}
	var reply admitReply
	if strictJSON(data, &reply) != nil || reply.ConsumerID != consumer || reply.Admission != e.request.Admission || reply.Status.RequestRef != e.request.RequestRef || reply.Status.Code != "" && !identifier.MatchString(reply.Status.Code) {
		return false, errDenied
	}
	switch reply.Status.Effect {
	case "not_dispatched", "dispatch_started", "response_started", "completed", "effect_unknown", "rejected_before_dispatch":
	default:
		return false, errDenied
	}
	h.mu.Lock()
	status := reply.Status
	e.status = &status
	h.mu.Unlock()
	if reply.Dispatch == nil {
		// Authenticated readback is never another permission, even if it says started.
		if reply.NativeDescriptor != nil || reply.LeaseExpiresAt != "" {
			return false, errDenied
		}
		return false, nil
	}
	d := reply.Dispatch
	p := d.Closure
	lease, err := parseInstant(reply.LeaseExpiresAt)
	deadline, _ := parseInstant(e.request.Admission.ExpiresAt)
	if err != nil || !lease.After(time.Now()) || !deadline.After(time.Now()) || !p.valid() ||
		reply.Status.Effect != "dispatch_started" || reply.NativeDescriptor == nil || !service.SameGatewayNativeDescriptor(*reply.NativeDescriptor, e.request.Descriptor) ||
		d.ExecutionRef != e.request.Admission.ExecutionRef || d.RequestRef != e.request.RequestRef || d.Limits != e.request.Admission.Limits || d.Deadline != e.request.Admission.ExpiresAt ||
		d.Descriptor.Generation != e.native.Generation || d.Descriptor.NativePhysicalIdentity != e.native.Generation || d.Descriptor.Profile != e.request.Admission.ProfileID ||
		p.ExecutionRef != d.ExecutionRef || p.RequestRef != d.RequestRef || p.Worker != e.request.Worker || p.Native != e.native ||
		h.cfg.VerifyDispatch(callbackCtx, consumer, p, lease) != nil || callbackCtx.Err() != nil {
		return false, errDenied
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	// The cancellation latch is permanent, including delayed/lost callback ACK.
	if e.sealed || ctx.Err() != nil || callbackCtx.Err() != nil || !lease.After(time.Now()) || !deadline.After(time.Now()) || !e.life.Admit(lease) {
		return false, errDenied
	}
	e.proof = &p
	e.admitted = true
	return true, nil
}

func (h *Handler) cleanup(ctx context.Context, consumer, action string, input cleanupRequest) (Receipt, error) {
	p := input.Proof
	lease, err := parseInstant(input.Cleanup.LeaseExpiresAt)
	if err != nil || !lease.After(time.Now()) || !p.valid() || !canonicalUUID.MatchString(input.Cleanup.CleanupRef) ||
		!canonicalUUID.MatchString(input.Cleanup.Worker) || !identifier.MatchString(input.Cleanup.Token) {
		return Receipt{}, errDenied
	}
	cleanupCtx, cancel := context.WithTimeout(ctx, h.cfg.CleanupTimeout)
	defer cancel()
	if h.cfg.AuthorizeCleanup(cleanupCtx, consumer, p, input.Cleanup) != nil || cleanupCtx.Err() != nil || !lease.After(time.Now()) {
		return Receipt{}, errDenied
	}
	key := transportKey{requestKey{consumer, p.ExecutionRef, p.RequestRef}, p.Native}
	h.mu.Lock()
	e := h.entries[key]
	if cleanupCtx.Err() != nil || !lease.After(time.Now()) || e == nil || e.native != p.Native || e.request.Worker != p.Worker || (e.proof != nil && *e.proof != p) {
		h.mu.Unlock()
		return Receipt{}, errDenied
	}
	if action == "cancel" || e.life.Snapshot().Sealed {
		e.sealed = true
	}
	if e.proof == nil {
		// SQL cleanup may recover the ORIGINAL lost-ACK proof, but only on a sealed
		// reservation. Attaching it never changes admitted/entered or the latch.
		if !e.sealed {
			h.mu.Unlock()
			return Receipt{}, errDenied
		}
		copy := p
		e.proof = &copy
	}
	h.mu.Unlock()
	if action == "cancel" {
		h.seal(e)
	}
	r := h.receipt(consumer, e)
	if action == "ack" {
		if r.Phase != "closed" || !lease.After(time.Now()) || h.cfg.AcknowledgeClosure(cleanupCtx, consumer, p, input.Cleanup, r) != nil || cleanupCtx.Err() != nil || !lease.After(time.Now()) {
			return Receipt{}, errDenied
		}
		h.mu.Lock()
		e.acknowledged = true
		h.mu.Unlock()
		r = h.receipt(consumer, e)
	}
	return r, nil
}
