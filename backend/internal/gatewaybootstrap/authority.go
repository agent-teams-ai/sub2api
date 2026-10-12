package gatewaybootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/gatewaytransport"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

// One configured authority, fixed paths, no retry/redirect/environment proxy.
// Fixture transport is an explicit outer-composition seam, never FD config.
type authority struct {
	origin, credential string
	client             *http.Client
}

func newAuthority(c AuthorityConfig, fixture *http.Transport) (*authority, error) {
	if !fixedOrigin(c.Origin) || !bearer.MatchString(c.Credential) || len(c.Credential) > 2048 {
		return nil, ErrDenied
	}
	transport := &http.Transport{DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second}
	if fixture != nil {
		transport = fixture.Clone()
	}
	transport.Proxy = nil
	transport.DisableKeepAlives = true
	transport.MaxResponseHeaderBytes = 16384
	return &authority{strings.TrimSuffix(c.Origin, "/"), c.Credential, &http.Client{Transport: transport, Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (a *authority) post(ctx context.Context, path string, body any) error {
	var ack struct {
		OK bool `json:"ok"`
	}
	if a.postReply(ctx, path, body, &ack) != nil || !ack.OK {
		return ErrDenied
	}
	return nil
}

// Owner lookup shares the fixed transport bounds, but has its own exact reply.
func (a *authority) postReply(ctx context.Context, path string, body, reply any) error {
	return a.postReplyDecoded(ctx, path, body, reply, 1024, decodeStrict)
}
func (a *authority) postReplyDecoded(ctx context.Context, path string, body, reply any, limit int64, decode func([]byte, any) error) error {
	raw, err := json.Marshal(body)
	if err != nil || len(raw) > 262144 {
		return ErrDenied
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(bounded, http.MethodPost, a.origin+path, bytes.NewReader(raw))
	if err != nil {
		return ErrDenied
	}
	req.GetBody = nil
	req.Header.Set("Authorization", "Bearer "+a.credential)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		return ErrDenied
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK || len(resp.Header.Values("Content-Type")) != 1 || resp.Header.Get("Content-Type") != "application/json" || len(resp.Header) > 64 {
		return ErrDenied
	}
	headerCount := 0
	for _, values := range resp.Header {
		headerCount += len(values)
	}
	if headerCount > 64 {
		return ErrDenied
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil || int64(len(data)) > limit || decode(data, reply) != nil || bounded.Err() != nil {
		return ErrDenied
	}
	return nil
}

type oauthOwnerBody struct {
	ConsumerID  string `json:"consumerId"`
	OperationID string `json:"operationId"`
	AccountRef  string `json:"accountRef"`
	Generation  string `json:"generation"`
}

func (a *authority) AuthorizeNativeOAuthOwner(ctx context.Context, consumer, operation, account, generation string) (string, error) {
	if !identifier.MatchString(consumer) || !service.GatewayNativeCredentialRefValid(operation) ||
		!service.GatewayNativeCredentialRefValid(account) || !incarnation.MatchString(generation) {
		return "", ErrDenied
	}
	var reply struct {
		OK       bool   `json:"ok"`
		OwnerRef string `json:"ownerRef"`
	}
	if a.postReply(ctx, "/private/native/v1/oauth-owner-authority", oauthOwnerBody{consumer, operation, account, generation}, &reply) != nil ||
		!reply.OK || !service.GatewayNativeCredentialRefValid(reply.OwnerRef) {
		return "", ErrDenied
	}
	return reply.OwnerRef, nil
}

// Refresh uses active-generation owner authority, separate from staging connect
// authority and the shared ACK protocol. Origin/credential/bounds stay fixed.
func (a *authority) AuthorizeNativeOAuthRefreshOwner(ctx context.Context, consumer, operation, account, generation string) (string, error) {
	if !identifier.MatchString(consumer) || !service.GatewayNativeCredentialRefValid(operation) ||
		!service.GatewayNativeCredentialRefValid(account) || !incarnation.MatchString(generation) {
		return "", ErrDenied
	}
	var reply struct {
		OK       bool   `json:"ok"`
		OwnerRef string `json:"ownerRef"`
	}
	if a.postReply(ctx, "/private/native/v1/oauth-refresh-authority", oauthOwnerBody{consumer, operation, account, generation}, &reply) != nil ||
		!reply.OK || !service.GatewayNativeCredentialRefValid(reply.OwnerRef) {
		return "", ErrDenied
	}
	return reply.OwnerRef, nil
}

type enrollmentBody struct {
	OriginRef         string `json:"originRef"`
	EngineIncarnation string `json:"engineIncarnation"`
	QualificationRef  string `json:"qualificationRef"`
}
type dispatchBody struct {
	ConsumerID     string                 `json:"consumerId"`
	Proof          gatewaytransport.Proof `json:"proof"`
	LeaseExpiresAt string                 `json:"leaseExpiresAt"`
}
type cleanupBody struct {
	ConsumerID string                        `json:"consumerId"`
	Proof      gatewaytransport.Proof        `json:"proof"`
	Cleanup    gatewaytransport.CleanupLease `json:"cleanup"`
}
type ownerBody struct {
	ConsumerID string                 `json:"consumerId"`
	Proof      gatewaytransport.Proof `json:"proof"`
}
type delegatedAckBody struct {
	ConsumerID string                        `json:"consumerId"`
	Proof      gatewaytransport.Proof        `json:"proof"`
	Cleanup    gatewaytransport.CleanupLease `json:"cleanup"`
	Receipt    gatewaytransport.Receipt      `json:"receipt"`
}
type ownerAckBody struct {
	ConsumerID string                   `json:"consumerId"`
	Proof      gatewaytransport.Proof   `json:"proof"`
	Receipt    gatewaytransport.Receipt `json:"receipt"`
}

func (a *authority) compose(c *gatewaytransport.Config) {
	c.CallbackOrigin, c.CallbackCredential = a.origin, a.credential
	c.VerifyEnrollment = func(ctx context.Context, e gatewaytransport.Enrollment) error {
		return a.post(ctx, "/private/native/v1/enrollment", enrollmentBody{e.OriginRef, e.EngineIncarnation, e.QualificationRef})
	}
	c.VerifyDispatch = func(ctx context.Context, consumer string, p gatewaytransport.Proof, lease time.Time) error {
		return a.post(ctx, "/private/native/v1/dispatch-proof", dispatchBody{consumer, p, lease.Format(time.RFC3339Nano)})
	}
	c.AuthorizeCleanup = func(ctx context.Context, consumer string, p gatewaytransport.Proof, lease gatewaytransport.CleanupLease) error {
		return a.post(ctx, "/private/native/v1/cleanup-authority", cleanupBody{consumer, p, lease})
	}
	c.AuthorizeOwnerClosure = func(ctx context.Context, consumer string, p gatewaytransport.Proof) error {
		return a.post(ctx, "/private/native/v1/owner-closure-authority", ownerBody{consumer, p})
	}
	c.AcknowledgeClosure = func(ctx context.Context, consumer string, p gatewaytransport.Proof, lease gatewaytransport.CleanupLease, receipt gatewaytransport.Receipt) error {
		return a.post(ctx, "/private/native/v1/closure-ack", delegatedAckBody{consumer, p, lease, receipt})
	}
	c.AcknowledgeOwnerClosure = func(ctx context.Context, consumer string, p gatewaytransport.Proof, receipt gatewaytransport.Receipt) error {
		return a.post(ctx, "/private/native/v1/closure-ack", ownerAckBody{consumer, p, receipt})
	}
}

func (a *authority) AuthorizeNativeOAuthCleanup(ctx context.Context, in service.GatewayNativeOAuthCleanupRequest) (service.GatewayNativeOAuthCleanupAuthority, error) {
	if !service.GatewayNativeOAuthCleanupRequestValid(in) || !identifier.MatchString(in.Scope.Consumer) {
		return service.GatewayNativeOAuthCleanupAuthority{}, ErrDenied
	}
	body := struct {
		ConsumerID   string `json:"consumerId"`
		OperationID  string `json:"operationId"`
		AccountRef   string `json:"accountRef"`
		Generation   string `json:"generation"`
		CleanupRef   string `json:"cleanupRef"`
		CleanupToken string `json:"cleanupToken"`
		Action       string `json:"action"`
	}{in.Scope.Consumer, in.Operation, in.Scope.Account, in.Scope.Generation, in.CleanupRef, in.CleanupToken, in.Action}
	var reply oauthCleanupReply
	if a.postReplyDecoded(ctx, "/private/native/v1/oauth-cleanup-authority", body, &reply, 2048, decodeOAuthCleanupReply) != nil || !reply.OK || reply.OwnerRef != in.Scope.Owner {
		return service.GatewayNativeOAuthCleanupAuthority{}, ErrDenied
	}
	lease, err := time.Parse(time.RFC3339Nano, reply.LeaseExpiresAt)
	if err != nil || !time.Now().Before(lease) {
		return service.GatewayNativeOAuthCleanupAuthority{}, ErrDenied
	}
	if reply.Native != nil {
		n := reply.Native
		if n.AccountID <= 0 || n.Generation != in.Scope.Generation || n.CreatedAt.IsZero() || n.CreatedAt.Nanosecond()%1000 != 0 || n.Profile != service.GatewayCodexOAuthResponsesProfile || n.BaseURL != service.GatewayCodexOAuthBaseURL || n.Model != service.GatewayCodexOAuthModel {
			return service.GatewayNativeOAuthCleanupAuthority{}, ErrDenied
		}
	}
	return service.GatewayNativeOAuthCleanupAuthority{Owner: reply.OwnerRef, LeaseExpiresAt: lease, Native: reply.Native}, nil
}

type oauthCleanupReply struct {
	OK                       bool
	OwnerRef, LeaseExpiresAt string
	Native                   *service.GatewayNativeRoute
}

// This reply's optional descriptor has a timestamp string on the wire. Keep
// the existing strict config decoder intact and validate the finite cleanup
// shape explicitly, including decoded duplicate/alias rejection.
func decodeOAuthCleanupReply(data []byte, target any) error {
	reply, ok := target.(*oauthCleanupReply)
	if !ok || !json.Valid(data) {
		return ErrDenied
	}
	d := json.NewDecoder(bytes.NewReader(data))
	tok, err := d.Token()
	if err != nil || tok != json.Delim('{') {
		return ErrDenied
	}
	fields := map[string]json.RawMessage{}
	for d.More() {
		tok, err = d.Token()
		name, ok := tok.(string)
		if err != nil || !ok {
			return ErrDenied
		}
		if _, exists := fields[name]; exists {
			return ErrDenied
		}
		switch name {
		case "ok", "ownerRef", "leaseExpiresAt", "native":
		default:
			return ErrDenied
		}
		var raw json.RawMessage
		if d.Decode(&raw) != nil {
			return ErrDenied
		}
		fields[name] = raw
	}
	tok, err = d.Token()
	if err != nil || tok != json.Delim('}') {
		return ErrDenied
	}
	if _, err = d.Token(); err != io.EOF {
		return ErrDenied
	}
	native, hasNative := fields["native"]
	delete(fields, "native")
	raw, err := json.Marshal(fields)
	if err != nil {
		return ErrDenied
	}
	var scope struct {
		OK             bool   `json:"ok"`
		OwnerRef       string `json:"ownerRef"`
		LeaseExpiresAt string `json:"leaseExpiresAt"`
	}
	if decodeStrict(raw, &scope) != nil {
		return ErrDenied
	}
	reply.OK, reply.OwnerRef, reply.LeaseExpiresAt = scope.OK, scope.OwnerRef, scope.LeaseExpiresAt
	if hasNative {
		var descriptor struct {
			AccountID  int64  `json:"account_id"`
			Generation string `json:"generation"`
			CreatedAt  string `json:"created_at"`
			Profile    string `json:"profile"`
			BaseURL    string `json:"base_url"`
			Model      string `json:"model"`
		}
		if decodeStrict(native, &descriptor) != nil {
			return ErrDenied
		}
		birth, err := time.Parse(time.RFC3339Nano, descriptor.CreatedAt)
		if err != nil {
			return ErrDenied
		}
		reply.Native = &service.GatewayNativeRoute{AccountID: descriptor.AccountID, Generation: descriptor.Generation, CreatedAt: birth, Profile: descriptor.Profile, BaseURL: descriptor.BaseURL, Model: descriptor.Model}
	}
	return nil
}
