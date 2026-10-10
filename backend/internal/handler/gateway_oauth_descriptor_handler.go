package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

// OAuthDescriptorPath is the existing Gateway private wire path. The handler is
// intentionally not registered on any router until authority adapters exist.
const OAuthDescriptorPath = "/private/native/v1/oauth/connect/descriptor"

const oauthDescriptorBodyLimit = 16 << 10

type oauthDescriptorDescriber interface {
	Describe(ctx context.Context, scope service.OAuthDescriptorScope) (service.OAuthVerifiedBirth, error)
}

// OAuthDescriptorPrincipal returns the authenticated consumer and owner of the
// request. It must come from verified authentication, never from the body.
type OAuthDescriptorPrincipal func(c *gin.Context) (consumerID, ownerRef string, ok bool)

type OAuthDescriptorHandler struct {
	service   oauthDescriptorDescriber
	principal OAuthDescriptorPrincipal
}

func NewOAuthDescriptorHandler(svc *service.OAuthDescriptorService, principal OAuthDescriptorPrincipal) *OAuthDescriptorHandler {
	if svc == nil || principal == nil {
		panic("oauth descriptor handler requires service and principal")
	}
	return &OAuthDescriptorHandler{service: svc, principal: principal}
}

type oauthDescriptorNative struct {
	AccountID  int64  `json:"account_id"`
	Generation string `json:"generation"`
	CreatedAt  string `json:"created_at"`
	Profile    string `json:"profile"`
	BaseURL    string `json:"base_url"`
	Model      string `json:"model"`
}

type oauthDescriptorResponse struct {
	Operation     string                `json:"operation"`
	AccountRef    string                `json:"account_ref"`
	State         string                `json:"state"`
	Qualification string                `json:"qualification"`
	Native        oauthDescriptorNative `json:"native"`
}

var oauthDescriptorWireKeys = map[string]bool{"operation": true, "owner_ref": true, "account_ref": true, "generation": true}

// decodeOAuthDescriptorBody accepts exactly one flat object of the four known
// string members, with no duplicates, unknown members or trailing JSON.
func decodeOAuthDescriptorBody(r io.Reader) (map[string]string, bool) {
	dec := json.NewDecoder(r)
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, false
	}
	out := make(map[string]string, 4)
	for dec.More() {
		keyTok, err := dec.Token()
		key, isString := keyTok.(string)
		if err != nil || !isString || !oauthDescriptorWireKeys[key] {
			return nil, false
		}
		if _, dup := out[key]; dup {
			return nil, false
		}
		valTok, err := dec.Token()
		val, isString := valTok.(string)
		if err != nil || !isString {
			return nil, false
		}
		out[key] = val
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, false
	}
	return out, len(out) == len(oauthDescriptorWireKeys)
}

func oauthDescriptorError(c *gin.Context, status int, category string) {
	c.Header("Cache-Control", "no-store")
	c.JSON(status, gin.H{"error": category})
}

// Describe serves POST /private/native/v1/oauth/connect/descriptor.
func (h *OAuthDescriptorHandler) Describe(c *gin.Context) {
	if c.Request.Method != http.MethodPost {
		oauthDescriptorError(c, http.StatusMethodNotAllowed, "invalid_request")
		return
	}
	consumerID, authOwner, ok := h.principal(c)
	if !ok || consumerID == "" || authOwner == "" {
		oauthDescriptorError(c, http.StatusUnauthorized, "unauthenticated")
		return
	}
	if c.ContentType() != "application/json" {
		oauthDescriptorError(c, http.StatusBadRequest, "invalid_request")
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, oauthDescriptorBodyLimit))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			oauthDescriptorError(c, http.StatusRequestEntityTooLarge, "too_large")
			return
		}
		oauthDescriptorError(c, http.StatusBadRequest, "invalid_request")
		return
	}
	fields, ok := decodeOAuthDescriptorBody(bytes.NewReader(raw))
	if !ok {
		oauthDescriptorError(c, http.StatusBadRequest, "invalid_request")
		return
	}
	if fields["owner_ref"] != authOwner {
		oauthDescriptorError(c, http.StatusForbidden, "denied")
		return
	}
	birth, err := h.service.Describe(c.Request.Context(), service.OAuthDescriptorScope{
		ConsumerID: consumerID, OwnerRef: authOwner, OperationID: fields["operation"],
		AccountRef: fields["account_ref"], Generation: fields["generation"],
	})
	if err != nil {
		switch {
		case errors.Is(err, service.ErrOAuthDescriptorInvalid):
			oauthDescriptorError(c, http.StatusBadRequest, "invalid_request")
		case errors.Is(err, service.ErrOAuthDescriptorDenied), errors.Is(err, service.ErrOAuthDescriptorExpired),
			errors.Is(err, service.ErrOAuthDescriptorRevoked):
			oauthDescriptorError(c, http.StatusForbidden, "denied")
		case errors.Is(err, service.ErrOAuthDescriptorUnqualified):
			oauthDescriptorError(c, http.StatusConflict, "not_qualified")
		default:
			oauthDescriptorError(c, http.StatusServiceUnavailable, "unavailable")
		}
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, oauthDescriptorResponse{
		Operation: birth.Scope.OperationID, AccountRef: birth.Scope.AccountRef,
		State: "staged", Qualification: "controlled-source-v1",
		Native: oauthDescriptorNative{AccountID: birth.AccountID, Generation: birth.Scope.Generation,
			CreatedAt: birth.CreatedAt, Profile: birth.Profile, BaseURL: birth.BaseURL, Model: birth.Model},
	})
}
