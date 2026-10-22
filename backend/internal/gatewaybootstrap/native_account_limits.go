package gatewaybootstrap

import (
	"context"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

// Separate purpose from connect, refresh, custody and inference authorization.
// The facade resolves the current physical route after owner+epoch validation.
type NativeAccountLimitsAuthority interface {
	AuthorizeNativeAccountLimits(context.Context, string, service.GatewayAccountLimitsInput) (service.GatewayNativeRoute, error)
}

func (a *authority) AuthorizeNativeAccountLimits(ctx context.Context, consumer string, in service.GatewayAccountLimitsInput) (service.GatewayNativeRoute, error) {
	var empty service.GatewayNativeRoute
	if !identifier.MatchString(consumer) || !in.Valid() {
		return empty, ErrDenied
	}
	body := struct {
		ConsumerID string `json:"consumerId"`
		service.GatewayAccountLimitsInput
	}{consumer, in}
	// The existing strict decoder rejects duplicate/alias/extra fields and
	// unsafe integer tokens. Time stays a string until this boundary validates it.
	var reply struct {
		OK     bool `json:"ok"`
		Native struct {
			AccountID  int64  `json:"account_id"`
			Generation string `json:"generation"`
			CreatedAt  string `json:"created_at"`
			Profile    string `json:"profile"`
			BaseURL    string `json:"base_url"`
			Model      string `json:"model"`
		} `json:"native"`
	}
	if a.postReplyDecoded(ctx, "/private/native/v1/account-limits-authority", body, &reply, 2048, decodeStrict) != nil || !reply.OK {
		return empty, ErrDenied
	}
	birth, err := time.Parse(time.RFC3339Nano, reply.Native.CreatedAt)
	if err != nil || birth.IsZero() || birth.Nanosecond()%1000 != 0 || reply.Native.AccountID <= 0 || reply.Native.Profile != in.ProfileID {
		return empty, ErrDenied
	}
	return service.GatewayNativeRoute{AccountID: reply.Native.AccountID, Generation: reply.Native.Generation, CreatedAt: birth, Profile: reply.Native.Profile, BaseURL: reply.Native.BaseURL, Model: reply.Native.Model}, nil
}
