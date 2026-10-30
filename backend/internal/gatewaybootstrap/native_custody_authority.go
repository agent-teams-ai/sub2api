package gatewaybootstrap

import "context"

// Optional purpose-specific capability. Older owner-authority implementations
// cannot authorize retained-custody reads through enrollment permissions.
type NativeOAuthCustodyAuthority interface {
	AuthorizeNativeOAuthCustodyOwner(ctx context.Context, consumer, operation, account, generation string) (string, error)
}
