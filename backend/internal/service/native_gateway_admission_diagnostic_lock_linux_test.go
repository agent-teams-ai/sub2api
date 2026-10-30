//go:build unit && linux

package service

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

type admissionDiagnosticLockRepo struct {
	gatewayIdentityRepoFixture
	mu       sync.Mutex
	acquired chan struct{}
}

func (r *admissionDiagnosticLockRepo) LockGatewayNativeAccount(context.Context, int64) (*Account, func(), error) {
	r.mu.Lock()
	close(r.acquired)
	return r.row, r.mu.Unlock, nil
}

// A stalled private diagnostic consumer must not retain the credential row lock
// after the final catalogue fence has already refused dispatch.
func TestGatewayNativeAdmissionDiagnosticReleasesCatalogLockBeforeBlockedStderr(t *testing.T) {
	account := nativeReviewStreamAccount(t, GatewayOpenRouterBaseURL, GatewayOpenRouterResponsesProfile)
	account.Extra[GatewayModelExtraKey] = "birth/anchor"
	route, err := GatewayNativeDescriptor(account)
	require.NoError(t, err)
	repo := &admissionDiagnosticLockRepo{gatewayIdentityRepoFixture: gatewayIdentityRepoFixture{row: account}, acquired: make(chan struct{})}
	gateway := &OpenAIGatewayService{accountRepo: repo}
	raw := `{"data":[]}`
	require.NoError(t, gateway.SetGatewayOpenRouterModels(openRouterModelsFixture(t, &raw)))
	state := &gatewayNativeDispatch{route: route, account: account, scope: nativeFixtureScope(account), custody: nativeFixtureCustody(t), requestedModel: "withdrawn/model"}
	ctx := context.WithValue(nativeFixtureContext(t, context.Background()), gatewayNativeContextKey{}, state)
	target, err := gateway.gatewayNativeTargetURL(account)
	require.NoError(t, err)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewBufferString(`{"model":"withdrawn/model","input":"text"}`))
	require.NoError(t, err)
	request.Header.Set("Authorization", "Bearer "+account.GetCredential("api_key"))

	reader, writer, err := os.Pipe()
	require.NoError(t, err)
	t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
	fd := int(writer.Fd())
	require.NoError(t, unix.SetNonblock(fd, true))
	// Fill the actual OS pipe to EAGAIN without relying on its capacity or sleeps.
	block := make([]byte, 4096)
	for len(block) > 0 {
		_, err = unix.Write(fd, block)
		if err == unix.EINTR {
			continue
		}
		if err == unix.EAGAIN {
			if len(block) == 1 {
				break
			}
			block = block[:1]
			continue
		}
		require.NoError(t, err)
	}
	require.NoError(t, unix.SetNonblock(fd, false))
	original := os.Stderr
	os.Stderr = writer
	finished := make(chan struct{})
	var dispatchErr error
	var drainOnce sync.Once
	unblock := func() { drainOnce.Do(func() { go func() { _, _ = io.Copy(io.Discard, reader) }() }) }
	defer func() {
		os.Stderr = original
		unblock()
		select {
		case <-finished:
		case <-time.After(5 * time.Second):
			t.Error("dispatch did not finish after stderr was drained")
		}
	}()
	go func() {
		defer close(finished)
		release, err := gateway.checkGatewayNativeDispatch(request, account)
		release()
		dispatchErr = err
	}()
	select {
	case <-repo.acquired:
	case <-time.After(5 * time.Second):
		t.Fatal("dispatch did not reach the credential row lock")
	}
	available := make(chan struct{})
	go func() { repo.mu.Lock(); repo.mu.Unlock(); close(available) }()
	select {
	case <-available:
	case <-time.After(5 * time.Second):
		t.Fatal("blocked stderr retained the refused dispatch's credential row lock")
	}
	select {
	case <-finished:
		t.Fatal("diagnostic unexpectedly completed while stderr was full")
	default:
	}
	unblock()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("dispatch did not finish after stderr was drained")
	}
	require.ErrorIs(t, dispatchErr, ErrGatewayNativeIdentity)
	require.False(t, state.entered.Load())
}
