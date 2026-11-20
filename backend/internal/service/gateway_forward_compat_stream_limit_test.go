//go:build unit

package service

import (
	"bufio"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAnthropicCompatStreamOverflowReportsEventLimitWithoutFalseLineSize(t *testing.T) {
	stream := &anthropicCompatStream{readErr: bufio.ErrTooLong, maxLineSize: 1 << 20}
	failure := stream.failure()
	require.NotNil(t, failure)
	require.Equal(t, "response_too_large", failure.errType)
	require.Equal(t, "upstream SSE event exceeded configured transport limits", failure.message)
	require.NotContains(t, failure.message, "1048576")
}
