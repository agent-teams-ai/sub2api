package handler

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestUserMsgQueueHelperPingInterval(t *testing.T) {
	cases := []struct {
		name     string
		interval time.Duration
		stream   bool
		format   SSEPingFormat
		want     bool
	}{
		{name: "zero disables pings", interval: 0, stream: true, format: SSEPingFormatComment},
		{name: "positive enables pings", interval: time.Second, stream: true, format: SSEPingFormatComment, want: true},
		{name: "negative falls back to default", interval: -time.Second, stream: true, format: SSEPingFormatComment, want: true},
		{name: "non-streaming disables pings", interval: time.Second, stream: false, format: SSEPingFormatComment},
		{name: "empty format disables pings", interval: time.Second, stream: true, format: SSEPingFormatNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := NewUserMsgQueueHelper(nil, tc.format, tc.interval)
			require.Equal(t, tc.want, h.shouldPing(tc.stream))
			if tc.interval == 0 {
				require.Zero(t, h.pingInterval)
			}
			if tc.interval < 0 {
				require.Equal(t, defaultPingInterval, h.pingInterval)
			}
		})
	}
}
