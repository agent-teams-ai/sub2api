//go:build linux

package gatewaybootstrap

import (
	"net"
	"sync"
)

// Keep transport ownership separate from live inference admission. Incomplete
// headers and a finite refusal burst can still reach the handler's positive
// 503 response. Header deadlines bound that headroom; the private control
// listener has its own independent 128-socket budget.
func publicSocketBudget(active int64) int { return 2*int(active) + 128 }

type boundedListener struct {
	net.Listener
	slots chan struct{}
}
type boundedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (l *boundedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
			return &boundedConn{Conn: conn, release: func() { <-l.slots }}, nil
		default:
			_ = conn.Close()
		}
	}
}
func (c *boundedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
