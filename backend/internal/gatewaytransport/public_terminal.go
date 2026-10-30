package gatewaytransport

// Terminal SSE buffering and durable-settlement delivery.
import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
)

// Public clients can finish as soon as their terminal SSE event arrives. Hold
// that bounded frame until the provider effect, configured usage and physical
// closure are durable; preceding frames retain their exact original bytes.
type publicTerminalBudget struct {
	mu            sync.Mutex
	used, maximum int
}

func (b *publicTerminalBudget) reserve(size int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if size < 0 || size > b.maximum-b.used {
		return false
	}
	b.used += size
	return true
}
func (b *publicTerminalBudget) release(size int) { b.mu.Lock(); defer b.mu.Unlock(); b.used -= size }

type publicTerminalWriter struct {
	budget   *publicTerminalBudget
	reserved int
	http.ResponseWriter
	pending, terminal []byte
	held, failed      bool
	maximum           int
}

func (w *publicTerminalWriter) dispose() {
	if w.reserved > 0 {
		w.budget.release(w.reserved)
		w.reserved = 0
	}
	w.pending = nil
	w.terminal = nil
}
func (w *publicTerminalWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *publicTerminalWriter) Write(data []byte) (int, error) {
	if strings.Split(w.Header().Get("Content-Type"), ";")[0] != "text/event-stream" {
		return w.ResponseWriter.Write(data)
	}
	if w.failed {
		return 0, errDenied
	}
	if w.held {
		if len(w.terminal)+len(data) > w.maximum || !w.budget.reserve(len(data)) {
			w.failed = true
			return 0, errDenied
		}
		w.reserved += len(data)
		w.terminal = append(w.terminal, data...)
		return len(data), nil
	}
	w.pending = append(w.pending, data...)
	for {
		end := publicSSEFrameEnd(w.pending)
		if end == 0 {
			if len(w.pending) > w.maximum {
				w.failed = true
				return 0, errDenied
			}
			return len(data), nil
		}
		frame := w.pending[:end]
		if end > w.maximum {
			w.failed = true
			return 0, errDenied
		}
		if publicTerminalFrame(frame) {
			if len(w.pending) > w.maximum {
				w.failed = true
				return 0, errDenied
			}
			if !w.budget.reserve(len(w.pending)) {
				w.failed = true
				return 0, errDenied
			}
			w.reserved += len(w.pending)
			w.terminal = bytes.Clone(w.pending)
			w.pending = nil
			w.held = true
			return len(data), nil
		}
		if _, err := w.ResponseWriter.Write(frame); err != nil {
			w.failed = true
			return 0, err
		}
		w.pending = w.pending[end:]
	}
}
func (w *publicTerminalWriter) Flush() { _ = w.FlushError() }
func (w *publicTerminalWriter) FlushError() error {
	return http.NewResponseController(w.ResponseWriter).Flush()
}
func (w *publicTerminalWriter) release() error {
	if w.failed || !w.held || len(w.pending) != 0 {
		return errDenied
	}
	if _, err := w.ResponseWriter.Write(w.terminal); err != nil {
		return err
	}
	w.terminal = nil
	return w.FlushError()
}
func publicSSEFrameEnd(raw []byte) int {
	start := 0
	for i, b := range raw {
		if b != '\n' {
			continue
		}
		line := bytes.TrimSuffix(raw[start:i], []byte{'\r'})
		if len(line) == 0 {
			return i + 1
		}
		start = i + 1
	}
	return 0
}
func publicTerminalFrame(frame []byte) bool {
	var data []byte
	for _, line := range bytes.Split(frame, []byte{'\n'}) {
		line = bytes.TrimSuffix(line, []byte{'\r'})
		if bytes.HasPrefix(line, []byte("data:")) {
			v := line[5:]
			v = bytes.TrimPrefix(v, []byte{' '})
			if len(data) > 0 {
				data = append(data, '\n')
			}
			data = append(data, v...)
		}
	}
	var event struct {
		Type string `json:"type"`
	}
	return json.Unmarshal(data, &event) == nil && (event.Type == "response.completed" || event.Type == "message_stop")
}
