//go:build linux

package main

import (
	"io"
	"os"
	"strings"
	"testing"
)

// Regression: the standard flag parser must not echo unknown argv values into
// supervisor diagnostics. Observe actual stderr, with no child or account use.
func TestParseErrorDoesNotEchoArguments(t *testing.T) {
	t.Log("Regression: invalid supervisor argv cannot disclose a synthetic secret marker")
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	original := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = original; w.Close() }()
	marker := "SYNTHETIC-ARGV-DO-NOT-PRINT"
	code := run([]string{"-unknown=" + marker})
	w.Close()
	output, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if code != 2 || strings.Contains(string(output), marker) || string(output) != "launcher: invalid supervisor configuration\n" {
		t.Fatal("argv diagnostic was not safe and bounded")
	}
}
