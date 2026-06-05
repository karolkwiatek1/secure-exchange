package logger

import (
	"bytes"
	"strings"
	"testing"
)

// TestEventLogger tests thread-safe logging with timestamps.
func TestEventLogger(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)

	l.Log("TTP_SERVER", "Initialized successfully")
	l.Log("USER_A", "Requested certificate")

	output := buf.String()

	if !strings.Contains(output, "TTP_SERVER: Initialized successfully") {
		t.Error("Expected first log entry not found")
	}
	if !strings.Contains(output, "USER_A: Requested certificate") {
		t.Error("Expected second log entry not found")
	}
	if !strings.Contains(output, "[202") { // Basic timestamp check
		t.Error("Expected timestamp in log entry")
	}
}
