package logger

import (
	"bytes"
	"os"
	"path/filepath"
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

// TestEventLoggerFile tests that logs are also written to a file when enabled.
func TestEventLoggerFile(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")

	var buf bytes.Buffer
	l := New(&buf)

	if err := l.EnableFileLogging(logPath); err != nil {
		t.Fatalf("Failed to enable file logging: %v", err)
	}
	defer l.Close()

	l.Log("TEST", "file logging test message")

	if !strings.Contains(buf.String(), "file logging test message") {
		t.Error("Expected log entry in buffer")
	}

	fileContent, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}
	if !strings.Contains(string(fileContent), "file logging test message") {
		t.Error("Expected log entry in file")
	}
}
