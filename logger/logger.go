// Package logger provides thread-safe event logging with timestamps.
package logger

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// EventLogger handles thread-safe logging with timestamps.
type EventLogger struct {
	mu     sync.Mutex
	writer io.Writer
}

// New creates a new EventLogger writing to the specified output.
func New(w io.Writer) *EventLogger {
	if w == nil {
		w = os.Stdout
	}
	return &EventLogger{
		writer: w,
	}
}

// Log writes an event with a timestamp and action description.
func (l *EventLogger) Log(subject, action string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	timestamp := time.Now().Format(time.RFC3339)
	logEntry := fmt.Sprintf("[%s] %s: %s\n", timestamp, subject, action)

	_, _ = l.writer.Write([]byte(logEntry))
}
