// Package logger provides thread-safe event logging with timestamps.
package logger

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// EventLogger handles thread-safe logging with timestamps.
type EventLogger struct {
	mu       sync.Mutex
	writer   io.Writer
	file     *os.File
	buffer   []string
	bufLimit int
}

// New creates a new EventLogger writing to the specified output.
func New(w io.Writer) *EventLogger {
	if w == nil {
		w = os.Stdout
	}
	return &EventLogger{
		writer:   w,
		bufLimit: 500,
	}
}

// EnableFileLogging opens a log file and writes all subsequent log entries to it
// in addition to the existing writer (e.g. stdout).
func (l *EventLogger) EnableFileLogging(filePath string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		return fmt.Errorf("failed to create log directory: %v", err)
	}

	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %v", err)
	}

	l.file = file
	l.writer = io.MultiWriter(l.writer, file)

	return nil
}

// Close closes the log file if one was opened.
func (l *EventLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// Log writes an event with a timestamp and action description.
func (l *EventLogger) Log(subject, action string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	timestamp := time.Now().Format(time.RFC3339)
	logEntry := fmt.Sprintf("[%s] %s: %s\n", timestamp, subject, action)

	_, _ = l.writer.Write([]byte(logEntry))

	if l.buffer != nil {
		if len(l.buffer) >= l.bufLimit {
			l.buffer = l.buffer[1:]
		}
		l.buffer = append(l.buffer, strings.TrimRight(logEntry, "\n"))
	}
}

// EnableBuffer activates the in-memory ring buffer (used by UI to display logs).
func (l *EventLogger) EnableBuffer() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buffer = make([]string, 0, l.bufLimit)
}

// GetBuffer returns a copy of the in-memory log buffer.
func (l *EventLogger) GetBuffer() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, len(l.buffer))
	copy(out, l.buffer)
	return out
}
