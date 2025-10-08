package oauth

import (
	"context"
	"fmt"
	"log"
	"os"
)

// Logger is a minimal interface for structured logging
// Implementations can provide their own logger (e.g., logrus, zap, slog)
type Logger interface {
	Infof(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}

type contextKey struct{}

var loggerKey = contextKey{}

// WithLogger returns a new context with the logger attached
func WithLogger(ctx context.Context, logger Logger) context.Context {
	return context.WithValue(ctx, loggerKey, logger)
}

// LoggerFromContext extracts the logger from context
// Returns a default logger if none is set
func LoggerFromContext(ctx context.Context) Logger {
	if logger, ok := ctx.Value(loggerKey).(Logger); ok {
		return logger
	}
	return defaultLogger
}

// defaultLogger is a simple implementation that logs to stderr with a prefix
var defaultLogger Logger = &stdLogger{
	logger: log.New(os.Stderr, "[oauth-helpers] ", log.LstdFlags),
}

// stdLogger implements Logger using the standard log package
type stdLogger struct {
	logger *log.Logger
}

func (l *stdLogger) Infof(format string, args ...interface{}) {
	l.logger.Printf("INFO: "+format, args...)
}

func (l *stdLogger) Warnf(format string, args ...interface{}) {
	l.logger.Printf("WARN: "+format, args...)
}

func (l *stdLogger) Errorf(format string, args ...interface{}) {
	l.logger.Printf("ERROR: "+format, args...)
}

// noopLogger is a logger that does nothing (for testing or when logging is disabled)
type noopLogger struct{}

func (noopLogger) Infof(format string, args ...interface{})  {}
func (noopLogger) Warnf(format string, args ...interface{})  {}
func (noopLogger) Errorf(format string, args ...interface{}) {}

// NoopLogger returns a logger that does nothing
func NoopLogger() Logger {
	return noopLogger{}
}

// Adapter for Pinata's ComponentLogger to implement our Logger interface
// This allows Pinata to pass its logger directly without wrapping

// For convenience, add a function to wrap any interface with these methods
func WrapLogger(l interface {
	Infof(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}) Logger {
	return &wrappedLogger{l: l}
}

type wrappedLogger struct {
	l interface {
		Infof(format string, args ...interface{})
		Warnf(format string, args ...interface{})
		Errorf(format string, args ...interface{})
	}
}

func (w *wrappedLogger) Infof(format string, args ...interface{}) {
	w.l.Infof(format, args...)
}

func (w *wrappedLogger) Warnf(format string, args ...interface{}) {
	w.l.Warnf(format, args...)
}

func (w *wrappedLogger) Errorf(format string, args ...interface{}) {
	w.l.Errorf(format, args...)
}

// Helper to create a prefixed logger from fmt package (for quick debugging)
func NewPrefixLogger(prefix string) Logger {
	return &stdLogger{
		logger: log.New(os.Stderr, fmt.Sprintf("[%s] ", prefix), log.LstdFlags),
	}
}
