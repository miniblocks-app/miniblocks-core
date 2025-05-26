package logger

import (
	"go.uber.org/zap"
)

var log *zap.Logger

// Initialize sets up the logger
func Initialize() {
	log = zap.Must(zap.NewProduction())
}

// Get returns the logger instance
func Get() *zap.Logger {
	return log
}

// Sync flushes any buffered log entries
func Sync() error {
	return log.Sync()
}

// Info logs a message at info level
func Info(msg string, fields ...zap.Field) {
	log.Info(msg, fields...)
}

// Error logs a message at error level
func Error(msg string, fields ...zap.Field) {
	log.Error(msg, fields...)
}

// Warn logs a message at warn level
func Warn(msg string, fields ...zap.Field) {
	log.Warn(msg, fields...)
}

// Debug logs a message at debug level
func Debug(msg string, fields ...zap.Field) {
	log.Debug(msg, fields...)
}

// Fatal logs a message at fatal level and then calls os.Exit(1)
func Fatal(msg string, fields ...zap.Field) {
	log.Fatal(msg, fields...)
}
