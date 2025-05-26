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
