// Package logger provides a deprecated zerolog-compatible logger.
//
// Deprecated: use log/slog with github.com/consensys/gnark/internal/logger
// inside gnark. This package will be removed soon.
package logger

import (
	"io"
	"sync"
	"testing"

	internallogger "github.com/consensys/gnark/internal/logger"

	"github.com/consensys/gnark/debug"
	"github.com/rs/zerolog"
)

const deprecationMessage = "github.com/consensys/gnark/logger is deprecated and will be removed soon; use log/slog instead"

var (
	logger         zerolog.Logger
	deprecatedOnce sync.Once
)

func init() {
	logger = newSlogBackedZerolog()

	if !debug.Debug && testing.Testing() {
		logger = zerolog.Nop()
	}
}

// SetOutput changes the output of the global logger.
//
// Deprecated: use log/slog directly. This package will be removed soon.
func SetOutput(w io.Writer) {
	warnDeprecated()
	logger = zerolog.New(w).Level(zerolog.TraceLevel)
}

// Set allows a gnark user to override the global logger.
//
// Deprecated: use log/slog directly. This package will be removed soon.
func Set(l zerolog.Logger) {
	warnDeprecated()
	logger = l
}

// Disable disables logging.
//
// Deprecated: use log/slog directly. This package will be removed soon.
func Disable() {
	warnDeprecated()
	logger = zerolog.Nop()
}

// Logger returns the legacy zerolog-compatible logger.
//
// Deprecated: use log/slog directly. This package will be removed soon.
func Logger() zerolog.Logger {
	warnDeprecated()
	return logger
}

func newSlogBackedZerolog() zerolog.Logger {
	return internallogger.ToZerolog(internallogger.Logger())
}

func warnDeprecated() {
	if logger.GetLevel() == zerolog.Disabled {
		return
	}
	deprecatedOnce.Do(func() {
		internallogger.Logger().Warn(deprecationMessage)
	})
}
