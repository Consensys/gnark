// Package logger provides a deprecated zerolog-compatible logger.
//
// Deprecated: use log/slog with github.com/consensys/gnark/internal/logger
// inside gnark. This package will be removed soon.
package logger

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"sort"
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
	return zerolog.New(slogLevelWriter{}).Level(zerolog.TraceLevel)
}

func warnDeprecated() {
	if logger.GetLevel() == zerolog.Disabled {
		return
	}
	deprecatedOnce.Do(func() {
		internallogger.Logger().Warn(deprecationMessage)
	})
}

type slogLevelWriter struct{}

func (slogLevelWriter) Write(p []byte) (int, error) {
	return slogLevelWriter{}.WriteLevel(zerolog.NoLevel, p)
}

func (slogLevelWriter) WriteLevel(level zerolog.Level, p []byte) (int, error) {
	level, msg, attrs := decodeZerologEvent(level, p)
	internallogger.Logger().LogAttrs(context.Background(), slogLevel(level), msg, attrs...)
	return len(p), nil
}

func decodeZerologEvent(level zerolog.Level, p []byte) (zerolog.Level, string, []slog.Attr) {
	decoder := json.NewDecoder(bytes.NewReader(p))
	decoder.UseNumber()

	var fields map[string]any
	if err := decoder.Decode(&fields); err != nil {
		return level, string(bytes.TrimSpace(p)), nil
	}

	if level == zerolog.NoLevel {
		level = zerologLevel(fields[zerolog.LevelFieldName])
	}

	msg, _ := fields[zerolog.MessageFieldName].(string)
	delete(fields, zerolog.LevelFieldName)
	delete(fields, zerolog.MessageFieldName)
	delete(fields, zerolog.TimestampFieldName)

	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	attrs := make([]slog.Attr, 0, len(keys))
	for _, key := range keys {
		attrs = append(attrs, slog.Any(key, fields[key]))
	}
	return level, msg, attrs
}

func zerologLevel(value any) zerolog.Level {
	level, ok := value.(string)
	if !ok {
		return zerolog.InfoLevel
	}
	parsed, err := zerolog.ParseLevel(level)
	if err != nil {
		return zerolog.InfoLevel
	}
	return parsed
}

func slogLevel(level zerolog.Level) slog.Level {
	switch level {
	case zerolog.TraceLevel:
		return internallogger.LevelTrace
	case zerolog.DebugLevel:
		return slog.LevelDebug
	case zerolog.InfoLevel, zerolog.NoLevel:
		return slog.LevelInfo
	case zerolog.WarnLevel:
		return slog.LevelWarn
	case zerolog.ErrorLevel, zerolog.FatalLevel, zerolog.PanicLevel:
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
