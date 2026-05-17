package logger

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"sort"

	"github.com/rs/zerolog"
)

// SlogAdapter is the set of logger types that can be adapted to slog.
type SlogAdapter interface {
	*slog.Logger | zerolog.Logger
}

// AsSlog returns l as a slog logger. It accepts *slog.Logger and, for legacy
// compatibility, zerolog.Logger.
//
// The zerolog support is deprecated and may be removed in future versions.
// Users should prefer using slog.Logger directly, as it is the standard library
// logger in Go 1.21 and later, and it is the default logger used by gnark.
func AsSlog[T SlogAdapter](l T) (*slog.Logger, bool) {
	switch l := any(l).(type) {
	case *slog.Logger:
		if l == nil {
			return nil, false
		}
		return l, true
	case zerolog.Logger:
		return FromZerolog(l), true
	default:
		return nil, false
	}
}

// FromZerolog adapts a legacy zerolog logger to slog.
func FromZerolog(log zerolog.Logger) *slog.Logger {
	return slog.New(zerologHandler{logger: log})
}

// ToZerolog adapts a slog logger to the legacy zerolog API.
func ToZerolog(log *slog.Logger) zerolog.Logger {
	return zerolog.New(slogLevelWriter{logger: log}).Level(zerolog.TraceLevel)
}

type zerologHandler struct {
	logger zerolog.Logger
	attrs  []slog.Attr
}

func (h zerologHandler) Enabled(_ context.Context, level slog.Level) bool {
	return h.logger.GetLevel() <= zerologLevel(level) && h.logger.GetLevel() != zerolog.Disabled
}

func (h zerologHandler) Handle(_ context.Context, record slog.Record) error {
	event := h.logger.WithLevel(zerologLevel(record.Level))
	for _, attr := range h.attrs {
		event = addAttr(event, attr)
	}
	record.Attrs(func(attr slog.Attr) bool {
		event = addAttr(event, attr)
		return true
	})
	event.Msg(record.Message)
	return nil
}

func (h zerologHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	h.attrs = append(append([]slog.Attr{}, h.attrs...), attrs...)
	return h
}

func (h zerologHandler) WithGroup(string) slog.Handler {
	return h
}

func addAttr(event *zerolog.Event, attr slog.Attr) *zerolog.Event {
	attr.Value = attr.Value.Resolve()
	switch attr.Value.Kind() {
	case slog.KindString:
		return event.Str(attr.Key, attr.Value.String())
	case slog.KindInt64:
		return event.Int64(attr.Key, attr.Value.Int64())
	case slog.KindUint64:
		return event.Uint64(attr.Key, attr.Value.Uint64())
	case slog.KindFloat64:
		return event.Float64(attr.Key, attr.Value.Float64())
	case slog.KindBool:
		return event.Bool(attr.Key, attr.Value.Bool())
	case slog.KindDuration:
		return event.Dur(attr.Key, attr.Value.Duration())
	case slog.KindTime:
		return event.Time(attr.Key, attr.Value.Time())
	default:
		return event.Interface(attr.Key, attr.Value.Any())
	}
}

func zerologLevel(level slog.Level) zerolog.Level {
	switch {
	case level <= LevelTrace:
		return zerolog.TraceLevel
	case level <= slog.LevelDebug:
		return zerolog.DebugLevel
	case level < slog.LevelWarn:
		return zerolog.InfoLevel
	case level < slog.LevelError:
		return zerolog.WarnLevel
	default:
		return zerolog.ErrorLevel
	}
}

type slogLevelWriter struct {
	logger *slog.Logger
}

func (w slogLevelWriter) Write(p []byte) (int, error) {
	return w.WriteLevel(zerolog.NoLevel, p)
}

func (w slogLevelWriter) WriteLevel(level zerolog.Level, p []byte) (int, error) {
	level, msg, attrs := decodeZerologEvent(level, p)
	w.logger.LogAttrs(context.Background(), slogLevel(level), msg, attrs...)
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
		level = parseZerologLevel(fields[zerolog.LevelFieldName])
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

func parseZerologLevel(value any) zerolog.Level {
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
		return LevelTrace
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
