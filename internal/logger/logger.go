// Package logger provides gnark's internal slog logger.
package logger

import (
	"context"
	"io"
	"log/slog"
	"os"
	"runtime"
	runtimedebug "runtime/debug"
	"strings"
	"sync"

	"github.com/consensys/gnark"
	"github.com/consensys/gnark-crypto/utils/cpu"
	"github.com/consensys/gnark/debug"
)

const (
	// EnvLevel is the environment variable used to configure the default logger.
	EnvLevel = "GNARK_LOG_LEVEL"

	LevelTrace slog.Level = -8

	LevelDisabled slog.Level = 1<<31 - 1
)

var (
	defaultOnce   = new(sync.Once)
	defaultLogger *slog.Logger
	defaultOutput io.Writer = os.Stdout
)

// Logger returns gnark's default internal logger.
func Logger() *slog.Logger {
	defaultOnce.Do(func() {
		level := levelFromEnv(debug.Debug)
		if level == LevelDisabled {
			defaultLogger = slog.New(newHandler(io.Discard, level))
			return
		}
		defaultLogger = slog.New(newHandler(defaultOutput, level))
		logDebugRuntimeInfo(defaultLogger)
	})
	return defaultLogger
}

func Trace(log *slog.Logger, msg string, attrs ...slog.Attr) {
	log.LogAttrs(context.Background(), LevelTrace, msg, attrs...)
}

func newHandler(w io.Writer, level slog.Level) slog.Handler {
	return slog.NewTextHandler(w, &slog.HandlerOptions{
		// We want to include the source for trace logs, but not for higher
		// levels, to avoid the overhead of getting the caller info when it's
		// not needed.
		AddSource: level <= LevelTrace,
		Level:     level,
		// LevelTrace is not a standard slog level, so we need to replace it
		// with a string for the text handler.
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.LevelKey && a.Value.Kind() == slog.KindAny {
				if level, ok := a.Value.Any().(slog.Level); ok && level == LevelTrace {
					a.Value = slog.StringValue("TRACE")
				}
			}
			return a
		},
	})
}

func levelFromEnv(debugDefault bool) slog.Level {
	envLevel, ok := os.LookupEnv(EnvLevel)
	if !ok {
		if debugDefault {
			return slog.LevelDebug
		}
		return slog.LevelInfo
	}
	switch strings.ToLower(strings.TrimSpace(envLevel)) {
	case "trace":
		return LevelTrace
	case "debug":
		return slog.LevelDebug
	case "", "info":
		return slog.LevelInfo
	case "warning", "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	case "quiet", "none":
		return LevelDisabled
	default:
		return slog.LevelInfo
	}
}

func logDebugRuntimeInfo(log *slog.Logger) {
	if !log.Enabled(context.Background(), slog.LevelDebug) {
		return
	}
	buildInfo, ok := runtimedebug.ReadBuildInfo()
	if !ok {
		log.LogAttrs(context.Background(), slog.LevelDebug, "runtime configuration", runtimeInfoAttrs(nil)...)
		return
	}
	log.LogAttrs(context.Background(), slog.LevelDebug, "runtime configuration", runtimeInfoAttrs(buildInfo)...)
}

func runtimeInfoAttrs(buildInfo *runtimedebug.BuildInfo) []slog.Attr {
	attrs := []slog.Attr{
		slog.Int("gomaxprocs", runtime.GOMAXPROCS(0)),
		slog.Int64("gomemlimit", runtimedebug.SetMemoryLimit(-1)),
		slog.String("goarch", runtime.GOARCH),
		slog.String("goos", runtime.GOOS),
		slog.Bool("support_neon", cpu.SupportNEON),
		slog.Bool("support_avx512", cpu.SupportAVX512),
		slog.Bool("support_avx512ifma", cpu.SupportAVX512IFMA),
		slog.String("gnark_version", gnark.Version.String()),
	}
	if runtime.GOARCH == "arm" {
		attrs = append(attrs, slog.String("goarm", buildSetting(buildInfo, "GOARM")))
	}
	if buildInfo != nil {
		attrs = append(attrs,
			slog.String("build_tags", buildSetting(buildInfo, "-tags")),
			slog.String("go_build_version", buildInfo.GoVersion),
			slog.String("vcs_tagged_version", buildInfo.Main.Version),
			slog.String("vcs_modified", buildSetting(buildInfo, "vcs.modified")),
		)
	}
	return attrs
}

func buildSetting(buildInfo *runtimedebug.BuildInfo, key string) string {
	if buildInfo == nil {
		return ""
	}
	for _, setting := range buildInfo.Settings {
		if setting.Key == key {
			return setting.Value
		}
	}
	return ""
}
