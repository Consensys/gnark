package logger

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/consensys/gnark/debug"
)

func TestLoggerUsesInfoTextHandler(t *testing.T) {
	var buf bytes.Buffer
	withLoggerOutput(t, &buf)

	t.Setenv(EnvLevel, "info")
	log := Logger()

	log.Debug("hidden")
	log.Info("visible")

	output := buf.String()
	if strings.Contains(output, "hidden") {
		t.Fatal("debug log should not be emitted at the default level")
	}
	if !strings.Contains(output, "level=INFO") || !strings.Contains(output, "msg=visible") {
		t.Fatalf("expected info text output, got %q", output)
	}
	if !strings.Contains(output, "time=") {
		t.Fatalf("expected timestamp in text output, got %q", output)
	}
}

func TestLoggerDefaultsToDebugWithDebugBuildTag(t *testing.T) {
	var buf bytes.Buffer
	withLoggerOutput(t, &buf)
	withUnsetenv(t, EnvLevel)

	log := Logger()
	log.Debug("visible")

	output := buf.String()
	if debug.Debug {
		if !strings.Contains(output, "level=DEBUG") || !strings.Contains(output, "msg=visible") {
			t.Fatalf("expected debug output with debug build tag, got %q", output)
		}
		return
	}
	if strings.Contains(output, "msg=visible") {
		t.Fatalf("debug output should not be emitted without debug build tag, got %q", output)
	}
}

func TestEnvironmentOverridesDebugBuildTagDefault(t *testing.T) {
	t.Setenv(EnvLevel, "error")
	if level := levelFromEnv(true); level != slog.LevelError {
		t.Fatalf("expected environment level to override debug default, got %s", level)
	}
}

func TestLoggerReadsEnvironmentLevel(t *testing.T) {
	testCases := []struct {
		name     string
		env      string
		level    slog.Level
		expected string
	}{
		{name: "trace", env: "trace", level: LevelTrace, expected: "level=TRACE"},
		{name: "debug", env: "debug", level: slog.LevelDebug, expected: "level=DEBUG"},
		{name: "info", env: "info", level: slog.LevelInfo, expected: "level=INFO"},
		{name: "warning", env: "warning", level: slog.LevelWarn, expected: "level=WARN"},
		{name: "error", env: "error", level: slog.LevelError, expected: "level=ERROR"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			withLoggerOutput(t, &buf)
			t.Setenv(EnvLevel, tc.env)

			Logger().Log(context.Background(), tc.level, "visible")

			output := buf.String()
			if !strings.Contains(output, tc.expected) || !strings.Contains(output, "msg=visible") {
				t.Fatalf("expected %q output, got %q", tc.expected, output)
			}
		})
	}
}

func TestLoggerQuietLevelDisablesOutput(t *testing.T) {
	for _, env := range []string{"quiet", "none"} {
		t.Run(env, func(t *testing.T) {
			var buf bytes.Buffer
			withLoggerOutput(t, &buf)
			t.Setenv(EnvLevel, env)

			log := Logger()
			log.Error("hidden")
			log.Log(context.Background(), LevelTrace, "hidden")

			if log.Enabled(context.Background(), slog.LevelError) {
				t.Fatal("quiet logger should be disabled for error logs")
			}
			if output := buf.String(); output != "" {
				t.Fatalf("quiet logger should not emit output, got %q", output)
			}
		})
	}
}

func TestLoggerDebugLevelEmitsRuntimeInfo(t *testing.T) {
	var buf bytes.Buffer
	withLoggerOutput(t, &buf)
	t.Setenv(EnvLevel, "debug")

	Logger()

	output := buf.String()
	for _, expected := range []string{
		"msg=\"runtime configuration\"",
		"gomaxprocs=",
		"gomemlimit=",
		"build_tags=",
		"goarch=",
		"goos=",
		"support_neon=",
		"support_avx512=",
		"support_avx512ifma=",
		"go_build_version=",
		"vcs_tagged_version=",
		"vcs_modified=",
		"gnark_version=",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("expected %q in debug runtime output, got %q", expected, output)
		}
	}
	if runtime.GOARCH == "arm" {
		if !strings.Contains(output, "goarm=") {
			t.Fatalf("expected goarm in debug runtime output for arm, got %q", output)
		}
	} else if strings.Contains(output, "goarm=") {
		t.Fatalf("did not expect goarm in debug runtime output for %s, got %q", runtime.GOARCH, output)
	}
}

func TestLoggerTraceLevelEmitsSource(t *testing.T) {
	var buf bytes.Buffer
	withLoggerOutput(t, &buf)
	t.Setenv(EnvLevel, "trace")

	Logger().Log(context.Background(), LevelTrace, "visible")

	output := buf.String()
	if !strings.Contains(output, "level=TRACE") || !strings.Contains(output, "msg=visible") {
		t.Fatalf("expected trace output, got %q", output)
	}
	if !strings.Contains(output, "source=") {
		t.Fatalf("expected source location in trace output, got %q", output)
	}
}

func withLoggerOutput(t *testing.T, w *bytes.Buffer) {
	t.Helper()

	previousOutput := defaultOutput
	previousLogger := defaultLogger
	previousOnce := defaultOnce
	defaultOutput = w
	defaultLogger = nil
	defaultOnce = new(sync.Once)

	t.Cleanup(func() {
		defaultOutput = previousOutput
		defaultLogger = previousLogger
		defaultOnce = previousOnce
	})
}

func withUnsetenv(t *testing.T, key string) {
	t.Helper()

	previousValue, previousSet := os.LookupEnv(key)
	if err := os.Unsetenv(key); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		var err error
		if previousSet {
			err = os.Setenv(key, previousValue)
		} else {
			err = os.Unsetenv(key)
		}
		if err != nil {
			t.Fatal(err)
		}
	})
}
