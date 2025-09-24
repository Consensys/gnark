// Package logger provides a configurable logger across gnark components
//
// The root logger defined by default uses github.com/rs/zerolog with a console writer
package logger

import (
	"io"
	"os"
	"strings"
	"sync/atomic"

	"github.com/consensys/gnark/debug"
	"github.com/rs/zerolog"
)

var globalLogger atomic.Value // stores zerolog.Logger

func init() {
	output := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}
	l := zerolog.New(output).With().Timestamp().Logger()

	if !debug.Debug && strings.HasSuffix(os.Args[0], ".test") {
		l = zerolog.Nop()
	}

	globalLogger.Store(l)
}

// SetOutput changes the output of the global logger
func SetOutput(w io.Writer) {
	l := globalLogger.Load().(zerolog.Logger)
	globalLogger.Store(l.Output(w))
}

// Set allows a gnark user to overhide the global logger
func Set(l zerolog.Logger) {
	globalLogger.Store(l)
}

// Disable disables logging
func Disable() {
	globalLogger.Store(zerolog.Nop())
}

// Logger returns a sublogger for a component
func Logger() zerolog.Logger {
	return globalLogger.Load().(zerolog.Logger)
}
