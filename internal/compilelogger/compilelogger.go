// Package compilelogger provides logging helpers for circuit compilation time.
// It deduplicates log messages within a single compilation run so that
// repeated gadget instantiations do not flood the output with identical warnings.
package compilelogger

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/kvstore"
	"github.com/consensys/gnark/logger"
	"github.com/rs/zerolog"
)

type compileLoggerKey struct {
	identifier string
}

// LogOnce logs a message with the given level and identifier, but only the
// first time it is called with that identifier during a compilation run.
// Subsequent calls with the same identifier will not log anything.
//
// Recommended identifier format is "component/feature" to allow filtering by
// component and grouping related messages together.
//
// msg can be a format string and args are the corresponding arguments, as in logger.Logger().Msgf(msg, args...).
//
// LogOnce panics if the api does not implement [kvstore.Store], which should
// never happen since the compiler is expected to implement it.
func LogOnce(api frontend.Compiler, level zerolog.Level, identifier, msg string, args ...any) {
	kv, ok := api.(kvstore.Store)
	if !ok {
		panic("compiler should implement key-value store")
	}
	key := compileLoggerKey{identifier: identifier}
	if kv.GetKeyValue(key) != nil {
		return
	}
	// set the key to avoid logging again with the same identifier
	kv.SetKeyValue(key, struct{}{})

	l := logger.Logger()
	l.WithLevel(level).Msgf(msg, args...)
}
