package solver

import (
	"fmt"
	"log/slog"
	"runtime"

	"github.com/consensys/gnark/internal/logger"
)

// Option defines option for altering the behavior of a constraint system
// solver (Solve() method). See the descriptions of functions returning instances
// of this type for implemented options.
type Option func(*Config) error

// Config is the configuration for the solver with the options applied.
type Config struct {
	HintFunctions map[HintID]Hint // defaults to all built-in hint functions
	Logger        *slog.Logger    // defaults to gnark's internal logger
	NbTasks       int             // defaults to runtime.NumCPU()
}

// WithHints is a solver option that specifies additional hint functions to be used
// by the constraint solver.
func WithHints(hintFunctions ...Hint) Option {
	return func(opt *Config) error {
		// use logger from config -- NewConfig initializes it.
		log := opt.Logger
		// it is an error to register hint function several times, but as the
		// prover already checks it then omit here.
		for _, h := range hintFunctions {
			uuid := GetHintID(h)
			if _, ok := opt.HintFunctions[uuid]; ok {
				log.Debug("WithHints called for already registered hint function, skipping", slog.Int("hintID", int(uuid)), slog.String("name", GetHintName(h)))
			} else {
				opt.HintFunctions[uuid] = h
			}
		}
		return nil
	}
}

// OverrideHint forces the solver to use provided hint function for given id.
func OverrideHint(id HintID, f Hint) Option {
	return func(opt *Config) error {
		logger.Trace(opt.Logger, "Overriding hint function", slog.Int("hintID", int(id)), slog.String("name", GetHintName(f)))
		opt.HintFunctions[id] = f
		return nil
	}
}

// WithLogger specifies the destination for logs printed by api.Println(). It
// accepts *slog.Logger. For compatibility, legacy logger values are also
// accepted, but deprecated. If this option is not provided, the default logger
// is used. Passing nil disables logging.
//
// The deprecated zerolog type parameter is accepted for backward compatibility,
// but the user should prefer using slog.Logger directly, as it is the standard
// library logger in Go 1.21 and later, and it is the default logger used by
// gnark. The zerolog support may be removed in future versions.
func WithLogger[T logger.SlogAdapter](l T) Option {
	return func(opt *Config) error {
		log, ok := logger.AsSlog(l)
		if ok {
			opt.Logger = log
		} else {
			opt.Logger = logger.DisabledLogger()
		}
		return nil
	}
}

// WithNbTasks sets the number of parallel workers to use for the solver. If not
// set, then the number of workers is set to runtime.NumCPU().
//
// The option may be useful for debugging the solver behaviour and restricting
// the CPU usage. Note that this is not hard limit - in case the solver calls a
// hint function which may create more goroutines, the number of goroutines may
// exceed the limit.
func WithNbTasks(nbTasks int) Option {
	return func(opt *Config) error {
		if nbTasks <= 0 {
			return fmt.Errorf("invalid number of threads: %d", nbTasks)
		}
		if nbTasks > 512 {
			// limit the number of tasks to 512. This is to avoid possible
			// saturation of the runtime scheduler.
			nbTasks = 512
		}
		opt.NbTasks = nbTasks
		return nil
	}
}

// NewConfig returns a default SolverConfig with given prover options opts applied.
func NewConfig(opts ...Option) (Config, error) {
	opt := Config{Logger: logger.Logger()}
	opt.HintFunctions = cloneHintRegistry()
	opt.NbTasks = runtime.NumCPU()
	for _, option := range opts {
		if err := option(&opt); err != nil {
			return Config{}, err
		}
	}
	return opt, nil
}
