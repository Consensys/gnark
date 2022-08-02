// Package profile provides a simple way to generate pprof compatible gnark circuit profile.
//
// Since the gnark frontend compiler is not thread safe and operates in a single go-routine,
// this package is also NOT thread safe and is meant to be called in the same go-routine.
package profile

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/consensys/gnark/logger"
	"github.com/google/pprof/profile"
)

var (
	sessions       []*Profile // active sessions
	activeSessions uint32
)

// Profile represents an active constraint system profiling session.
type Profile struct {
	// defaults to ./gnark.pprof
	// if blank, profiile is not written to disk
	filePath string

	// actual pprof profile struct
	// details on pprof format: https://github.com/google/pprof/blob/main/proto/README.md
	pprof profile.Profile

	functions map[string]*profile.Function
	locations map[uint64]*profile.Location

	onceSetName sync.Once

	chDone chan struct{}
}

// ProfilePath controls the profile destination file. If blank, profile is not written.
//
// Defaults to ./gnark.pprof.
func ProfilePath(path string) func(*Profile) {
	return func(p *Profile) {
		p.filePath = path
	}
}

// Start creates a new active profiling session. When Stop() is called, this session is removed from
// active profiling sessions and may be serialized to disk as a pprof compatible file (see ProfilePath option).
//
// All calls to profile.Start() and Stop() are meant to be executed in the same go routine (frontend.Compile).
//
// It is allowed to create multiple overlapping profiling sessions in one circuit.
func Start(options ...func(*Profile)) *Profile {

	// start the worker first time a profiling session starts.
	onceInit.Do(func() {
		go worker()
	})

	prof := Profile{
		functions: make(map[string]*profile.Function),
		locations: make(map[uint64]*profile.Location),
		filePath:  filepath.Join(".", "gnark.pprof"),
		chDone:    make(chan struct{}),
	}
	prof.pprof.SampleType = []*profile.ValueType{{
		Type: "constraints",
		Unit: "count",
	}}

	for _, option := range options {
		option(&prof)
	}

	log := logger.Logger()
	if prof.filePath == "" {
		log.Warn().Msg("gnark profiling enabled [not writting to disk]")
	} else {
		log.Info().Str("path", prof.filePath).Msg("gnark profiling enabled")
	}

	// add the session to active sessions
	chCommands <- command{p: &prof}
	atomic.AddUint32(&activeSessions, 1)

	return &prof
}

// Stop removes the profile from active session and may write the pprof file to disk. See ProfilePath option.
func (p *Profile) Stop() {
	log := logger.Logger()

	if p.chDone == nil {
		log.Fatal().Msg("gnark profile stopped multiple times")
	}

	// ask worker routine to remove ourselves from the active sessions
	chCommands <- command{p: p, remove: true}

	// wait for worker routine to remove us.
	<-p.chDone
	p.chDone = nil

	// if filePath is set, serialize profile to disk in pprof format
	if p.filePath != "" {
		f, err := os.Create(p.filePath)
		if err != nil {
			log.Fatal().Err(err).Msg("could not create gnark profile")
		}
		if err := p.pprof.Write(f); err != nil {
			log.Error().Err(err).Msg("writing profile")
		}
		f.Close()
		log.Info().Str("path", p.filePath).Msg("gnark profiling disabled")
	} else {
		log.Warn().Msg("gnark profiling disabled [not writting to disk]")
	}

}

// RecordConstraint add a sample (with count == 1) to all the active profiling sessions.
func RecordConstraint() {
	if n := atomic.LoadUint32(&activeSessions); n == 0 {
		return // do nothing, no active session.
	}

	// collect the stack and send it async to the worker
	pc := make([]uintptr, 20)
	n := runtime.Callers(3, pc)
	if n == 0 {
		return
	}
	pc = pc[:n]
	chCommands <- command{pc: pc}
}

func (p *Profile) getLocation(frame *runtime.Frame) *profile.Location {

	// location
	// locationID := frame.File + strconv.Itoa(frame.Line)
	l, ok := p.locations[uint64(frame.PC)]
	if !ok {
		// first let's see if we have the function.
		f, ok := p.functions[frame.File+frame.Function]
		if !ok {
			fe := strings.Split(frame.Function, "/")
			fName := fe[len(fe)-1]
			f = &profile.Function{
				ID:         uint64(len(p.functions) + 1),
				Name:       fName,
				SystemName: frame.Function,
				Filename:   frame.File,
			}

			p.functions[frame.File+frame.Function] = f
			p.pprof.Function = append(p.pprof.Function, f)
		}

		l = &profile.Location{
			ID:   uint64(len(p.locations) + 1),
			Line: []profile.Line{{Function: f, Line: int64(frame.Line)}},
		}
		p.locations[uint64(frame.PC)] = l
		p.pprof.Location = append(p.pprof.Location, l)
	}

	return l
}
