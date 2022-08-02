package profile

import (
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/google/pprof/profile"
)

// since we are assuming usage of this package from a single go routine, this channel only has
// one "producer", and one "consumer". it's purpose is to guarantee the order of execution of
// adding / removing a profiling session and sampling events, while enabling the caller
// (frontend.Compile) to sample the events asynchronously.
var chCommands = make(chan command, 100)
var onceInit sync.Once

type command struct {
	p      *Profile
	pc     []uintptr
	remove bool
}

func worker() {
	for c := range chCommands {
		if c.p != nil {
			if c.remove {
				for i := 0; i < len(sessions); i++ {
					if sessions[i] == c.p {
						sessions[i] = sessions[len(sessions)-1]
						sessions = sessions[:len(sessions)-1]
						break
					}
				}
				close(c.p.chDone)

				// decrement active sessions
				atomic.AddUint32(&activeSessions, ^uint32(0))
			} else {
				sessions = append(sessions, c.p)
			}
			continue
		}

		// it's a sampling of event
		collectSample(c.pc)
	}

}

// collectSample must be called from the worker go routine
func collectSample(pc []uintptr) {
	// for each session we may have a distinct sample, since ids of functions and locations may mismatch
	samples := make([]*profile.Sample, len(sessions))
	for i := 0; i < len(samples); i++ {
		samples[i] = &profile.Sample{Value: []int64{1}} // for now, we just collect new constraints count
	}

	frames := runtime.CallersFrames(pc)
	// Loop to get frames.
	// A fixed number of pcs can expand to an indefinite number of Frames.
	for {
		frame, more := frames.Next()

		if strings.HasSuffix(frame.Function, ".func1") {
			// TODO @gbotrel filter anonymous func better
			continue
		}

		// to avoid aving a location that concentrates 99% of the calls, we transfer the "addConstraint"
		// occuring in Mul to the previous level in the stack
		if strings.Contains(frame.Function, "github.com/consensys/gnark/frontend/cs/r1cs.(*r1cs).Mul") {
			continue
		}

		if strings.HasPrefix(frame.Function, "github.com/consensys/gnark/frontend/cs/scs.(*scs).Mul") {
			continue
		}

		if strings.HasPrefix(frame.Function, "github.com/consensys/gnark/frontend/cs/scs.(*scs).split") {
			continue
		}

		// with scs.Builder (Plonk) Add and Sub always add a constraint --> we record the caller as the constraint adder
		// but in the future we may record a different type of sample for these
		if strings.HasPrefix(frame.Function, "github.com/consensys/gnark/frontend/cs/scs.(*scs).Add") {
			continue
		}
		if strings.HasPrefix(frame.Function, "github.com/consensys/gnark/frontend/cs/scs.(*scs).Sub") {
			continue
		}

		// TODO @gbotrel [...] -> from generics display poorly in pprof
		// https://github.com/golang/go/issues/54105
		frame.Function = strings.Replace(frame.Function, "[...]", "[T]", -1)

		for i := 0; i < len(samples); i++ {
			samples[i].Location = append(samples[i].Location, sessions[i].getLocation(&frame))
		}

		if !more {
			break
		}
		if strings.HasSuffix(frame.Function, ".Define") {
			for i := 0; i < len(sessions); i++ {
				sessions[i].onceSetName.Do(func() {
					// once per profile session, we set the "name of the binary"
					// here we grep the struct name where "Define" exist: hopefully the circuit Name
					fe := strings.Split(frame.Function, "/")
					circuitName := strings.TrimSuffix(fe[len(fe)-1], ".Define")
					sessions[i].pprof.Mapping = []*profile.Mapping{
						{ID: 1, File: circuitName},
					}
				})
			}
			break
		}
	}

	for i := 0; i < len(sessions); i++ {
		sessions[i].pprof.Sample = append(sessions[i].pprof.Sample, samples[i])
	}

}
