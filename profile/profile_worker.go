package profile

import (
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"unicode"

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

	// For SparseR1C constraints (most common case), we pass the 3 wire IDs directly
	// to avoid slice allocation. hasVids indicates these are valid.
	xa, xb, xc uint32
	hasVids    bool

	// vids contains variable IDs used in a constraint (for R1C with variable length)
	vids []int

	// recordVid is set when recording a variable creation (non-zero means record this VID)
	// -1 is a special value meaning "not recording a vid"
	recordVid int
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

		// check if this is a variable recording command
		if c.recordVid != 0 {
			recordVariableOrigin(c.recordVid, c.pc)
			continue
		}

		// it's a sampling of event (constraint)
		// convert SparseR1C wire IDs to slice if present
		var vids []int
		if c.hasVids {
			vids = []int{int(c.xa), int(c.xb), int(c.xc)}
		} else if c.vids != nil {
			vids = c.vids
		}
		collectSample(c.pc, vids)
	}

}

// recordVariableOrigin stores the stack trace for a variable ID
func recordVariableOrigin(vid int, pc []uintptr) {
	for _, session := range sessions {
		// store the stack trace for this variable
		session.variableOrigins[vid] = pc
		// also update the "last" variable origin for fallback attribution
		session.lastVariableOrigin = pc
		session.lastVariableVID = vid
	}
}

// collectSample must be called from the worker go routine
// vids contains the variable IDs used in the constraint (for attribution during deferred phase)
func collectSample(pc []uintptr, vids []int) {
	isDeferred := atomic.LoadUint32(&inDeferredPhase) == 1

	// for each session we may have a distinct sample, since ids of functions and locations may mismatch
	samples := make([]*profile.Sample, len(sessions))
	for i := range samples {
		samples[i] = &profile.Sample{Value: []int64{1}} // for now, we just collect new constraints count
	}

	// Process the current stack trace for the regular profile
	frames := runtime.CallersFrames(pc)
	// Loop to get frames.
	// A fixed number of pcs can expand to an indefinite number of Frames.
	for {
		frame, more := frames.Next()

		if strings.Contains(frame.Function, "frontend.parseCircuit") {
			// we stop; previous frame was the .Define definition of the circuit
			break
		}

		if strings.HasSuffix(frame.Function, ".func1") {
			// TODO @gbotrel filter anonymous func better
			//
			// ivokub: relevant comment - if we have many anonymous functions in package, then the name of the anonymous function has different suffices.
			continue
		}

		// filter internal builder functions
		if filterSCSPrivateFunc(frame.Function) || filterR1CSPrivateFunc(frame.Function) {
			continue
		}

		// TODO @gbotrel [...] -> from generics display poorly in pprof
		// https://github.com/golang/go/issues/54105
		frame.Function = strings.ReplaceAll(frame.Function, "[...]", "[T]")

		for i := range samples {
			samples[i].Location = append(samples[i].Location, sessions[i].getLocation(&frame))
		}

		if !more {
			break
		}
		if strings.HasSuffix(frame.Function, ".Define") {
			for i := range sessions {
				sessions[i].onceSetName.Do(func() {
					// once per profile session, we set the "name of the binary"
					// here we grep the struct name where "Define" exist: hopefully the circuit Name
					// note: this won't work well for nested Define calls.
					fe := strings.Split(frame.Function, "/")
					circuitName := strings.TrimSuffix(fe[len(fe)-1], ".Define")
					sessions[i].pprof.Mapping = []*profile.Mapping{
						{ID: 1, File: circuitName},
					}
				})
			}
			// break --> we break when we hit frontend.parseCircuit; in case we have nested Define calls in the stack.
		}
	}

	// Add regular samples to the regular profile
	for i := range sessions {
		sessions[i].pprof.Sample = append(sessions[i].pprof.Sample, samples[i])
	}

	// If in deferred phase, create samples for the deferred profile using origin stacks
	if isDeferred {
		collectDeferredSample(pc, vids)
	}
}

// collectDeferredSample creates samples for the deferred profile, attributing constraints
// to their origin in the circuit based on the variables they use.
func collectDeferredSample(currentPC []uintptr, vids []int) {
	// For each session, find the best origin stack(s) to attribute this constraint to
	for _, session := range sessions {
		// Collect all known origins from the VIDs used in this constraint
		var knownOrigins [][]uintptr
		var originLabels []string

		for _, vid := range vids {
			if vid == 0 {
				continue // skip zero VIDs
			}
			if origin, ok := session.variableOrigins[vid]; ok {
				// Check if we already have this origin (by comparing first PC)
				isDuplicate := false
				for _, existing := range knownOrigins {
					if len(existing) > 0 && len(origin) > 0 && existing[0] == origin[0] {
						isDuplicate = true
						break
					}
				}
				if !isDuplicate {
					knownOrigins = append(knownOrigins, origin)
					originLabels = append(originLabels, getOriginLabel(origin))
				}
			}
		}

		// If no known origins found, use the last variable origin as fallback
		// This heuristic assumes the constraint is related to recently created variables
		if len(knownOrigins) == 0 && session.lastVariableOrigin != nil {
			knownOrigins = append(knownOrigins, session.lastVariableOrigin)
			originLabels = append(originLabels, getOriginLabel(session.lastVariableOrigin)+" (inferred)")
		}

		// If still no origin, fall back to current stack (less useful but better than nothing)
		if len(knownOrigins) == 0 {
			knownOrigins = append(knownOrigins, currentPC)
			originLabels = append(originLabels, "unknown origin")
		}

		// Create a sample for each unique origin
		// This helps show all the circuit regions that contributed to this deferred constraint
		for idx, originPC := range knownOrigins {
			sample := &profile.Sample{Value: []int64{1}}

			// Add label to indicate the origin source
			if len(originLabels) > 1 {
				// Multiple origins - add label to distinguish
				sample.Label = map[string][]string{
					"origin": {originLabels[idx]},
				}
			}

			// Build the location stack from the origin
			frames := runtime.CallersFrames(originPC)
			for {
				frame, more := frames.Next()

				if strings.Contains(frame.Function, "frontend.parseCircuit") {
					break
				}

				// Don't filter anonymous functions for origin stacks - they may be important
				// for understanding where in user code the variable was created

				// filter internal builder functions
				if filterSCSPrivateFunc(frame.Function) || filterR1CSPrivateFunc(frame.Function) {
					if more {
						continue
					}
					break
				}

				frame.Function = strings.ReplaceAll(frame.Function, "[...]", "[T]")

				sample.Location = append(sample.Location, session.getDeferredLocation(&frame))

				if !more {
					break
				}
				if strings.HasSuffix(frame.Function, ".Define") {
					session.onceSetName.Do(func() {
						fe := strings.Split(frame.Function, "/")
						circuitName := strings.TrimSuffix(fe[len(fe)-1], ".Define")
						session.deferredPprof.Mapping = []*profile.Mapping{
							{ID: 1, File: circuitName},
						}
					})
				}
			}

			// Only add sample if it has at least one location
			if len(sample.Location) > 0 {
				session.deferredPprof.Sample = append(session.deferredPprof.Sample, sample)
			}
		}
	}
}

// getOriginLabel extracts a short label from a stack trace for labeling purposes
func getOriginLabel(pc []uintptr) string {
	if len(pc) == 0 {
		return "unknown"
	}
	frames := runtime.CallersFrames(pc[:1])
	frame, _ := frames.Next()
	// Extract just the function name without package path
	parts := strings.Split(frame.Function, "/")
	funcName := parts[len(parts)-1]
	// Remove generics markers
	funcName = strings.ReplaceAll(funcName, "[...]", "[T]")
	return funcName
}

func filterSCSPrivateFunc(f string) bool {
	const scsPrefix = "github.com/consensys/gnark/frontend/cs/scs.(*builder)."
	if strings.HasPrefix(f, scsPrefix) && len(f) > len(scsPrefix) {
		// filter plonk frontend private APIs from the trace.
		c := []rune(f)[len(scsPrefix)]
		if unicode.IsLower(c) {
			return true
		}
	}
	return false
}

func filterR1CSPrivateFunc(f string) bool {
	const r1csPrefix = "github.com/consensys/gnark/frontend/cs/r1cs.(*builder)."
	if strings.HasPrefix(f, r1csPrefix) && len(f) > len(r1csPrefix) {
		// filter r1cs frontend private APIs from the trace.
		c := []rune(f)[len(r1csPrefix)]
		if unicode.IsLower(c) {
			return true
		}
	}
	return false
}
