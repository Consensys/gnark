package debug

import (
	"path/filepath"
	"runtime"
	"strings"
)

type SymbolTable struct {
	Locations  []Location
	Functions  []Function
	mFunctions map[string]int `cbor:"-"` // frame.File+frame.Function to id in Functions
	mLocations map[uint64]int `cbor:"-"` // frame PC to location id in Locations
}

func NewSymbolTable() SymbolTable {
	return SymbolTable{
		mFunctions: map[string]int{},
		mLocations: map[uint64]int{},
	}
}

func (st *SymbolTable) LocationID(frame *runtime.Frame) int {
	lID, ok := st.mLocations[uint64(frame.PC)]
	if !ok {
		// first let's see if we have the function.
		fID, ok := st.mFunctions[frame.File+frame.Function]
		if !ok {
			fe := strings.Split(frame.Function, "/")
			fName := fe[len(fe)-1]
			f := Function{
				Name:       fName,
				SystemName: frame.Function,
				Filename:   frame.File,
			}

			st.Functions = append(st.Functions, f)
			fID = len(st.Functions) - 1
			st.mFunctions[frame.File+frame.Function] = fID
		}

		l := Location{FunctionID: fID, Line: int64(frame.Line)}

		st.Locations = append(st.Locations, l)
		lID = len(st.Locations) - 1
		st.mLocations[uint64(frame.PC)] = lID
	}

	return lID
}

func (st *SymbolTable) CollectStack() []int {
	r := make([]int, 0)
	// derived from: https://golang.org/pkg/runtime/#example_Frames
	// we stop when func name == Define as it is where the gnark circuit code should start

	// Ask runtime.Callers for up to 10 pcs
	pc := make([]uintptr, 20)
	n := runtime.Callers(4, pc)
	if n == 0 {
		// No pcs available. Stop now.
		// This can happen if the first argument to runtime.Callers is large.
		return r
	}
	pc = pc[:n] // pass only valid pcs to runtime.CallersFrames
	frames := runtime.CallersFrames(pc)
	// Loop to get frames.
	// A fixed number of pcs can expand to an indefinite number of Frames.
	for {
		frame, more := frames.Next()
		fe := strings.Split(frame.Function, "/")
		function := fe[len(fe)-1]

		if !Debug {
			if strings.Contains(function, "runtime.gopanic") {
				continue
			}
			if strings.Contains(function, "frontend.(*constraintSystem)") {
				continue
			}
			if strings.Contains(frame.File, "test/engine.go") {
				continue
			}
			if strings.Contains(frame.File, "gnark/frontend") {
				continue
			}
			frame.File = filepath.Base(frame.File)
		}

		r = append(r, st.LocationID(&frame))

		if !more {
			break
		}
		if strings.HasSuffix(function, "Define") {
			break
		}
	}
	return r
}
