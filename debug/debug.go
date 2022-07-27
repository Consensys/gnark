package debug

import (
	"errors"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

type StackLine struct {
	Line uint32
	File string
}

// ParseStack parses a stack as stored in a log entry and return readable data
func ParseStack(stack []uint64, stackPaths map[uint32]string) ([]StackLine, error) {
	r := make([]StackLine, len(stack))

	for i, s := range stack {
		pID := uint32(s >> 32)
		line := uint32(s)
		path, ok := stackPaths[pID]
		if !ok {
			return nil, errors.New("missing stack path in stackPaths map")
		}
		r[i] = StackLine{Line: line, File: path}
	}

	return r, nil
}

func Stack() string {
	var sbb strings.Builder
	WriteStack(&sbb)
	return sbb.String()
}

func WriteStack(sbb *strings.Builder, forceClean ...bool) {
	// derived from: https://golang.org/pkg/runtime/#example_Frames
	// we stop when func name == Define as it is where the gnark circuit code should start

	// Ask runtime.Callers for up to 10 pcs
	pc := make([]uintptr, 10)
	n := runtime.Callers(3, pc)
	if n == 0 {
		// No pcs available. Stop now.
		// This can happen if the first argument to runtime.Callers is large.
		return
	}
	pc = pc[:n] // pass only valid pcs to runtime.CallersFrames
	frames := runtime.CallersFrames(pc)
	// Loop to get frames.
	// A fixed number of pcs can expand to an indefinite number of Frames.
	for {
		frame, more := frames.Next()
		fe := strings.Split(frame.Function, "/")
		function := fe[len(fe)-1]
		file := frame.File

		if !Debug || (len(forceClean) > 1 && forceClean[0]) {
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
			file = filepath.Base(file)
		}

		sbb.WriteString(function)
		sbb.WriteByte('\n')
		sbb.WriteByte('\t')
		sbb.WriteString(file)
		sbb.WriteByte(':')
		sbb.WriteString(strconv.Itoa(frame.Line))
		sbb.WriteByte('\n')
		if !more {
			break
		}
		if strings.HasSuffix(function, "Define") {
			break
		}
	}
}
