package frontend

import (
	"fmt"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/internal/backend/compiled"
)

// ID defines a unique identifier for a frontend.
type ID uint16

const (
	UNKNOWN ID = iota
	R1CS
	PLONK
)

func (id ID) String() string {
	switch id {
	case R1CS:
		return "R1CS"
	case PLONK:
		return "PLONK"
	default:
		return "unknown"
	}
}

// Compiler compiles a circuit into a frontend-specific constraint system.
type Compiler func(curve ecc.ID, circuit Circuit) (compiled.ConstraintSystem, error)

var (
	systems  = make(map[ID]Compiler)
	systemsM sync.RWMutex
)

// RegisterCompiler registers a compiler c for a frontend f. It is an error to
// assign multiple compilers to a single frontend and the method panics.
func RegisterCompiler(f ID, c Compiler) {
	if f == UNKNOWN {
		panic("can not assign compiler to unknown frontend")
	}
	systemsM.Lock()
	defer systemsM.Unlock()
	if _, ok := systems[f]; ok {
		panic(fmt.Sprintf("double compiler registration for frontend '%s'", f))
	}
	systems[f] = c
}

var (
	backends  = make(map[backend.ID]ID)
	backendsM sync.RWMutex
)

// RegisterFrontend registers a frontend f for a backend b. This registration
// ensures that a correct frontend system is chosen for a specific backend when
// compiling a circuit. The method does not check that the compiler for that
// frontend is already registered and the compiler is looked up during compile
// time. It is an error to double-assign a frontend to a single backend and the
// mehod panics.
func RegisterFrontend(b backend.ID, f ID) {
	if b == backend.UNKNOWN {
		panic("can not assign frontend to unknown backend")
	}
	if f == UNKNOWN {
		panic("can not assign unknown frontend to any backend")
	}
	// a frontend may be assigned before a compiler to that frontend is
	// registered. we perform frontend compiler lookup during compilation.
	backendsM.Lock()
	defer backendsM.Unlock()
	if _, ok := backends[b]; ok {
		panic(fmt.Sprintf("double frontend registration for backend '%s'", b))
	}
	backends[b] = f
}
