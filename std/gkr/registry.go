package gkr

import (
	"fmt"
	"github.com/consensys/gnark/std/gkr/internal"
	"sync"
)

var (
	gates     = make(map[string]*Gate)
	gatesLock sync.Mutex
)

type registerGateSettings struct {
	solvableVar               int
	noSolvableVarVerification bool
	noDegreeVerification      bool
	degree                    int
}

// TODO @Tabaie once GKR is moved to gnark, use the same options/settings type for all curves, obviating this

type RegisterGateOption func(*registerGateSettings)

// WithSolvableVar gives the index of a variable whose value can be uniquely determined from that of the other variables along with the gate's output.
// RegisterGate will return an error if it cannot verify that this claim is correct.
func WithSolvableVar(solvableVar int) RegisterGateOption {
	return func(settings *registerGateSettings) {
		settings.solvableVar = solvableVar
	}
}

// WithUnverifiedSolvableVar sets the index of a variable whose value can be uniquely determined from that of the other variables along with the gate's output.
// RegisterGate will not verify that the given index is correct.
func WithUnverifiedSolvableVar(solvableVar int) RegisterGateOption {
	return func(settings *registerGateSettings) {
		settings.noSolvableVarVerification = true
		settings.solvableVar = solvableVar
	}
}

// WithNoSolvableVar sets the gate as having no variable whose value can be uniquely determined from that of the other variables along with the gate's output.
// RegisterGate will not check the correctness of this claim.
func WithNoSolvableVar() RegisterGateOption {
	return func(settings *registerGateSettings) {
		settings.solvableVar = -1
		settings.noSolvableVarVerification = true
	}
}

// WithUnverifiedDegree sets the degree of the gate. RegisterGate will not verify that the given degree is correct.
func WithUnverifiedDegree(degree int) RegisterGateOption {
	return func(settings *registerGateSettings) {
		settings.noDegreeVerification = true
		settings.degree = degree
	}
}

// WithDegree sets the degree of the gate. RegisterGate will return an error if the degree is not correct.
func WithDegree(degree int) RegisterGateOption {
	return func(settings *registerGateSettings) {
		settings.degree = degree
	}
}

// RegisterGate creates a gate object and stores it in the gates registry
// name is a human-readable name for the gate
// f is the polynomial function defining the gate
// nbIn is the number of inputs to the gate
// NB! This package generally expects certain properties of the gate to be invariant across all curves.
// In particular the degree is computed and verified over BN254. If the leading coefficient is divided by
// the curve's order, the degree will be computed incorrectly.
func RegisterGate(name string, f GateFunction, nbIn int, options ...RegisterGateOption) error {
	s := registerGateSettings{degree: -1, solvableVar: -1}
	for _, option := range options {
		option(&s)
	}

	frF := internal.ToBn254GateFunction(f)

	if s.degree == -1 { // find a degree
		if s.noDegreeVerification {
			panic("invalid settings")
		}
		const maxAutoDegreeBound = 32
		var err error
		if s.degree, err = frF.FindDegree(maxAutoDegreeBound, nbIn); err != nil {
			return fmt.Errorf("for gate %s: %v", name, err)
		}
	} else {
		if !s.noDegreeVerification { // check that the given degree is correct
			if err := frF.VerifyDegree(s.degree, nbIn); err != nil {
				return fmt.Errorf("for gate %s: %v", name, err)
			}
		}
	}

	if s.solvableVar == -1 {
		if !s.noSolvableVarVerification { // find a solvable variable
			s.solvableVar = frF.FindSolvableVar(nbIn)
		}
	} else {
		// solvable variable given
		if !s.noSolvableVarVerification && !frF.IsVarSolvable(s.solvableVar, nbIn) {
			return fmt.Errorf("cannot verify the solvability of variable %d in gate %s", s.solvableVar, name)
		}
	}

	gatesLock.Lock()
	defer gatesLock.Unlock()
	gates[name] = &Gate{Evaluate: f, nbIn: nbIn, degree: s.degree, solvableVar: s.solvableVar}
	return nil
}

func GetGate(name string) *Gate {
	gatesLock.Lock()
	defer gatesLock.Unlock()
	return gates[name]
}
