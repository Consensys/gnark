package gkr

import (
	"fmt"
	"sync"

	"github.com/consensys/gnark/frontend"
)

type GateName string

var (
	gates     = make(map[GateName]*Gate)
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
func RegisterGate(name GateName, f GateFunction, nbIn int, options ...RegisterGateOption) error {
	s := registerGateSettings{degree: -1, solvableVar: -1}
	for _, option := range options {
		option(&s)
	}

	frF := toBn254GateFunction(f)

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

func GetGate(name GateName) *Gate {
	gatesLock.Lock()
	defer gatesLock.Unlock()
	return gates[name]
}

const (
	Identity GateName = "identity" // Identity gate: x -> x
	Add2     GateName = "add2"     // Add2 gate: (x, y) -> x + y
	Sub2     GateName = "sub2"     // Sub2 gate: (x, y) -> x - y
	Neg      GateName = "neg"      // Neg gate: x -> -x
	Mul2     GateName = "mul2"     // Mul2 gate: (x, y) -> x * y
)

func init() {
	panicIfError(RegisterGate(Mul2, func(api GateAPI, x ...frontend.Variable) frontend.Variable {
		return api.Mul(x[0], x[1])
	}, 2, WithUnverifiedDegree(2), WithNoSolvableVar()))
	panicIfError(RegisterGate(Add2, func(api GateAPI, x ...frontend.Variable) frontend.Variable {
		return api.Add(x[0], x[1])
	}, 2, WithUnverifiedDegree(1), WithUnverifiedSolvableVar(0)))
	panicIfError(RegisterGate(Identity, func(api GateAPI, x ...frontend.Variable) frontend.Variable {
		return x[0]
	}, 1, WithUnverifiedDegree(1), WithUnverifiedSolvableVar(0)))
	panicIfError(RegisterGate(Neg, func(api GateAPI, x ...frontend.Variable) frontend.Variable {
		return api.Neg(x[0])
	}, 1, WithUnverifiedDegree(1), WithUnverifiedSolvableVar(0)))
	panicIfError(RegisterGate(Sub2, func(api GateAPI, x ...frontend.Variable) frontend.Variable {
		return api.Sub(x[0], x[1])
	}, 2, WithUnverifiedDegree(1), WithUnverifiedSolvableVar(0)))
}
