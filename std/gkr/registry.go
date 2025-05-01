package gkr

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/internal/gkr"
	bls12377 "github.com/consensys/gnark/internal/gkr/bls12-377"
	bls12381 "github.com/consensys/gnark/internal/gkr/bls12-381"
	bls24315 "github.com/consensys/gnark/internal/gkr/bls24-315"
	bls24317 "github.com/consensys/gnark/internal/gkr/bls24-317"
	bn254 "github.com/consensys/gnark/internal/gkr/bn254"
	bw6633 "github.com/consensys/gnark/internal/gkr/bw6-633"
	bw6761 "github.com/consensys/gnark/internal/gkr/bw6-761"
	"sync"

	"github.com/consensys/gnark/frontend"
)

type GateName string

var (
	gates     = make(map[GateName]*Gate)
	gatesLock sync.Mutex
)

// TODO @Tabaie once GKR is moved to gnark, use the same options/settings type for all curves, obviating this

type RegisterGateOption interface {
	apply(*gkr.RegisterGateSettings)
}

type registerGateOption func(*gkr.RegisterGateSettings)

func (f registerGateOption) apply(settings *gkr.RegisterGateSettings) {
	f(settings)
}

type gateConcreteImplOption interface {
	RegisterGateOption
	isConcreteImpl()
}

type gateConcreteImpl struct {
	impl any
}

func (g gateConcreteImpl) apply(settings *gkr.RegisterGateSettings) {
	settings.PerCurveImpls = append(settings.PerCurveImpls, g.impl)
}

func (g gateConcreteImpl) isConcreteImpl() {}

// WithSolvableVar gives the index of a variable whose value can be uniquely determined from that of the other variables along with the gate's output.
// RegisterGate will return an error if it cannot verify that this claim is correct.
func WithSolvableVar(solvableVar int) RegisterGateOption {
	return registerGateOption(func(settings *gkr.RegisterGateSettings) {
		settings.SolvableVar = solvableVar
	})
}

// WithUnverifiedSolvableVar sets the index of a variable whose value can be uniquely determined from that of the other variables along with the gate's output.
// RegisterGate will not verify that the given index is correct.
func WithUnverifiedSolvableVar(solvableVar int) RegisterGateOption {
	return registerGateOption(func(settings *gkr.RegisterGateSettings) {
		settings.NoSolvableVarVerification = true
		settings.SolvableVar = solvableVar
	})
}

// WithNoSolvableVar sets the gate as having no variable whose value can be uniquely determined from that of the other variables along with the gate's output.
// RegisterGate will not check the correctness of this claim.
func WithNoSolvableVar() RegisterGateOption {
	return registerGateOption(func(settings *gkr.RegisterGateSettings) {
		settings.SolvableVar = -1
		settings.NoSolvableVarVerification = true
	})
}

// WithUnverifiedDegree sets the degree of the gate. RegisterGate will not verify that the given degree is correct.
func WithUnverifiedDegree(degree int) RegisterGateOption {
	return registerGateOption(func(settings *gkr.RegisterGateSettings) {
		settings.NoDegreeVerification = true
		settings.Degree = degree
	})
}

// WithDegree sets the degree of the gate. RegisterGate will return an error if the degree is not correct.
func WithDegree(degree int) RegisterGateOption {
	return registerGateOption(func(settings *gkr.RegisterGateSettings) {
		settings.Degree = degree
	})
}

// WithBls12377Impl provides a concrete implementation of the gate for the BLS12-377 curve.
func WithBls12377Impl(f bls12377.GateFunction) RegisterGateOption {
	return gateConcreteImpl{func(settings *gkr.RegisterGateSettings) {
		settings.PerCurveImpls = append(settings.PerCurveImpls, f)
	}}
}

// WithBls12381Impl provides a concrete implementation of the gate for the BLS12-381 curve.
func WithBls12381Impl(f bls12381.GateFunction) RegisterGateOption {
	return gateConcreteImpl{func(settings *gkr.RegisterGateSettings) {
		settings.PerCurveImpls = append(settings.PerCurveImpls, f)
	}}
}

// WithBls24315Impl provides a concrete implementation of the gate for the BLS24-315 curve.
func WithBls24315Impl(f bls24315.GateFunction) RegisterGateOption {
	return gateConcreteImpl{func(settings *gkr.RegisterGateSettings) {
		settings.PerCurveImpls = append(settings.PerCurveImpls, f)
	}}
}

// WithBls24317Impl provides a concrete implementation of the gate for the BLS24-317 curve.
func WithBls24317Impl(f bls24317.GateFunction) RegisterGateOption {
	return gateConcreteImpl{func(settings *gkr.RegisterGateSettings) {
		settings.PerCurveImpls = append(settings.PerCurveImpls, f)
	}}
}

// WithBn254Impl provides a concrete implementation of the gate for the BN254 curve.
func WithBn254Impl(f bn254.GateFunction) RegisterGateOption {
	return gateConcreteImpl{func(settings *gkr.RegisterGateSettings) {
		settings.PerCurveImpls = append(settings.PerCurveImpls, f)
	}}
}

// WithBw6633Impl provides a concrete implementation of the gate for the BW6-633 curve.
func WithBw6633Impl(f bw6633.GateFunction) RegisterGateOption {
	return gateConcreteImpl{func(settings *gkr.RegisterGateSettings) {
		settings.PerCurveImpls = append(settings.PerCurveImpls, f)
	}}
}

// WithBw6761Impl provides a concrete implementation of the gate for the BW6-761 curve.
func WithBw6761Impl(f bw6761.GateFunction) RegisterGateOption {
	return gateConcreteImpl{func(settings *gkr.RegisterGateSettings) {
		settings.PerCurveImpls = append(settings.PerCurveImpls, f)
	}}
}

// RegisterGate creates a gate object and stores it in the gates registry
// name is a human-readable name for the gate
// f is the polynomial function defining the gate
// nbIn is the number of inputs to the gate
// concreteImplementation is a function that implements the gate for a specific curve. More can be added as options as well.
// NB! This package generally expects certain properties of the gate to be invariant across all curves.
// In particular the degree is computed and verified over BN254. If the leading coefficient is divided by
// the curve's order, the degree will be computed incorrectly.
func RegisterGate(name GateName, f GateFunction, nbIn int, concreteImplementation gateConcreteImplOption, options ...RegisterGateOption) error {
	s := gkr.RegisterGateSettings{Degree: -1, SolvableVar: -1}
	concreteImplementation.apply(&s)
	for _, option := range options {
		option.apply(&s)
	}

	frF := ToBn254GateFunction(f)

	if s.Degree == -1 { // find a degree
		if s.NoDegreeVerification {
			panic("invalid settings")
		}
		const maxAutoDegreeBound = 32
		var err error
		if s.Degree, err = frF.FindDegree(maxAutoDegreeBound, nbIn); err != nil {
			return fmt.Errorf("for gate %s: %v", name, err)
		}
	} else {
		if !s.NoDegreeVerification { // check that the given degree is correct
			if err := frF.VerifyDegree(s.Degree, nbIn); err != nil {
				return fmt.Errorf("for gate %s: %v", name, err)
			}
		}
	}

	if s.SolvableVar == -1 {
		if !s.NoSolvableVarVerification { // find a solvable variable
			s.SolvableVar = frF.FindSolvableVar(nbIn)
		}
	} else {
		// solvable variable given
		if !s.NoSolvableVarVerification && !frF.IsVarSolvable(s.SolvableVar, nbIn) {
			return fmt.Errorf("cannot verify the solvability of variable %d in gate %s", s.SolvableVar, name)
		}
	}

	for _, impl := range s.PerCurveImpls {
		switch impl := impl.(type) {
		case bls12377.GateFunction:
			if err := bls12377.RegisterGate(name, f, nbIn, impl, s.Degree, s.SolvableVar); err != nil {
				return fmt.Errorf("for gate %s: %v", name, err)
			}
		case bls12381.GateFunction:
			if err := bls12381.RegisterGate(name, f, nbIn, impl, s.Degree, s.SolvableVar); err != nil {
				return fmt.Errorf("for gate %s: %v", name, err)
			}
		case bls24315.GateFunction:
			if err := bls24315.RegisterGate(name, f, nbIn, impl, s.Degree, s.SolvableVar); err != nil {
				return fmt.Errorf("for gate %s: %v", name, err)
			}
		case bls24317.GateFunction:
			if err := bls24317.RegisterGate(name, f, nbIn, impl, s.Degree, s.SolvableVar); err != nil {
				return fmt.Errorf("for gate %s: %v", name, err)
			}
		case bn254.GateFunction:
			if err := bn254.RegisterGate(name, f, nbIn, impl, s.Degree, s.SolvableVar); err != nil {
				return fmt.Errorf("for gate %s: %v", name, err)
			}
		case bw6633.GateFunction:
			if err := bw6633.RegisterGate(name, f, nbIn, impl, s.Degree, s.SolvableVar); err != nil {
				return fmt.Errorf("for gate %s: %v", name, err)
			}
		case bw6761.GateFunction:
			if err := bw6761.RegisterGate(name, f, nbIn, impl, s.Degree, s.SolvableVar); err != nil {
				return fmt.Errorf("for gate %s: %v", name, err)
			}
		default:
			panic(fmt.Sprintf("unsupported curve implementation for gate %s", name))
		}
	}

	gatesLock.Lock()
	defer gatesLock.Unlock()
	gates[name] = &Gate{Evaluate: f, nbIn: nbIn, degree: s.Degree, solvableVar: s.SolvableVar}
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
