// Package gkrgates contains the registry of GKR gates.
package gkrgates

import (
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"sync"

	"github.com/consensys/gnark"
	"github.com/consensys/gnark-crypto/ecc"

	bls12377 "github.com/consensys/gnark/internal/gkr/bls12-377"
	bls12381 "github.com/consensys/gnark/internal/gkr/bls12-381"
	bn254 "github.com/consensys/gnark/internal/gkr/bn254"
	bw6761 "github.com/consensys/gnark/internal/gkr/bw6-761"
	"github.com/consensys/gnark/internal/gkr/gkrtypes"

	"github.com/consensys/gnark/std/gkrapi/gkr"
)

var (
	gates     = make(map[gkr.GateName]*gkrtypes.Gate)
	gatesLock sync.Mutex
)

type registerSettings struct {
	solvableVar               int
	noSolvableVarVerification bool
	noDegreeVerification      bool
	degree                    int
	name                      gkr.GateName
	curves                    []ecc.ID
}

type RegisterOption func(*registerSettings) error

// WithSolvableVar gives the index of a variable whose value can be uniquely determined from that of the other variables along with the gate's output.
// RegisterGate will return an error if it cannot verify that this claim is correct.
func WithSolvableVar(solvableVar int) RegisterOption {
	return func(settings *registerSettings) error {
		if settings.solvableVar != -1 {
			return fmt.Errorf("solvable variable already set to %d", settings.solvableVar)
		}
		if settings.noSolvableVarVerification {
			return errors.New("solvable variable already set to NONE")
		}
		settings.solvableVar = solvableVar
		return nil
	}
}

// WithUnverifiedSolvableVar sets the index of a variable whose value can be uniquely determined from that of the other variables along with the gate's output.
// RegisterGate will not verify that the given index is correct.
func WithUnverifiedSolvableVar(solvableVar int) RegisterOption {
	return func(settings *registerSettings) error {
		if settings.solvableVar != -1 {
			return fmt.Errorf("solvable variable already set to %d", settings.solvableVar)
		}
		if settings.noSolvableVarVerification {
			return errors.New("solvable variable already set to NONE")
		}
		settings.noSolvableVarVerification = true
		settings.solvableVar = solvableVar
		return nil
	}
}

// WithNoSolvableVar sets the gate as having no variable whose value can be uniquely determined from that of the other variables along with the gate's output.
// RegisterGate will not check the correctness of this claim.
func WithNoSolvableVar() RegisterOption {
	return func(settings *registerSettings) error {
		if settings.solvableVar != -1 {
			return fmt.Errorf("solvable variable already set to %d", settings.solvableVar)
		}
		if settings.noSolvableVarVerification {
			return errors.New("solvable variable already set to NONE")
		}
		settings.solvableVar = -1
		settings.noSolvableVarVerification = true
		return nil
	}
}

// WithUnverifiedDegree sets the degree of the gate. RegisterGate will not verify that the given degree is correct.
func WithUnverifiedDegree(degree int) RegisterOption {
	return func(settings *registerSettings) error {
		if settings.degree != -1 {
			return fmt.Errorf("gate degree already set to %d", settings.degree)
		}
		settings.noDegreeVerification = true
		settings.degree = degree
		return nil
	}
}

// WithDegree sets the degree of the gate. RegisterGate will return an error if the degree is not correct.
func WithDegree(degree int) RegisterOption {
	return func(settings *registerSettings) error {
		if settings.degree != -1 {
			return fmt.Errorf("gate degree already set to %d", settings.degree)
		}
		settings.degree = degree
		return nil
	}
}

// WithName can be used to set a human-readable name for the gate.
func WithName(name gkr.GateName) RegisterOption {
	return func(settings *registerSettings) error {
		if name == "" {
			return errors.New("gate name must not be empty")
		}
		if settings.name != "" {
			return fmt.Errorf("gate name already set to \"%s\"", settings.name)
		}
		settings.name = name
		return nil
	}
}

// WithCurves determines on which curves the gate is validated and allowed to be used.
// By default, the gate can be used on any curve, and is only validated on BN254.
// This works for most gates, unless the leading coefficient is divided by
// the curve's order, in which case the degree will be computed incorrectly.
func WithCurves(curves ...ecc.ID) RegisterOption {
	return func(settings *registerSettings) error {
		if settings.curves != nil {
			return errors.New("gate curves already set")
		}
		settings.curves = curves
		return nil
	}
}

// Register creates a gate object and stores it in the gates registry.
// - name is a human-readable name for the gate.
// - f is the polynomial function defining the gate.
// - nbIn is the number of inputs to the gate.
//
// If the gate is already registered, it will return false and no error.
func Register(f gkr.GateFunction, nbIn int, options ...RegisterOption) error {
	s := registerSettings{degree: -1, solvableVar: -1}
	for _, option := range options {
		if err := option(&s); err != nil {
			return err
		}
	}
	if s.name == "" {
		s.name = GetDefaultGateName(f)
	}

	curvesForTesting := s.curves
	allowedCurves := s.curves
	if len(curvesForTesting) == 0 {
		// no restriction on curves, but only test on BN254
		curvesForTesting = []ecc.ID{ecc.BN254}
		allowedCurves = gnark.Curves()
	}

	compiled, err := gkrtypes.CompileGateFunction(f, nbIn)
	if err != nil {
		return err
	}

	gatesLock.Lock()
	defer gatesLock.Unlock()

	if g, ok := gates[s.name]; ok {
		// gate already registered
		if g.NbIn() != nbIn {
			return fmt.Errorf("gate \"%s\" already registered with a different number of inputs (%d != %d)", s.name, g.NbIn(), nbIn)
		}

		for _, curve := range curvesForTesting {
			gateVer, err := newGateTester(g.Compiled(), g.NbIn(), curve)
			if err != nil {
				return err
			}
			if !gateVer.Equal(compiled) {
				return fmt.Errorf("mismatch with already registered gate \"%s\" (degree %d) over curve %s", s.name, g.Degree(), curve)
			}
		}

		return nil // gate already registered
	}

	for _, curve := range curvesForTesting {
		t, err := newGateTester(compiled, nbIn, curve)
		if err != nil {
			return err
		}

		if s.degree == -1 { // find a degree
			if s.noDegreeVerification {
				panic("invalid settings")
			}
			const maxAutoDegreeBound = 32
			if s.degree, err = t.FindDegree(maxAutoDegreeBound); err != nil {
				return fmt.Errorf("for gate \"%s\": %v", s.name, err)
			}
		} else {
			if !s.noDegreeVerification { // check that the given degree is correct
				if err = t.VerifyDegree(s.degree); err != nil {
					return fmt.Errorf("for gate \"%s\": %v", s.name, err)
				}
			}
		}

		if s.solvableVar == -1 {
			if !s.noSolvableVarVerification { // find a solvable variable
				s.solvableVar = findSolvableVar(t, nbIn)
			}
		} else {
			// solvable variable given
			if !s.noSolvableVarVerification && !isVarSolvable(t, s.solvableVar, nbIn) {
				return fmt.Errorf("cannot verify the solvability of variable %d in gate \"%s\"", s.solvableVar, s.name)
			}
		}

	}

	gates[s.name] = gkrtypes.NewGate(f, compiled, nbIn, s.degree, s.solvableVar, allowedCurves)
	return nil
}

// Get returns a registered gate of the given name.
// If not found, it will panic.
// Gates can be added to the registry through Register.
func Get(name gkr.GateName) *gkrtypes.Gate {
	gatesLock.Lock()
	defer gatesLock.Unlock()
	if gate, ok := gates[name]; ok {
		return gate
	}
	panic(fmt.Sprintf("gate \"%s\" not found", name))
}

type gateTester interface {
	IsAdditive(varIndex int) bool
	FindDegree(max int) (int, error)
	VerifyDegree(claimedDegree int) error
	Equal(other *gkrtypes.CompiledGate) bool
}

func newGateTester(g *gkrtypes.CompiledGate, nbIn int, curve ecc.ID) (gateTester, error) {

	switch curve {
	case ecc.BLS12_377:
		return bls12377.NewGateTester(g, nbIn), nil
	case ecc.BLS12_381:
		return bls12381.NewGateTester(g, nbIn), nil
	case ecc.BN254:
		return bn254.NewGateTester(g, nbIn), nil
	case ecc.BW6_761:
		return bw6761.NewGateTester(g, nbIn), nil
	}
	return nil, fmt.Errorf("unsupported curve %s", curve)
}

// GetDefaultGateName provides a standardized name for a gate function, depending on its package and name.
// NB: For anonymous functions, the name is the same no matter the implicit arguments provided.
func GetDefaultGateName(fn gkr.GateFunction) gkr.GateName {
	fnptr := reflect.ValueOf(fn).Pointer()
	return gkr.GateName(runtime.FuncForPC(fnptr).Name())
}

// findSolvableVar returns the index of a variable whose value can be uniquely determined from that of the other variables along with the gate's output.
// It returns -1 if it fails to find one.
// nbIn is the number of inputs to the gate
func findSolvableVar(t gateTester, nbIn int) int {
	for i := range nbIn {
		if t.IsAdditive(i) {
			return i
		}
	}
	return -1
}

// isVarSolvable returns whether claimedSolvableVar is a variable whose value can be uniquely determined from that of the other variables along with the gate's output.
// It returns false if it fails to verify this claim.
// nbIn is the number of inputs to the gate.
func isVarSolvable(t gateTester, claimedSolvableVar, nbIn int) bool {
	return t.IsAdditive(claimedSolvableVar)
}

func init() {
	// register some basic gates
	gatesLock.Lock()

	gates[gkr.Identity] = gkrtypes.Identity()
	gates[gkr.Add2] = gkrtypes.Add2()
	gates[gkr.Sub2] = gkrtypes.Sub2()
	gates[gkr.Neg] = gkrtypes.Neg()
	gates[gkr.Mul2] = gkrtypes.Mul2()

	gatesLock.Unlock()
}
