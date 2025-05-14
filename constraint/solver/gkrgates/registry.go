// Package gkrgates contains the registry of GKR gates.
package gkrgates

import (
	"fmt"
	"reflect"
	"regexp"
	"runtime"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"

	bls12377 "github.com/consensys/gnark/internal/gkr/bls12-377"
	bls12381 "github.com/consensys/gnark/internal/gkr/bls12-381"
	bls24315 "github.com/consensys/gnark/internal/gkr/bls24-315"
	bls24317 "github.com/consensys/gnark/internal/gkr/bls24-317"
	bn254 "github.com/consensys/gnark/internal/gkr/bn254"
	bw6633 "github.com/consensys/gnark/internal/gkr/bw6-633"
	bw6761 "github.com/consensys/gnark/internal/gkr/bw6-761"
	"github.com/consensys/gnark/internal/gkr/gkrtypes"

	"github.com/consensys/gnark/std/gkr"
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

type RegisterOption func(*registerSettings)

// WithSolvableVar gives the index of a variable whose value can be uniquely determined from that of the other variables along with the gate's output.
// RegisterGate will return an error if it cannot verify that this claim is correct.
func WithSolvableVar(solvableVar int) RegisterOption {
	return func(settings *registerSettings) {
		settings.solvableVar = solvableVar
	}
}

// WithUnverifiedSolvableVar sets the index of a variable whose value can be uniquely determined from that of the other variables along with the gate's output.
// RegisterGate will not verify that the given index is correct.
func WithUnverifiedSolvableVar(solvableVar int) RegisterOption {
	return func(settings *registerSettings) {
		settings.noSolvableVarVerification = true
		settings.solvableVar = solvableVar
	}
}

// WithNoSolvableVar sets the gate as having no variable whose value can be uniquely determined from that of the other variables along with the gate's output.
// RegisterGate will not check the correctness of this claim.
func WithNoSolvableVar() RegisterOption {
	return func(settings *registerSettings) {
		settings.solvableVar = -1
		settings.noSolvableVarVerification = true
	}
}

// WithUnverifiedDegree sets the degree of the gate. RegisterGate will not verify that the given degree is correct.
func WithUnverifiedDegree(degree int) RegisterOption {
	return func(settings *registerSettings) {
		settings.noDegreeVerification = true
		settings.degree = degree
	}
}

// WithDegree sets the degree of the gate. RegisterGate will return an error if the degree is not correct.
func WithDegree(degree int) RegisterOption {
	return func(settings *registerSettings) {
		settings.degree = degree
	}
}

// WithName can be used to set a human-readable name for the gate.
func WithName(name gkr.GateName) RegisterOption {
	return func(settings *registerSettings) {
		settings.name = name
	}
}

// WithCurves determines which curves the gate is validated on.
// The default is to validate on BN254.
// This works for most gates, unless the leading coefficient is divided by
// the curve's order, in which case the degree will be computed incorrectly.
func WithCurves(curves ...ecc.ID) RegisterOption {
	return func(settings *registerSettings) {
		settings.curves = curves
	}
}

// Register creates a gate object and stores it in the gates registry.
// - name is a human-readable name for the gate.
// - f is the polynomial function defining the gate.
// - nbIn is the number of inputs to the gate.
func Register(f gkr.GateFunction, nbIn int, options ...RegisterOption) error {
	s := registerSettings{degree: -1, solvableVar: -1, name: GetDefaultGateName(f), curves: []ecc.ID{ecc.BN254}}
	for _, option := range options {
		option(&s)
	}

	for _, curve := range s.curves {
		gateVer, err := NewGateVerifier(curve)
		if err != nil {
			return err
		}

		if s.degree == -1 { // find a degree
			if s.noDegreeVerification {
				panic("invalid settings")
			}
			const maxAutoDegreeBound = 32
			var err error
			if s.degree, err = gateVer.findDegree(f, maxAutoDegreeBound, nbIn); err != nil {
				return fmt.Errorf("for gate %s: %v", s.name, err)
			}
		} else {
			if !s.noDegreeVerification { // check that the given degree is correct
				if err = gateVer.verifyDegree(f, s.degree, nbIn); err != nil {
					return fmt.Errorf("for gate %s: %v", s.name, err)
				}
			}
		}

		if s.solvableVar == -1 {
			if !s.noSolvableVarVerification { // find a solvable variable
				s.solvableVar = gateVer.findSolvableVar(f, nbIn)
			}
		} else {
			// solvable variable given
			if !s.noSolvableVarVerification && !gateVer.isVarSolvable(f, s.solvableVar, nbIn) {
				return fmt.Errorf("cannot verify the solvability of variable %d in gate %s", s.solvableVar, s.name)
			}
		}

	}

	gatesLock.Lock()
	defer gatesLock.Unlock()
	gates[s.name] = gkrtypes.NewGate(f, nbIn, s.degree, s.solvableVar)
	return nil
}

func Get(name gkr.GateName) *gkrtypes.Gate {
	gatesLock.Lock()
	defer gatesLock.Unlock()
	return gates[name]
}

type gateVerifier struct {
	isAdditive   func(f gkr.GateFunction, i int, nbIn int) bool
	findDegree   func(f gkr.GateFunction, max, nbIn int) (int, error)
	verifyDegree func(f gkr.GateFunction, claimedDegree, nbIn int) error
}

func NewGateVerifier(curve ecc.ID) (*gateVerifier, error) {
	var (
		o   gateVerifier
		err error
	)
	switch curve {
	case ecc.BLS12_377:
		o.isAdditive = bls12377.IsGateFunctionAdditive
		o.findDegree = bls12377.FindGateFunctionDegree
		o.verifyDegree = bls12377.VerifyGateFunctionDegree
	case ecc.BLS12_381:
		o.isAdditive = bls12381.IsGateFunctionAdditive
		o.findDegree = bls12381.FindGateFunctionDegree
		o.verifyDegree = bls12381.VerifyGateFunctionDegree
	case ecc.BLS24_315:
		o.isAdditive = bls24315.IsGateFunctionAdditive
		o.findDegree = bls24315.FindGateFunctionDegree
		o.verifyDegree = bls24315.VerifyGateFunctionDegree
	case ecc.BLS24_317:
		o.isAdditive = bls24317.IsGateFunctionAdditive
		o.findDegree = bls24317.FindGateFunctionDegree
		o.verifyDegree = bls24317.VerifyGateFunctionDegree
	case ecc.BN254:
		o.isAdditive = bn254.IsGateFunctionAdditive
		o.findDegree = bn254.FindGateFunctionDegree
		o.verifyDegree = bn254.VerifyGateFunctionDegree
	case ecc.BW6_633:
		o.isAdditive = bw6633.IsGateFunctionAdditive
		o.findDegree = bw6633.FindGateFunctionDegree
		o.verifyDegree = bw6633.VerifyGateFunctionDegree
	case ecc.BW6_761:
		o.isAdditive = bw6761.IsGateFunctionAdditive
		o.findDegree = bw6761.FindGateFunctionDegree
		o.verifyDegree = bw6761.VerifyGateFunctionDegree
	default:
		err = fmt.Errorf("unsupported curve %s", curve)
	}
	return &o, err
}

// GetDefaultGateName provides a standardized name for a gate function, depending on its package and name.
// NB: For anonymous functions, the name is the same no matter the implicit arguments provided.
func GetDefaultGateName(fn gkr.GateFunction) gkr.GateName {
	// copied from solver.GetHintName
	fnptr := reflect.ValueOf(fn).Pointer()
	name := runtime.FuncForPC(fnptr).Name()
	return gkr.GateName(newToOldStyle(name))
}

func newToOldStyle(name string) string {
	return string(newStyleAnonRe.ReplaceAll([]byte(name), []byte("${pkgname}glob.${funcname}")))
}

var newStyleAnonRe = regexp.MustCompile(`^(?P<pkgname>.*\.)init(?P<funcname>\.func\d+)$`)

// FindSolvableVar returns the index of a variable whose value can be uniquely determined from that of the other variables along with the gate's output.
// It returns -1 if it fails to find one.
// nbIn is the number of inputs to the gate
func (v *gateVerifier) findSolvableVar(f gkr.GateFunction, nbIn int) int {
	for i := range nbIn {
		if v.isAdditive(f, i, nbIn) {
			return i
		}
	}
	return -1
}

// IsVarSolvable returns whether claimedSolvableVar is a variable whose value can be uniquely determined from that of the other variables along with the gate's output.
// It returns false if it fails to verify this claim.
// nbIn is the number of inputs to the gate.
func (v *gateVerifier) isVarSolvable(f gkr.GateFunction, claimedSolvableVar, nbIn int) bool {
	return v.isAdditive(f, claimedSolvableVar, nbIn)
}

func (v *gateVerifier) VerifyDegree(g *gkrtypes.Gate) error {
	if err := v.verifyDegree(g.Evaluate, g.Degree(), g.NbIn()); err != nil {
		deg, errFind := v.findDegree(g.Evaluate, g.Degree(), g.NbIn())
		if errFind != nil {
			return fmt.Errorf("could not find gate degree: %w\n\tdegree verification error: %w", errFind, errFind)
		}
		return fmt.Errorf("detected degree %d\n\tdegree verification error: %w", deg, errFind)
	}
	return nil
}

func (v *gateVerifier) VerifySolvability(g *gkrtypes.Gate) error {
	if g.SolvableVar() == -1 {
		return nil
	}
	if !v.isVarSolvable(g.Evaluate, g.SolvableVar(), g.NbIn()) {
		return fmt.Errorf("cannot verify the solvability of variable %d", g.SolvableVar())
	}
	return nil
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
