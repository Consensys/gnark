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

// Register creates a gate object and stores it in the gates registry
// name is a human-readable name for the gate
// f is the polynomial function defining the gate
// nbIn is the number of inputs to the gate
func Register(f gkr.GateFunction, nbIn int, options ...RegisterOption) error {
	s := registerSettings{degree: -1, solvableVar: -1, name: getFunctionName(f), curves: []ecc.ID{ecc.BN254}}
	for _, option := range options {
		option(&s)
	}

	for _, curve := range s.curves {
		var (
			isAdditiveF   isAdditive
			findDegreeF   findDegree
			verifyDegreeF verifyDegree
		)

		switch curve {
		case ecc.BLS12_377:
			isAdditiveF = bls12377.IsGateFunctionAdditive
			findDegreeF = bls12377.FindGateFunctionDegree
			verifyDegreeF = bls12377.VerifyGateFunctionDegree
		case ecc.BLS12_381:
			isAdditiveF = bls12381.IsGateFunctionAdditive
			findDegreeF = bls12381.FindGateFunctionDegree
			verifyDegreeF = bls12381.VerifyGateFunctionDegree
		case ecc.BLS24_315:
			isAdditiveF = bls24315.IsGateFunctionAdditive
			findDegreeF = bls24315.FindGateFunctionDegree
			verifyDegreeF = bls24315.VerifyGateFunctionDegree
		case ecc.BLS24_317:
			isAdditiveF = bls24317.IsGateFunctionAdditive
			findDegreeF = bls24317.FindGateFunctionDegree
			verifyDegreeF = bls24317.VerifyGateFunctionDegree
		case ecc.BN254:
			isAdditiveF = bn254.IsGateFunctionAdditive
			findDegreeF = bn254.FindGateFunctionDegree
			verifyDegreeF = bn254.VerifyGateFunctionDegree
		case ecc.BW6_633:
			isAdditiveF = bw6633.IsGateFunctionAdditive
			findDegreeF = bw6633.FindGateFunctionDegree
			verifyDegreeF = bw6633.VerifyGateFunctionDegree
		case ecc.BW6_761:
			isAdditiveF = bw6761.IsGateFunctionAdditive
			findDegreeF = bw6761.FindGateFunctionDegree
			verifyDegreeF = bw6761.VerifyGateFunctionDegree
		default:
			return fmt.Errorf("unsupported curve %s", curve)
		}

		if s.degree == -1 { // find a degree
			if s.noDegreeVerification {
				panic("invalid settings")
			}
			const maxAutoDegreeBound = 32
			var err error
			if s.degree, err = findDegreeF(f, maxAutoDegreeBound, nbIn); err != nil {
				return fmt.Errorf("for gate %s: %v", s.name, err)
			}
		} else {
			if !s.noDegreeVerification { // check that the given degree is correct
				if err := verifyDegreeF(f, s.degree, nbIn); err != nil {
					return fmt.Errorf("for gate %s: %v", s.name, err)
				}
			}
		}

		if s.solvableVar == -1 {
			if !s.noSolvableVarVerification { // find a solvable variable
				s.solvableVar = findSolvableVar(f, isAdditiveF, nbIn)
			}
		} else {
			// solvable variable given
			if !s.noSolvableVarVerification && !isVarSolvable(f, isAdditiveF, s.solvableVar, nbIn) {
				return fmt.Errorf("cannot verify the solvability of variable %d in gate %s", s.solvableVar, s.name)
			}
		}

	}

	gatesLock.Lock()
	defer gatesLock.Unlock()
	gates[s.name] = gkrtypes.New(f, nbIn, s.degree, s.solvableVar)
	return nil
}

func Get(name gkr.GateName) *gkrtypes.Gate {
	gatesLock.Lock()
	defer gatesLock.Unlock()
	return gates[name]
}

// getFunctionName copied from solver.GetHintName
func getFunctionName(fn gkr.GateFunction) gkr.GateName {
	fnptr := reflect.ValueOf(fn).Pointer()
	name := runtime.FuncForPC(fnptr).Name()
	return gkr.GateName(newToOldStyle(name))
}

func newToOldStyle(name string) string {
	return string(newStyleAnonRe.ReplaceAll([]byte(name), []byte("${pkgname}glob.${funcname}")))
}

var newStyleAnonRe = regexp.MustCompile(`^(?P<pkgname>.*\.)init(?P<funcname>\.func\d+)$`)

type isAdditive func(f gkr.GateFunction, i int, nbIn int) bool
type findDegree func(f gkr.GateFunction, max, nbIn int) (int, error)
type verifyDegree func(f gkr.GateFunction, claimedDegree, nbIn int) error

// FindSolvableVar returns the index of a variable whose value can be uniquely determined from that of the other variables along with the gate's output.
// It returns -1 if it fails to find one.
// nbIn is the number of inputs to the gate
func findSolvableVar(f gkr.GateFunction, isAdditiveF isAdditive, nbIn int) int {
	for i := range nbIn {
		if isAdditiveF(f, i, nbIn) {
			return i
		}
	}
	return -1
}

// IsVarSolvable returns whether claimedSolvableVar is a variable whose value can be uniquely determined from that of the other variables along with the gate's output.
// It returns false if it fails to verify this claim.
// nbIn is the number of inputs to the gate.
func isVarSolvable(f gkr.GateFunction, isAdditiveF isAdditive, claimedSolvableVar, nbIn int) bool {
	return isAdditiveF(f, claimedSolvableVar, nbIn)
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
