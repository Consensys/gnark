package gkr_poseidon2

import (
	"fmt"
	"sync"

	"github.com/consensys/gnark/constraint/solver/gkrgates"
	"github.com/consensys/gnark/std/gkrapi"
	"github.com/consensys/gnark/std/gkrapi/gkr"

	"github.com/consensys/gnark-crypto/ecc"
	poseidon2Bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/poseidon2"
	"github.com/consensys/gnark/frontend"
)

// extKeyGate applies the external matrix mul, then adds the round key
// because of its symmetry, we don't need to define distinct x1 and x2 versions of it
func extKeyGate(roundKey frontend.Variable) gkr.GateFunction {
	return func(api gkr.GateAPI, x ...frontend.Variable) frontend.Variable {
		if len(x) != 2 {
			panic("expected 2 inputs")
		}
		return api.Add(api.Mul(x[0], 2), x[1], roundKey)
	}
}

// pow4Gate computes a -> a⁴
func pow4Gate(api gkr.GateAPI, x ...frontend.Variable) frontend.Variable {
	if len(x) != 1 {
		panic("expected 1 input")
	}
	y := api.Mul(x[0], x[0])
	y = api.Mul(y, y)

	return y
}

// pow4TimesGate computes a, b -> a⁴ * b
func pow4TimesGate(api gkr.GateAPI, x ...frontend.Variable) frontend.Variable {
	if len(x) != 2 {
		panic("expected 2 input")
	}
	y := api.Mul(x[0], x[0])
	y = api.Mul(y, y)

	return api.Mul(y, x[1])
}

// pow2Gate computes a -> a²
func pow2Gate(api gkr.GateAPI, x ...frontend.Variable) frontend.Variable {
	if len(x) != 1 {
		panic("expected 1 input")
	}
	return api.Mul(x[0], x[0])
}

// pow2TimesGate computes a, b -> a² * b
func pow2TimesGate(api gkr.GateAPI, x ...frontend.Variable) frontend.Variable {
	if len(x) != 2 {
		panic("expected 2 inputs")
	}
	return api.Mul(x[0], x[0], x[1])
}

// for x1, the partial round gates are identical to full round gates
// for x2, the partial round gates are just a linear combination
// TODO @Tabaie try eliminating the x2 partial round gates and have the x1 gates depend on i - rf/2 or so previous x1's

// extGate2 applies the external matrix mul, outputting the second element of the result
func extGate2(api gkr.GateAPI, x ...frontend.Variable) frontend.Variable {
	if len(x) != 2 {
		panic("expected 2 inputs")
	}
	return api.Add(api.Mul(x[1], 2), x[0])
}

// intKeyGate2 applies the internal matrix mul, then adds the round key
func intKeyGate2(roundKey frontend.Variable) gkr.GateFunction {
	return func(api gkr.GateAPI, x ...frontend.Variable) frontend.Variable {
		if len(x) != 2 {
			panic("expected 2 inputs")
		}
		return api.Add(api.Mul(x[1], 3), x[0], roundKey)
	}
}

// intGate2 applies the internal matrix mul. The round key is zero
func intGate2(api gkr.GateAPI, x ...frontend.Variable) frontend.Variable {
	if len(x) != 2 {
		panic("expected 2 inputs")
	}
	return api.Add(api.Mul(x[1], 3), x[0])
}

// extGate applies the first row of the external matrix
func extGate(api gkr.GateAPI, x ...frontend.Variable) frontend.Variable {
	if len(x) != 2 {
		panic("expected 2 inputs")
	}
	return api.Add(api.Mul(x[0], 2), x[1])
}

// extAddGate applies the first row of the external matrix to the first two elements and adds the third
func extAddGate(api gkr.GateAPI, x ...frontend.Variable) frontend.Variable {
	if len(x) != 3 {
		panic("expected 3 inputs")
	}
	return api.Add(api.Mul(x[0], 2), x[1], x[2])
}

type GkrPermutations struct {
	api           frontend.API
	gkrCircuit    *gkrapi.Circuit
	in1, in2, out gkr.Variable
}

// NewGkrPermutations returns an object that can compute the Poseidon2 compression function (currently only for BLS12-377)
// which consists of a permutation along with the input fed forward.
// The correctness of the compression functions is proven using GKR.
// Note that the solver will need the function RegisterGkrGates to be called with the desired curves
func NewGkrPermutations(api frontend.API) *GkrPermutations {
	if api.Compiler().Field().Cmp(ecc.BLS12_377.ScalarField()) != 0 {
		panic("currently only BL12-377 is supported")
	}
	gkrApi, in1, in2, out, err := defineCircuitBls12377()
	if err != nil {
		panic(fmt.Errorf("failed to define GKR circuit: %v", err))
	}
	return &GkrPermutations{
		api:        api,
		gkrCircuit: gkrApi.Compile(api, "MIMC"),
		in1:        in1,
		in2:        in2,
		out:        out,
	}
}

func (p *GkrPermutations) Compress(a, b frontend.Variable) frontend.Variable {
	outs, err := p.gkrCircuit.AddInstance(map[gkr.Variable]frontend.Variable{p.in1: a, p.in2: b})
	if err != nil {
		panic(err)
	}

	return outs[p.out]
}

// defineCircuitBls12377 defines the GKR circuit for the Poseidon2 permutation over BLS12-377
// insLeft and insRight are the inputs to the permutation
// they must be padded to a power of 2
func defineCircuitBls12377() (gkrApi *gkrapi.API, in1, in2, out gkr.Variable, err error) {
	// variable indexes
	const (
		xI = iota
		yI
	)

	if err = registerGatesBls12377(); err != nil {
		return
	}

	// poseidon2 parameters
	gateNamer := newRoundGateNamer(poseidon2Bls12377.GetDefaultParameters())
	rF := poseidon2Bls12377.GetDefaultParameters().NbFullRounds
	rP := poseidon2Bls12377.GetDefaultParameters().NbPartialRounds
	halfRf := rF / 2

	gkrApi = gkrapi.New()

	x := gkrApi.NewInput()
	y := gkrApi.NewInput()

	in1, in2 = x, y // save to feed forward at the end

	// *** helper functions to register and apply gates ***

	// Poseidon2 is a sequence of additions, exponentiations (s-Box), and linear operations
	// but here we group the operations so that every round consists of a degree-1 operation followed by the s-Box
	// this allows for more efficient result sharing among the gates
	// but also breaks the uniformity of the circuit a bit, in that the matrix operation
	// in every round comes from the previous (canonical) round.

	// apply the s-Box to u
	// the s-Box gates: u¹⁷ = (u⁴)⁴ * u
	sBox := func(u gkr.Variable) gkr.Variable {
		v := gkrApi.Gate(pow4Gate, u)           // u⁴
		return gkrApi.Gate(pow4TimesGate, v, u) // u¹⁷
	}

	// apply external matrix multiplication and round key addition
	// round dependent due to the round key
	extKeySBox := func(round, varI int, a, b gkr.Variable) gkr.Variable {
		return sBox(gkrApi.NamedGate(gateNamer.linear(varI, round), a, b))
	}

	// apply external matrix multiplication and round key addition
	// then apply the s-Box
	// for the second variable
	// round independent due to the round key
	intKeySBox2 := func(round int, a, b gkr.Variable) gkr.Variable {
		return sBox(gkrApi.NamedGate(gateNamer.linear(yI, round), a, b))
	}

	// apply a full round
	fullRound := func(i int) {
		x1 := extKeySBox(i, xI, x, y)
		x, y = x1, extKeySBox(i, yI, y, x) // the external matrix is symmetric so we can use the same gate with inputs swapped
	}

	// *** construct the circuit ***

	for i := range halfRf {
		fullRound(i)
	}

	{
		// i = halfRf: first partial round
		// still using the external matrix, since the linear operation still belongs to a full (canonical) round
		x1 := extKeySBox(halfRf, xI, x, y)

		x, y = x1, gkrApi.Gate(extGate2, x, y)
	}

	for i := halfRf + 1; i < halfRf+rP; i++ {
		x1 := extKeySBox(i, xI, x, y) // the first row of the internal matrix is the same as that of the external matrix
		x, y = x1, gkrApi.Gate(intGate2, x, y)
	}

	{
		i := halfRf + rP
		// first iteration of the final batch of full rounds
		// still using the internal matrix, since the linear operation still belongs to a partial (canonical) round
		x1 := extKeySBox(i, xI, x, y)
		x, y = x1, intKeySBox2(i, x, y)
	}

	for i := halfRf + rP + 1; i < rP+rF; i++ {
		fullRound(i)
	}

	// apply the external matrix one last time to obtain the final value of y
	out = gkrApi.NamedGate(gateNamer.linear(yI, rP+rF), y, x, in2)

	return
}

var bls12377Permutation = sync.OnceValue(func() *poseidon2Bls12377.Permutation {
	params := poseidon2Bls12377.GetDefaultParameters()
	return poseidon2Bls12377.NewPermutation(2, params.NbFullRounds, params.NbPartialRounds) // TODO @Tabaie add NewDefaultPermutation to gnark-crypto
})

// RegisterGkrGates registers the GKR gates corresponding to the given curves for the solver
func RegisterGkrGates(curves ...ecc.ID) {
	if len(curves) == 0 {
		panic("expected at least one curve")
	}
	for _, curve := range curves {
		switch curve {
		case ecc.BLS12_377:
			if err := registerGatesBls12377(); err != nil {
				panic(err)
			}
		default:
			panic(fmt.Sprintf("curve %s not currently supported", curve))
		}
	}
}

func registerGatesBls12377() error {
	const (
		x = iota
		y
	)

	p := poseidon2Bls12377.GetDefaultParameters()
	halfRf := p.NbFullRounds / 2
	gateNames := newRoundGateNamer(p)

	if _, err := gkrgates.Register(pow2Gate, 1, gkrgates.WithUnverifiedDegree(2), gkrgates.WithNoSolvableVar(), gkrgates.WithCurves(ecc.BLS12_377)); err != nil {
		return err
	}
	if _, err := gkrgates.Register(pow4Gate, 1, gkrgates.WithUnverifiedDegree(4), gkrgates.WithNoSolvableVar(), gkrgates.WithCurves(ecc.BLS12_377)); err != nil {
		return err
	}
	if _, err := gkrgates.Register(pow2TimesGate, 2, gkrgates.WithUnverifiedDegree(3), gkrgates.WithNoSolvableVar(), gkrgates.WithCurves(ecc.BLS12_377)); err != nil {
		return err
	}
	if _, err := gkrgates.Register(pow4TimesGate, 2, gkrgates.WithUnverifiedDegree(5), gkrgates.WithNoSolvableVar(), gkrgates.WithCurves(ecc.BLS12_377)); err != nil {
		return err
	}

	if _, err := gkrgates.Register(intGate2, 2, gkrgates.WithUnverifiedDegree(1), gkrgates.WithUnverifiedSolvableVar(0), gkrgates.WithCurves(ecc.BLS12_377)); err != nil {
		return err
	}

	extKeySBox := func(round int, varIndex int) error {
		_, err := gkrgates.Register(extKeyGate(&p.RoundKeys[round][varIndex]), 2, gkrgates.WithUnverifiedDegree(1), gkrgates.WithUnverifiedSolvableVar(0), gkrgates.WithName(gateNames.linear(varIndex, round)), gkrgates.WithCurves(ecc.BLS12_377))
		return err
	}

	intKeySBox2 := func(round int) error {
		_, err := gkrgates.Register(intKeyGate2(&p.RoundKeys[round][1]), 2, gkrgates.WithUnverifiedDegree(1), gkrgates.WithUnverifiedSolvableVar(0), gkrgates.WithName(gateNames.linear(y, round)), gkrgates.WithCurves(ecc.BLS12_377))
		return err
	}

	fullRound := func(i int) error {
		if err := extKeySBox(i, x); err != nil {
			return err
		}
		return extKeySBox(i, y)
	}

	for round := range halfRf {
		if err := fullRound(round); err != nil {
			return err
		}
	}

	{ // round = halfRf: first partial one
		if err := extKeySBox(halfRf, x); err != nil {
			return err
		}
	}

	for round := halfRf + 1; round < halfRf+p.NbPartialRounds; round++ {
		if err := extKeySBox(round, x); err != nil { // for x1, intKeySBox is identical to extKeySBox
			return err
		}
	}

	{
		round := halfRf + p.NbPartialRounds
		if err := extKeySBox(round, x); err != nil {
			return err
		}
		if err := intKeySBox2(round); err != nil {
			return err
		}
	}

	for round := halfRf + p.NbPartialRounds + 1; round < p.NbPartialRounds+p.NbFullRounds; round++ {
		if err := fullRound(round); err != nil {
			return err
		}
	}

	_, err := gkrgates.Register(extAddGate, 3, gkrgates.WithUnverifiedDegree(1), gkrgates.WithUnverifiedSolvableVar(0), gkrgates.WithName(gateNames.linear(y, p.NbPartialRounds+p.NbFullRounds)), gkrgates.WithCurves(ecc.BLS12_377))
	return err
}

type roundGateNamer string

// newRoundGateNamer returns an object that returns standardized names for gates in the GKR circuit
func newRoundGateNamer(p fmt.Stringer) roundGateNamer {
	return roundGateNamer(p.String())
}

// linear is the name of a gate where a polynomial of total degree 1 is applied to the input
func (n roundGateNamer) linear(varIndex, round int) gkr.GateName {
	return gkr.GateName(fmt.Sprintf("x%d-l-op-round=%d;%s", varIndex, round, n))
}

// integrated is the name of a gate where a polynomial of total degree 1 is applied to the input, followed by an S-box
func (n roundGateNamer) integrated(varIndex, round int) gkr.GateName {
	return gkr.GateName(fmt.Sprintf("x%d-i-op-round=%d;%s", varIndex, round, n))
}
