package gkr_poseidon2

import (
	"errors"
	"fmt"
	"sync"

	"github.com/consensys/gnark/constraint/solver/gkrgates"
	"github.com/consensys/gnark/internal/kvstore"
	"github.com/consensys/gnark/internal/utils"
	"github.com/consensys/gnark/std/gkrapi"
	"github.com/consensys/gnark/std/gkrapi/gkr"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/permutation/poseidon2"

	"github.com/consensys/gnark-crypto/ecc"
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

// pow3Gate computes a -> a³
func pow3Gate(api gkr.GateAPI, x ...frontend.Variable) frontend.Variable {
	if len(x) != 1 {
		panic("expected 1 input")
	}
	return api.Mul(x[0], x[0], x[0])
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

// extAddGate applies the first row of the external matrix to the first two elements and adds the third
func extAddGate(api gkr.GateAPI, x ...frontend.Variable) frontend.Variable {
	if len(x) != 3 {
		panic("expected 3 inputs")
	}
	return api.Add(api.Mul(x[0], 2), x[1], x[2])
}

type compressor struct {
	api           frontend.API
	gkrCircuit    *gkrapi.Circuit
	in1, in2, out gkr.Variable
}

// NewCompressor returns an object that can compute the Poseidon2 compression function (currently only for BLS12-377)
// which consists of a permutation along with the input fed forward.
// The correctness of the compression functions is proven using GKR.
// Note that the solver will need the function RegisterGates to be called with the desired curves
func NewCompressor(api frontend.API) (hash.Compressor, error) {
	store, ok := api.Compiler().(kvstore.Store)
	if !ok {
		return nil, fmt.Errorf("api of type %T does not implement kvstore.Store", api)
	}

	cached := store.GetKeyValue(gkrPoseidon2Key{})
	if cached != nil {
		if compressor, ok := cached.(*compressor); ok {
			return compressor, nil
		}
		return nil, fmt.Errorf("cached value is of type %T, not a gkr-poseidon2.Compressor", cached)
	}

	gkrCircuit, in1, in2, out, err := defineCircuit(api)
	if err != nil {
		return nil, fmt.Errorf("failed to define GKR circuit: %w", err)
	}
	res := &compressor{
		api:        api,
		gkrCircuit: gkrCircuit,
		in1:        in1,
		in2:        in2,
		out:        out,
	}
	store.SetKeyValue(gkrPoseidon2Key{}, res)
	return res, nil
}

func (p *compressor) Compress(a, b frontend.Variable) frontend.Variable {
	outs, err := p.gkrCircuit.AddInstance(map[gkr.Variable]frontend.Variable{p.in1: a, p.in2: b})
	if err != nil {
		panic(err)
	}

	return outs[p.out]
}

// defineCircuit defines the GKR circuit for the Poseidon2 permutation over BLS12-377
// insLeft and insRight are the inputs to the permutation
// they must be padded to a power of 2
func defineCircuit(api frontend.API) (gkrCircuit *gkrapi.Circuit, in1, in2, out gkr.Variable, err error) {
	// variable indexes
	const (
		xI = iota
		yI
	)

	curve := utils.FieldToCurve(api.Compiler().Field())
	p, err := poseidon2.GetDefaultParameters(curve)
	if err != nil {
		return
	}
	gateNamer := newRoundGateNamer(&p, curve)

	registerStaticGates()
	if err = registerGates(&p, curve); err != nil {
		return
	}

	gkrApi, err := gkrapi.New(api)
	if err != nil {
		return
	}

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

	var sBox func(gkr.Variable) gkr.Variable
	switch p.DegreeSBox {
	case 5:
		sBox = func(u gkr.Variable) gkr.Variable {
			v := gkrApi.Gate(pow2Gate, u)           // u²
			return gkrApi.Gate(pow2TimesGate, v, u) // u⁵
		}
	case 7:
		sBox = func(u gkr.Variable) gkr.Variable {
			v := gkrApi.Gate(pow3Gate, u)           // u³
			return gkrApi.Gate(pow2TimesGate, v, u) // u⁷
		}
	case 17:
		sBox = func(u gkr.Variable) gkr.Variable {
			v := gkrApi.Gate(pow4Gate, u)           // u⁴
			return gkrApi.Gate(pow4TimesGate, v, u) // u¹⁷
		}
	default:
		err = fmt.Errorf("unsupported s-Box degree %d", p.DegreeSBox)
		return
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

	for i := range p.NbFullRounds / 2 {
		fullRound(i)
	}

	{
		// i = halfRf: first partial round
		// still using the external matrix, since the linear operation still belongs to a full (canonical) round
		x1 := extKeySBox(p.NbFullRounds/2, xI, x, y)

		x, y = x1, gkrApi.Gate(extGate2, x, y)
	}

	for i := p.NbFullRounds/2 + 1; i < p.NbFullRounds/2+p.NbPartialRounds; i++ {
		x1 := extKeySBox(i, xI, x, y) // the first row of the internal matrix is the same as that of the external matrix
		x, y = x1, gkrApi.Gate(intGate2, x, y)
	}

	{
		i := p.NbFullRounds/2 + p.NbPartialRounds
		// first iteration of the final batch of full rounds
		// still using the internal matrix, since the linear operation still belongs to a partial (canonical) round
		x1 := extKeySBox(i, xI, x, y)
		x, y = x1, intKeySBox2(i, x, y)
	}

	for i := p.NbFullRounds/2 + p.NbPartialRounds + 1; i < p.NbPartialRounds+p.NbFullRounds; i++ {
		fullRound(i)
	}

	// apply the external matrix one last time to obtain the final value of y
	out = gkrApi.Gate(extAddGate, y, x, in2)

	gkrCircuit, err = gkrApi.Compile("MIMC")

	return
}

// RegisterGates registers the GKR gates corresponding to the given curves for the solver.
func RegisterGates(curves ...ecc.ID) error {
	if len(curves) == 0 {
		return errors.New("expected at least one curve")
	}
	registerStaticGates()
	for _, curve := range curves {
		p, err := poseidon2.GetDefaultParameters(curve)
		if err != nil {
			return fmt.Errorf("failed to get default parameters for curve %s: %w", curve, err)
		}
		if err = registerGates(&p, curve); err != nil {
			return fmt.Errorf("failed to register gates for curve %s: %w", curve, err)
		}
	}
	return nil
}

var staticGatesOnce sync.Once

func registerStaticGates() {
	staticGatesOnce.Do(func() {
		if err := gkrgates.Register(pow4Gate, 1, gkrgates.WithUnverifiedDegree(4)); err != nil {
			panic(err)
		}
		if err := gkrgates.Register(pow4TimesGate, 2, gkrgates.WithUnverifiedDegree(5)); err != nil {
			panic(err)
		}
		if err := gkrgates.Register(pow3Gate, 1, gkrgates.WithUnverifiedDegree(3)); err != nil {
			panic(err)
		}
		if err := gkrgates.Register(pow2Gate, 1, gkrgates.WithUnverifiedDegree(2)); err != nil {
			panic(err)
		}
		if err := gkrgates.Register(pow2TimesGate, 2, gkrgates.WithUnverifiedDegree(3)); err != nil {
			panic(err)
		}
		if err := gkrgates.Register(extGate2, 2, gkrgates.WithUnverifiedDegree(1)); err != nil {
			panic(err)
		}
		if err := gkrgates.Register(intGate2, 2, gkrgates.WithUnverifiedDegree(1)); err != nil {
			panic(err)
		}
		if err := gkrgates.Register(extAddGate, 3, gkrgates.WithUnverifiedDegree(1)); err != nil {
			panic(err)
		}
	})
}

func registerGates(p *poseidon2.Parameters, curve ecc.ID) error {
	const (
		x = iota
		y
	)

	gateNames := newRoundGateNamer(p, curve)
	halfRf := p.NbFullRounds / 2

	extKeySBox := func(round int, varIndex int) error {
		return gkrgates.Register(extKeyGate(&p.RoundKeys[round][varIndex]), 2, gkrgates.WithUnverifiedDegree(1), gkrgates.WithUnverifiedSolvableVar(0), gkrgates.WithName(gateNames.linear(varIndex, round)), gkrgates.WithCurves(curve))
	}

	intKeySBox2 := func(round int) error {
		return gkrgates.Register(intKeyGate2(&p.RoundKeys[round][1]), 2, gkrgates.WithUnverifiedDegree(1), gkrgates.WithUnverifiedSolvableVar(0), gkrgates.WithName(gateNames.linear(y, round)), gkrgates.WithCurves(curve))
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

	return nil
}

type roundGateNamer string

// newRoundGateNamer returns an object that returns standardized names for gates in the GKR circuit
func newRoundGateNamer(p *poseidon2.Parameters, curve ecc.ID) roundGateNamer {
	return roundGateNamer(fmt.Sprintf("Poseidon2-%s[t=%d,rF=%d,rP=%d,d=%d]", curve.String(), p.Width, p.NbFullRounds, p.NbPartialRounds, p.DegreeSBox))
}

// linear is the name of a gate where a polynomial of total degree 1 is applied to the input
func (n roundGateNamer) linear(varIndex, round int) gkr.GateName {
	return gkr.GateName(fmt.Sprintf("x%d-l-op-round=%d;%s", varIndex, round, n))
}

type gkrPoseidon2Key struct{}
