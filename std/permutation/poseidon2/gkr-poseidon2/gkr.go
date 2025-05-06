package gkr_poseidon2

import (
	"errors"
	"fmt"
	"hash"
	"math/big"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	frBls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	mimcBls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/mimc"
	poseidon2Bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/poseidon2"

	"github.com/consensys/gnark/constraint"
	csBls12377 "github.com/consensys/gnark/constraint/bls12-377"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/gkr"
	stdHash "github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/permutation/poseidon2/gkr-poseidon2/internal"
	gkrPoseidon2Bls12377 "github.com/consensys/gnark/std/permutation/poseidon2/gkr-poseidon2/internal/bls12-377"
)

// extKeyGate applies the external matrix mul, then adds the round key
// because of its symmetry, we don't need to define distinct x1 and x2 versions of it
func extKeyGate(roundKey *big.Int) gkr.GateFunction {
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
		panic("expected 1 input")
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
func intKeyGate2(roundKey *big.Int) gkr.GateFunction {
	return func(api gkr.GateAPI, x ...frontend.Variable) frontend.Variable {
		if len(x) != 2 {
			panic("expected 2 inputs")
		}
		return api.Add(api.Mul(x[1], 3), x[0], roundKey)
	}
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

type GkrCompressions struct {
	api  frontend.API
	ins1 []frontend.Variable
	ins2 []frontend.Variable
	outs []frontend.Variable
}

// NewGkrCompressions returns an object that can compute the Poseidon2 compression function (currently only for BLS12-377)
// which consists of a permutation along with the input fed forward.
// The correctness of the compression functions is proven using GKR.
// Note that the solver will need the function RegisterGkrSolverOptions to be called with the desired curves
func NewGkrCompressions(api frontend.API) *GkrCompressions {
	res := GkrCompressions{
		api: api,
	}
	api.Compiler().Defer(res.finalize)
	return &res
}

func (p *GkrCompressions) Compress(a, b frontend.Variable) frontend.Variable {
	s, err := p.api.Compiler().NewHint(permuteHint, 1, a, b)
	if err != nil {
		panic(err)
	}
	p.ins1 = append(p.ins1, a)
	p.ins2 = append(p.ins2, b)
	p.outs = append(p.outs, s[0])
	return s[0]
}

func frToInt(x *frBls12377.Element) *big.Int {
	var res big.Int
	x.BigInt(&res)
	return &res
}

// defineCircuit defines the GKR circuit for the Poseidon2 permutation over BLS12-377
// insLeft and insRight are the inputs to the permutation
// they must be padded to a power of 2
func defineCircuit(insLeft, insRight []frontend.Variable) (*gkr.API, constraint.GkrVariable, error) {
	// variable indexes
	const (
		xI = iota
		yI
	)

	// poseidon2 parameters
	roundKeysFr := poseidon2Bls12377.GetDefaultParameters().RoundKeys
	gateNamer := internal.RoundGateNamer[gkr.GateName](poseidon2Bls12377.GetDefaultParameters())
	rF := poseidon2Bls12377.GetDefaultParameters().NbFullRounds
	rP := poseidon2Bls12377.GetDefaultParameters().NbPartialRounds
	halfRf := rF / 2

	gkrApi := gkr.NewApi()

	x, err := gkrApi.Import(insLeft)
	if err != nil {
		return nil, -1, err
	}
	y, err := gkrApi.Import(insRight)
	y0 := y // save to feed forward at the end
	if err != nil {
		return nil, -1, err
	}

	// the s-Box gates: u¹⁷ = (u⁴)⁴ * u
	if err = gkr.RegisterGate("pow4", pow4Gate, 1, gkr.WithUnverifiedDegree(4), gkr.WithNoSolvableVar()); err != nil {
		return nil, -1, err
	}
	if err = gkr.RegisterGate("pow4Times", pow4TimesGate, 2, gkr.WithUnverifiedDegree(5), gkr.WithNoSolvableVar()); err != nil {
		return nil, -1, err
	}

	// *** helper functions to register and apply gates ***

	// Poseidon2 is a sequence of additions, exponentiations (s-Box), and linear operations
	// but here we group the operations so that every round consists of a degree-1 operation followed by the s-Box
	// this allows for more efficient result sharing among the gates
	// but also breaks the uniformity of the circuit a bit, in that the matrix operation
	// in every round comes from the previous (canonical) round.

	// apply the s-Box to u
	sBox := func(u constraint.GkrVariable) constraint.GkrVariable {
		v := gkrApi.NamedGate("pow4", u)           // u⁴
		return gkrApi.NamedGate("pow4Times", v, u) // u¹⁷
	}

	// register and apply external matrix multiplication and round key addition
	// round dependent due to the round key
	extKeySBox := func(round, varI int, a, b constraint.GkrVariable) constraint.GkrVariable {
		gate := gateNamer.Linear(varI, round)
		if err = gkr.RegisterGate(gate, extKeyGate(frToInt(&roundKeysFr[round][varI])), 2, gkr.WithUnverifiedDegree(1), gkr.WithUnverifiedSolvableVar(0)); err != nil {
			return -1
		}
		return sBox(gkrApi.NamedGate(gate, a, b))
	}

	// register and apply external matrix multiplication and round key addition
	// then apply the s-Box
	// for the second variable
	// round independent due to the round key
	intKeySBox2 := func(round int, a, b constraint.GkrVariable) constraint.GkrVariable {
		gate := gateNamer.Linear(yI, round)
		if err = gkr.RegisterGate(gate, intKeyGate2(frToInt(&roundKeysFr[round][1])), 2, gkr.WithUnverifiedDegree(1), gkr.WithUnverifiedSolvableVar(0)); err != nil {
			return -1
		}
		return sBox(gkrApi.NamedGate(gate, a, b))
	}

	// apply a full round
	fullRound := func(i int) {
		x1 := extKeySBox(i, xI, x, y)      // TODO inline this
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

		gate := gateNamer.Linear(yI, halfRf)
		if err = gkr.RegisterGate(gate, extGate2, 2, gkr.WithUnverifiedDegree(1), gkr.WithUnverifiedSolvableVar(0)); err != nil {
			return nil, -1, err
		}
		x, y = x1, gkrApi.NamedGate(gate, x, y)
	}

	zero := new(big.Int)
	for i := halfRf + 1; i < halfRf+rP; i++ {
		x1 := extKeySBox(i, xI, x, y) // the first row of the internal matrix is the same as that of the external matrix

		gate := gateNamer.Linear(yI, i)
		if err = gkr.RegisterGate(gate, intKeyGate2(zero), 2, gkr.WithUnverifiedDegree(1), gkr.WithUnverifiedSolvableVar(0)); err != nil {
			return nil, -1, err
		}
		x, y = x1, gkrApi.NamedGate(gate, x, y)
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
	gate := gateNamer.Linear(yI, rP+rF)
	if err = gkr.RegisterGate(gate, extAddGate, 3, gkr.WithUnverifiedDegree(1), gkr.WithUnverifiedSolvableVar(0)); err != nil {
		return nil, -1, err
	}
	y = gkrApi.NamedGate(gate, y, x, y0)

	return gkrApi, y, nil
}

func (p *GkrCompressions) finalize(api frontend.API) error {
	if p.api != api {
		panic("unexpected API")
	}

	// register MiMC to be used as a random oracle in the GKR proof
	stdHash.Register("mimc", func(api frontend.API) (stdHash.FieldHasher, error) {
		m, err := mimc.NewMiMC(api)
		return &m, err
	})

	// pad instances into a power of 2
	// TODO @Tabaie the GKR API to do this automatically?
	ins1Padded := make([]frontend.Variable, ecc.NextPowerOfTwo(uint64(len(p.ins1))))
	ins2Padded := make([]frontend.Variable, len(ins1Padded))
	copy(ins1Padded, p.ins1)
	copy(ins2Padded, p.ins2)
	for i := len(p.ins1); i < len(ins1Padded); i++ {
		ins1Padded[i] = 0
		ins2Padded[i] = 0
	}

	gkrApi, y, err := defineCircuit(ins1Padded, ins2Padded)
	if err != nil {
		return err
	}

	// connect to output
	// TODO can we save 1 constraint per instance by giving the desired outputs to the gkr api?
	solution, err := gkrApi.Solve(api)
	if err != nil {
		return err
	}
	yVals := solution.Export(y)
	for i := range p.outs {
		api.AssertIsEqual(yVals[i], p.outs[i])
	}

	// verify GKR proof
	allVals := make([]frontend.Variable, 0, 3*len(p.ins1))
	allVals = append(allVals, p.ins1...)
	allVals = append(allVals, p.ins2...)
	allVals = append(allVals, p.outs...)
	challenge, err := p.api.(frontend.Committer).Commit(allVals...)
	if err != nil {
		return err
	}
	return solution.Verify("mimc", challenge)
}

func permuteHint(m *big.Int, ins, outs []*big.Int) error {
	if m.Cmp(ecc.BLS12_377.ScalarField()) != 0 {
		return errors.New("only bls12-377 supported")
	}
	if len(ins) != 2 || len(outs) != 1 {
		return errors.New("expected 2 inputs and 1 output")
	}
	var x [2]frBls12377.Element
	x[0].SetBigInt(ins[0])
	x[1].SetBigInt(ins[1])
	y0 := x[1]

	err := bls12377Permutation().Permutation(x[:])
	x[1].Add(&x[1], &y0) // feed forward
	x[1].BigInt(outs[0])
	return err
}

var bls12377Permutation = sync.OnceValue(func() *poseidon2Bls12377.Permutation {
	params := poseidon2Bls12377.GetDefaultParameters()
	return poseidon2Bls12377.NewPermutation(2, params.NbFullRounds, params.NbPartialRounds) // TODO @Tabaie add NewDefaultPermutation to gnark-crypto
})

// RegisterGkrSolverOptions registers the GKR gates corresponding to the given curves for the solver
func RegisterGkrSolverOptions(curves ...ecc.ID) {
	if len(curves) == 0 {
		panic("expected at least one curve")
	}
	solver.RegisterHint(permuteHint)
	for _, curve := range curves {
		switch curve {
		case ecc.BLS12_377:
			csBls12377.RegisterHashBuilder("mimc", func() hash.Hash {
				return mimcBls12377.NewMiMC()
			})
			if err := gkrPoseidon2Bls12377.RegisterGkrGates(); err != nil {
				panic(err)
			}
		default:
			panic(fmt.Sprintf("curve %s not currently supported", curve))
		}
	}
}
