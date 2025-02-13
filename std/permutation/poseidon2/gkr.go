package poseidon2

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	frBls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	mimcBls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/mimc"
	poseidon2Bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/poseidon2"
	gkrPoseidon2Bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/poseidon2/gkrgates"
	"github.com/consensys/gnark/constraint"
	csBls12377 "github.com/consensys/gnark/constraint/bls12-377"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/gkr"
	stdHash "github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/hash/mimc"
	"hash"
	"math/big"
	"sync"
)

// Gkr implements a GKR version of the Poseidon2 permutation with fan-in 2
type Gkr struct {
	Permutation
	Ins         []frontend.Variable
	Outs        []frontend.Variable
	plainHasher hash.Hash
}

// SHA256 hash of the hash parameters - as a unique identifier
// Note that the identifier is only unique with respect to the size parameters
// t, d, rF, rP
func (h *Permutation) hash(curve ecc.ID) []byte {
	hasher := sha256.New()
	writeAsByte := func(i int) {
		if i > 255 || i < 0 {
			panic("uint8 expected")
		}
		hasher.Write([]byte{byte(i)})
	}
	writeAsTwoBytes := func(i int) {
		if i > 65535 || i < 0 {
			panic("uint16 expected")
		}
		var buf [2]byte
		binary.LittleEndian.PutUint16(buf[:], uint16(i))
		hasher.Write(buf[:])
	}
	writeAsTwoBytes(int(curve))
	writeAsByte(h.params.t)
	writeAsByte(h.params.d)
	writeAsByte(h.params.rF)
	writeAsByte(h.params.rP)
	return hasher.Sum(nil)
}

// extKeyGate applies the external matrix mul, then adds the round key
// because of its symmetry, we don't need to define distinct x1 and x2 versions of it
type extKeyGate struct {
	roundKey *big.Int
}

func (g *extKeyGate) Evaluate(api frontend.API, x ...frontend.Variable) frontend.Variable {
	if len(x) != 2 {
		panic("expected 2 inputs")
	}
	return api.Add(api.Mul(x[0], 2), x[1], g.roundKey)
}

func (g *extKeyGate) Degree() int {
	return 1
}

// pow4Gate computes a -> a^4
type pow4Gate struct{}

func (g pow4Gate) Evaluate(api frontend.API, x ...frontend.Variable) frontend.Variable {
	if len(x) != 1 {
		panic("expected 1 input")
	}
	y := api.Mul(x[0], x[0])
	y = api.Mul(y, y)

	return y
}

func (g pow4Gate) Degree() int {
	return 4
}

// pow4Gate computes a, b -> a^4 * b
type pow4TimesGate struct{}

func (g pow4TimesGate) Evaluate(api frontend.API, x ...frontend.Variable) frontend.Variable {
	if len(x) != 2 {
		panic("expected 1 input")
	}
	y := api.Mul(x[0], x[0])
	y = api.Mul(y, y)

	return api.Mul(y, x[1])
}

func (g pow4TimesGate) Degree() int {
	return 5
}

type pow2Gate struct{}

func (g pow2Gate) Evaluate(api frontend.API, x ...frontend.Variable) frontend.Variable {
	if len(x) != 1 {
		panic("expected 1 input")
	}
	return api.Mul(x[0], x[0])
}

func (g pow2Gate) Degree() int {
	return 2
}

type pow2TimesGate struct{}

func (g pow2TimesGate) Evaluate(api frontend.API, x ...frontend.Variable) frontend.Variable {
	if len(x) != 2 {
		panic("expected 2 inputs")
	}
	return api.Mul(x[0], x[0], x[1])
}

func (g pow2TimesGate) Degree() int {
	return 3
}

// for x1, the partial round gates are identical to full round gates
// for x2, the partial round gates are just a linear combination
// TODO @Tabaie eliminate the x2 partial round gates and have the x1 gates depend on i - rf/2 or so previous x1's

// extGate2 applies the external matrix mul, outputting the second element of the result
type extGate2 struct {
}

func (g *extGate2) Evaluate(api frontend.API, x ...frontend.Variable) frontend.Variable {
	if len(x) != 2 {
		panic("expected 2 inputs")
	}
	return api.Add(api.Mul(x[1], 2), x[0])
}

func (g *extGate2) Degree() int {
	return 1
}

// intKeyGate2 applies the internal matrix mul, then adds the round key
type intKeyGate2 struct {
	roundKey *big.Int
}

func (g *intKeyGate2) Evaluate(api frontend.API, x ...frontend.Variable) frontend.Variable {
	if len(x) != 2 {
		panic("expected 2 inputs")
	}
	return api.Add(api.Mul(x[1], 3), x[0], g.roundKey)
}

func (g *intKeyGate2) Degree() int {
	return 1
}

type extGate struct{}

func (g extGate) Evaluate(api frontend.API, x ...frontend.Variable) frontend.Variable {
	if len(x) != 2 {
		panic("expected 2 inputs")
	}
	return api.Add(api.Mul(x[0], 2), x[1])
}

func (g extGate) Degree() int {
	return 1
}

type GkrPermutations struct {
	api  frontend.API
	ins1 []frontend.Variable
	ins2 []frontend.Variable
	outs []frontend.Variable
}

func NewGkrPermutations(api frontend.API) *GkrPermutations {
	res := GkrPermutations{
		api: api,
	}
	api.Compiler().Defer(res.finalize)
	return &res
}

func (p *GkrPermutations) Permute(a, b frontend.Variable) frontend.Variable {
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

func (p *GkrPermutations) finalize(api frontend.API) error {
	if p.api != api {
		panic("unexpected API")
	}

	stdHash.Register("mimc", func(api frontend.API) (stdHash.FieldHasher, error) {
		m, err := mimc.NewMiMC(api)
		return &m, err
	})

	// variable indexes
	const (
		xI = iota
		yI
	)

	roundKeysFr := poseidon2Bls12377.GetDefaultParameters().RoundKeys
	params := poseidon2Bls12377.GetDefaultParameters().String()
	zero := new(big.Int)
	const halfRf = rF / 2

	// build GKR circuit
	gkrApi := gkr.NewApi()

	// TODO @Tabaie gkr to auto pad?
	ins1Padded := make([]frontend.Variable, ecc.NextPowerOfTwo(uint64(len(p.ins1))))
	ins2Padded := make([]frontend.Variable, len(ins1Padded))
	copy(ins1Padded, p.ins1)
	copy(ins2Padded, p.ins2)
	for i := len(p.ins1); i < len(ins1Padded); i++ {
		ins1Padded[i] = 0
		ins2Padded[i] = 0
	}

	x, err := gkrApi.Import(ins1Padded)
	if err != nil {
		return err
	}
	y, err := gkrApi.Import(ins2Padded)
	if err != nil {
		return err
	}

	gateNameLinear := func(varI, i int) string {
		return fmt.Sprintf("x%d-l-op-round=%d;%s", varI, i, params)
	}

	gkr.Gates["pow4"] = pow4Gate{}
	gkr.Gates["pow4Times"] = pow4TimesGate{}

	sBox := func(round int, u constraint.GkrVariable) constraint.GkrVariable {
		v := gkrApi.NamedGate("pow4", u)           // u^4
		return gkrApi.NamedGate("pow4Times", v, u) // u^17
	}

	extKeySBox := func(round, varI int, a, b constraint.GkrVariable) constraint.GkrVariable {
		gate := gateNameLinear(varI, round)
		gkr.Gates[gate] = &extKeyGate{
			roundKey: frToInt(&roundKeysFr[round][varI]),
		}
		return sBox(round, gkrApi.NamedGate(gate, a, b))
	}

	intKeySBox2 := func(round int, a, b constraint.GkrVariable) constraint.GkrVariable {
		gate := gateNameLinear(yI, round)
		gkr.Gates[gate] = &intKeyGate2{
			roundKey: frToInt(&roundKeysFr[round][1]),
		}
		return sBox(round, gkrApi.NamedGate(gate, a, b))
	}

	fullRound := func(i int) {
		x1 := extKeySBox(i, xI, x, y) // TODO inline this
		x, y = x1, extKeySBox(i, yI, y, x)
	}

	for i := range halfRf {
		fullRound(i)
	}

	{ // i = halfRf: first partial round
		x1 := extKeySBox(halfRf, xI, x, y)

		gate := gateNameLinear(yI, halfRf)
		gkr.Gates[gate] = &extGate2{}
		x, y = x1, gkrApi.NamedGate(gate, x, y)
	}

	for i := halfRf + 1; i < halfRf+rP; i++ {
		x1 := extKeySBox(i, xI, x, y)

		gate := gateNameLinear(yI, i)
		gkr.Gates[gate] = &intKeyGate2{ // TODO replace with extGate
			roundKey: zero,
		}
		x, y = x1, gkrApi.NamedGate(gate, x, y)
	}

	{
		i := halfRf + rP
		x1 := extKeySBox(i, xI, x, y)

		x, y = x1, intKeySBox2(i, x, y)
	}

	for i := halfRf + rP + 1; i < rP+rF; i++ {
		fullRound(i)
	}

	gate := gateNameLinear(yI, rP+rF)
	gkr.Gates[gate] = extGate{}
	y = gkrApi.NamedGate(gate, y, x)

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

	err := bls12377Permutation().Permutation(x[:])
	x[1].BigInt(outs[0])
	return err
}

const (
	rF = 6
	rP = 32 - rF
	d  = 17
)

var (
	bls12377Permutation = sync.OnceValue(func() *poseidon2Bls12377.Permutation {
		return poseidon2Bls12377.NewPermutation(2, rF, rP) // TODO @Tabaie add NewDefaultPermutation to gnark-crypto
	})
)

// TODO find better name
// these are the fr gates
func AddGkrGatesSolution() {
	csBls12377.RegisterHashBuilder("mimc", func() hash.Hash {
		return mimcBls12377.NewMiMC()
	})
	gkrPoseidon2Bls12377.RegisterGkrGates()
}
