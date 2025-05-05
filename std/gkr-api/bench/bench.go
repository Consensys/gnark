package main

import (
	"fmt"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	hash2 "github.com/consensys/gnark-crypto/hash"
	cs2 "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	gkrFr "github.com/consensys/gnark/internal/gkr/bn254"
	"github.com/consensys/gnark/std/gkr/gates"
	stdHash "github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/hash/mimc"
)

const (
	nbInstances        = 2097152
	gateName           = "mimcGate"
	permutationNbGates = 100
)

var ark fr.Element

func permutation(in ...fr.Element) fr.Element {
	in[0].
		Add(&in[0], &in[1]).
		Add(&in[0], &ark)

	in[1].Square(&in[0]).Mul(&in[1], &in[0]).Square(&in[1]) // in[0]^6
	in[0].Mul(&in[0], &in[1])                               // in[0]^7

	return in[0]
}

func permutationSnark(api gates.GateAPI, in ...frontend.Variable) frontend.Variable {
	in[0] = api.Add(in[0], in[1], ark)
	in[1] = api.Mul(in[0], in[0], in[0])
	in[1] = api.Mul(in[1], in[1])
	return api.Mul(in[0], in[1])
}

func main() {

	var isUnigate string
	if !cs2.Unigate {
		isUnigate = "NOT_"
	}
	isUnigate = isUnigate + "unigate"

	fmt.Println(isUnigate)

	ark.SetUint64(0x1234567890abcdef)

	panicIfError(gkrFr.RegisterGate(gateName, permutation, 2))
	panicIfError(gates.RegisterGate(gateName, permutationSnark, 2))

	cs2.RegisterHashBuilder("mimc", hash2.MIMC_BN254.New)
	stdHash.Register("mimc", func(api frontend.API) (stdHash.FieldHasher, error) {
		m, err := mimc.NewMiMC(api)
		return &m, err
	})

	var assignment testGkrPermutationCircuit
	for i := range nbInstances {
		assignment.Ins[0][i] = 2 * i
		assignment.Ins[1][i] = 2*i + 1
	}

	cs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &testGkrPermutationCircuit{})
	panicIfError(err)

	w, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	panicIfError(err)

	start := time.Now().UnixMicro()

	panicIfError(cs.IsSolved(w))

	fmt.Printf("took %d microseconds\n", time.Now().UnixMicro()-start)
}

func panicIfError(err error) {
	if err != nil {
		panic(err)
	}
}

type testGkrPermutationCircuit struct {
	Ins [2][nbInstances]frontend.Variable
	//Outs [nbInstances]frontend.Variable
}

func (c *testGkrPermutationCircuit) Define(api frontend.API) error {
	gkrApi := gkr_api.NewApi()

	x, err := gkrApi.Import(c.Ins[0][:])
	panicIfError(err)
	y, err := gkrApi.Import(c.Ins[1][:])

	for range permutationNbGates {
		x = gkrApi.NamedGate(gateName, x, y)
	}

	solution, err := gkrApi.Solve(api)
	panicIfError(err)

	return solution.Verify("mimc", 12345)
}
