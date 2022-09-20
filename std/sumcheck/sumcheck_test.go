package sumcheck

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	r1csPackage "github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/polynomial"
	"math/bits"
	"testing"
)

type singleMultilinLazyClaim struct {
	G          []frontend.Variable `gnark:",public"` //TODO: Why getting unconstrained input error?
	ClaimedSum frontend.Variable   `gnark:",public"`
}

type singleMultilinProof struct {
	PartialSumPolys [][]frontend.Variable
}

func (p singleMultilinProof) PartialSumPoly(index int) polynomial.Polynomial {
	return p.PartialSumPolys[index]
}

func (p singleMultilinProof) FinalEvalProof() Proof {
	return nil
}

func (c singleMultilinLazyClaim) ClaimsNum() int {
	return 1
}

func (c singleMultilinLazyClaim) VarsNum() int {
	return bits.TrailingZeros(uint(len(c.G)))
}

func (c singleMultilinLazyClaim) CombinedSum(frontend.Variable) frontend.Variable {
	return c.ClaimedSum
}

func (c singleMultilinLazyClaim) Degree(int) int {
	return 1
}

func (c singleMultilinLazyClaim) VerifyFinalEval(api frontend.API, r []frontend.Variable, _, purportedValue frontend.Variable, _ interface{}) error {
	g := polynomial.MultiLin(c.G)
	val := g.Eval(api, r)
	api.AssertIsEqual(val, purportedValue)
	return nil
}

func sumAsInts(poly polynomial.MultiLin) (sum int) {
	sum = 0
	for _, i := range poly {
		sum += i.(int)
	}
	return
}

type singleMultilinCircuit struct {
	Claim         singleMultilinLazyClaim
	Proof         singleMultilinProof `gnark:",secret"`
	transcriptGen func() ArithmeticTranscript
}

func (c *singleMultilinCircuit) Define(api frontend.API) error {
	return Verify(api, c.Claim, c.Proof, c.transcriptGen())
}

func testSumcheckSingleClaimMultilin(t *testing.T, poly polynomial.MultiLin, proof singleMultilinProof, transcriptGen func() ArithmeticTranscript) {

	assignment := singleMultilinCircuit{
		Claim: singleMultilinLazyClaim{
			G:          poly,
			ClaimedSum: sumAsInts(poly),
		},
		Proof:         proof,
		transcriptGen: transcriptGen,
	}

	emptyProof := singleMultilinProof{PartialSumPolys: make([][]frontend.Variable, len(proof.PartialSumPolys))}
	for i, proofPoly := range proof.PartialSumPolys {
		emptyProof.PartialSumPolys[i] = make([]frontend.Variable, len(proofPoly))
	}

	circuit := singleMultilinCircuit{
		Claim:         singleMultilinLazyClaim{G: make([]frontend.Variable, len(poly))},
		Proof:         emptyProof,
		transcriptGen: transcriptGen,
	}
	/* assert := test.NewAssert(t)
	assert.ProverSucceeded(&circuit, &assignment)
	assert.SolvingSucceeded(&circuit, &assignment, test.WithCurves(ecc.BN254))*/

	//var publicWitness *witnessPackage.Witness
	var pk groth16.ProvingKey
	//var vk groth16.VerifyingKey
	//var snarkProof groth16.Proof

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1csPackage.NewBuilder, &circuit)
	if err != nil {
		t.Error(err)
	}
	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Error(err)
	}

	/*publicWitness, err = witness.Public()
	if err != nil {
		t.Error(err)
	}*/

	pk, _, err = groth16.Setup(r1cs)
	if err != nil {
		t.Error(err)
	}

	_, err = groth16.Prove(r1cs, pk, witness)
	if err != nil {
		t.Error(err)
	}

	/*err = groth16.Verify(snarkProof, vk, publicWitness)
	if err != nil {
		t.Error(err)
	}*/

}

func TestSumcheckSingleClaimMultilin(t *testing.T) {
	testSumcheckSingleClaimMultilin(
		t,
		polynomial.MultiLin{1, 2, 3, 4}, // 2 X₀ + X₁ + 1
		singleMultilinProof{
			PartialSumPolys: [][]frontend.Variable{{7}, {6}},
		},
		NewMessageCounterGenerator(1, 1),
	)
}

// MessageCounter is a very bad fiat-shamir challenge generator
type MessageCounter struct {
	state   int64
	step    int64
	updated bool
}

func (m *MessageCounter) Update(...interface{}) {
	m.state += m.step
	m.updated = true
}

func (m *MessageCounter) Next(i ...interface{}) frontend.Variable {
	if !m.updated || len(i) != 0 {
		m.Update(i)
	}
	fmt.Println("hash returning", m.state)
	m.updated = false
	return m.state
}

func (m *MessageCounter) NextN(N int, i ...interface{}) (challenges []frontend.Variable) {
	challenges = make([]frontend.Variable, N)
	for n := 0; n < N; n++ {
		challenges[n] = m.Next(i)
		i = []interface{}{}
	}
	return
}

func NewMessageCounter(startState, step int) ArithmeticTranscript {
	transcript := &MessageCounter{state: int64(startState), step: int64(step)}
	//transcript.Update([]byte{})
	return transcript
}

func NewMessageCounterGenerator(startState, step int) func() ArithmeticTranscript {
	return func() ArithmeticTranscript {
		return NewMessageCounter(startState, step)
	}
}
