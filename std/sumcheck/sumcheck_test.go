package sumcheck

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/polynomial"
	"github.com/consensys/gnark/test"
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

	witness := singleMultilinCircuit{
		Claim: singleMultilinLazyClaim{
			G:          poly,
			ClaimedSum: sumAsInts(poly),
		},
		Proof:         proof,
		transcriptGen: transcriptGen,
	}

	assert := test.NewAssert(t)

	emptyProof := singleMultilinProof{PartialSumPolys: make([][]frontend.Variable, len(proof.PartialSumPolys))}
	for i, proofPoly := range proof.PartialSumPolys {
		emptyProof.PartialSumPolys[i] = make([]frontend.Variable, len(proofPoly))
	}

	circuit := singleMultilinCircuit{
		Claim:         singleMultilinLazyClaim{G: make([]frontend.Variable, len(poly))},
		Proof:         emptyProof,
		transcriptGen: transcriptGen,
	}

	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254))

}

func TestSumcheckSingleClaimMultilin(t *testing.T) {
	testSumcheckSingleClaimMultilin(
		t,
		polynomial.MultiLin{1, 2, 3, 4}, // 2 X₀ + X₁ + 1
		singleMultilinProof{
			PartialSumPolys: [][]frontend.Variable{{7}, {2}},
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
