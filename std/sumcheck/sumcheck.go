package sumcheck

import (
	"fmt"
	"github.com/consensys/gnark/frontend"
)

type Polynomial []frontend.Variable //TODO: Is there already such a data structure?
type MultiLin []frontend.Variable

func (m MultiLin) Evaluate(api frontend.API, r []frontend.Variable) frontend.Variable {
	eqs := make([]frontend.Variable, len(m))
	eqs[0] = 1
	for i, rI := range r {
		prevSize := 1 << i
		oneMinusRI := api.Sub(1, rI)
		for j := prevSize - 1; j >= 0; j-- {
			eqs[2*j+1] = api.Mul(rI, eqs[j])
			eqs[2*j] = api.Mul(oneMinusRI, eqs[j])
		}
	}

	evaluation := frontend.Variable(0) //TODO: Does the API ignore publicly adding 0 to something?
	for j := range m {
		evaluation = api.Add(
			evaluation,
			api.Mul(eqs[j], m[j]),
		)
	}
	return evaluation
}

// LazyClaims is the Claims data structure on the verifier side. It is "lazy" in that it has to compute fewer things.
type LazyClaims interface {
	ClaimsNum() int                                    // ClaimsNum = m
	VarsNum() int                                      // VarsNum = n
	CombinedSum(a frontend.Variable) frontend.Variable // CombinedSum returns c = ∑_{1≤j≤m} aʲ⁻¹cⱼ
	Degree(i int) int                                  //Degree of the total claim in the i'th variable
	VerifyFinalEval(api frontend.API, r []frontend.Variable, combinationCoeff, purportedValue frontend.Variable, proof interface{}) error
}

// Proof of a multi-sumcheck statement.
type Proof struct {
	PartialSumPolys []Polynomial
	FinalEvalProof  interface{} //in case it is difficult for the verifier to compute g(r₁, ..., rₙ) on its own, the prover can provide the value and a proof
}

type Verifier struct {
	Claims     LazyClaims
	Proof      Proof `gnark:"proof"` //TODO: Is this allowed with "complex" objects?
	Transcript ArithmeticTranscript
}

func (v *Verifier) Define(api frontend.API) error {
	var combinationCoeff frontend.Variable

	if v.Claims.ClaimsNum() >= 2 {
		combinationCoeff = v.Transcript.Next()
	}

	r := make([]frontend.Variable, v.Claims.VarsNum())

	// Just so that there is enough room for gJ to be reused
	maxDegree := v.Claims.Degree(0)
	for j := 1; j < v.Claims.VarsNum(); j++ {
		if d := v.Claims.Degree(j); d > maxDegree {
			maxDegree = d
		}
	}

	gJ := make(Polynomial, maxDegree+1)           //At the end of iteration j, gJ = ∑_{i < 2ⁿ⁻ʲ⁻¹} g(X₁, ..., Xⱼ₊₁, i...)		NOTE: n is shorthand for v.Claims.VarsNum()
	gJR := v.Claims.CombinedSum(combinationCoeff) // At the beginning of iteration j, gJR = ∑_{i < 2ⁿ⁻ʲ} g(r₁, ..., rⱼ, i...)

	for j := 0; j < v.Claims.VarsNum(); j++ {
		if len(v.Proof.PartialSumPolys[j]) != v.Claims.Degree(j) {
			return fmt.Errorf("malformed proof") //Malformed proof
		}
		copy(gJ[1:], v.Proof.PartialSumPolys[j])
		gJ[0] = api.Sub(gJR, v.Proof.PartialSumPolys[j][0]) // Requirement that gⱼ(0) + gⱼ(1) = gⱼ₋₁(r)
		// gJ is ready

		//Prepare for the next iteration
		r[j] = v.Transcript.Next(v.Proof.PartialSumPolys[j])

		gJR = InterpolateOnRange(api, r[j], gJ[:(v.Claims.Degree(j)+1)]...)
	}

	return v.Claims.VerifyFinalEval(api, r, combinationCoeff, gJR, v.Proof.FinalEvalProof)
}
