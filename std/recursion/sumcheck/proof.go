package sumcheck

import (
	"math/big"

	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/polynomial"
)

// Proof contains the prover messages in the sumcheck protocol.
type Proof[FR emulated.FieldParams] struct {
	// RoundPolyEvaluations is polynomial representation in evaluation form
	RoundPolyEvaluations []polynomial.Univariate[FR]
	// FinalEvalProof is the witness for helping the verifier to compute the
	// final round of the sumcheck protocol.
	FinalEvalProof EvaluationProof
}

type NativeProof struct {
	RoundPolyEvaluations []NativePolynomial
	FinalEvalProof       NativeEvaluationProof
}

// EvaluationProof is proof for allowing the sumcheck verifier to perform the
// final evaluation needed to complete the check. It is untyped as it depends
// how the final evaluation is implemented:
//   - if sumcheck verifier directly evaluates the function, then it is nil,
//   - if it is multivariate polynomial opening proof, then it is the opening value,
//   - if it is deferred, then it is a slice.
type EvaluationProof any

// evaluationProof for gkr
type DeferredEvalProof[FR emulated.FieldParams] []emulated.Element[FR]
type NativeDeferredEvalProof []big.Int

type NativeEvaluationProof any

func ValueOfProof[FR emulated.FieldParams](nproof NativeProof) Proof[FR] {
	rps := make([]polynomial.Univariate[FR], len(nproof.RoundPolyEvaluations))
	finaleval := nproof.FinalEvalProof
	if finaleval != nil {
		switch v := finaleval.(type) {
		case NativeDeferredEvalProof:
			deferredEval := make(DeferredEvalProof[FR], len(v))
			for i := range v {
				deferredEval[i] = emulated.ValueOf[FR](v[i])
			}
			finaleval = deferredEval
		}
	} 
	for i := range nproof.RoundPolyEvaluations {
		rps[i] = polynomial.ValueOfUnivariate[FR](nproof.RoundPolyEvaluations[i])
	}

	return Proof[FR]{
		RoundPolyEvaluations: rps,
		FinalEvalProof:       finaleval,
	}
}

func placeholderMultilinearProof[FR emulated.FieldParams](nbVars int) Proof[FR] {
	rps := make([]polynomial.Univariate[FR], nbVars)
	for i := range rps {
		rps[i] = polynomial.PlaceholderUnivariate[FR](1)
	}
	return Proof[FR]{
		RoundPolyEvaluations: rps,
	}
}

func placeholderGateProof[FR emulated.FieldParams](nbVars int, gateDegree int) Proof[FR] {
	rps := make([]polynomial.Univariate[FR], nbVars)
	for i := range rps {
		rps[i] = polynomial.PlaceholderUnivariate[FR](gateDegree + 1)
	}
	return Proof[FR]{
		RoundPolyEvaluations: rps,
	}
}
