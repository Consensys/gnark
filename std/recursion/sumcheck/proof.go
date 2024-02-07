package sumcheck

import (
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

type nativeProof struct {
	RoundPolyEvaluations []nativePolynomial
	FinalEvalProof       nativeEvaluationProof
}

// EvaluationProof is proof for allowing the sumcheck verifier to perform the
// final evaluation needed to complete the check. It is untyped as it depends
// how the final evaluation is implemented:
//   - if sumcheck verifier directly evaluates the function, then it is nil,
//   - if it is multivariate polynomial opening proof, then it is the opening value,
//   - if it is deferred, then it is a slice.
type EvaluationProof any

type nativeEvaluationProof any

func valueOfProof[FR emulated.FieldParams](nproof nativeProof) Proof[FR] {
	rps := make([]polynomial.Univariate[FR], len(nproof.RoundPolyEvaluations))
	for i := range nproof.RoundPolyEvaluations {
		rps[i] = polynomial.ValueOfUnivariate[FR](nproof.RoundPolyEvaluations[i])
	}
	// TODO: type switch FinalEvalProof when it is not-nil
	return Proof[FR]{
		RoundPolyEvaluations: rps,
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
