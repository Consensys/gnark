package sumcheck

import (
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/polynomial"
)

type Proof[FR emulated.FieldParams] struct {
	// PartialSumPolys is polynomial representation in evaluation form
	RoundPolyEvaluations []polynomial.Univariate[FR]
	FinalEvalProof       EvaluationProof
}

type nativeProof struct {
	RoundPolyEvaluations []nativePolynomial
	FinalEvalProof       nativeEvaluationProof
}

type EvaluationProof interface{}

type nativeEvaluationProof interface{}

func ValueOfProof[FR emulated.FieldParams](nproof nativeProof) Proof[FR] {
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
