package sumcheck

import (
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/polynomial"
	"math/big"
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
	// Convert native FinalEvalProof into emulated representation when present.
	var final EvaluationProof
	switch v := any(nproof.FinalEvalProof).(type) {
	case nil:
		final = nil
	case *big.Int:
		val := emulated.ValueOf[FR](v)
		final = val
	case []*big.Int:
		vals := make([]emulated.Element[FR], len(v))
		for i := range v {
			vals[i] = emulated.ValueOf[FR](v[i])
		}
		final = vals
	case [][]*big.Int:
		outer := make([][]emulated.Element[FR], len(v))
		for i := range v {
			inner := make([]emulated.Element[FR], len(v[i]))
			for j := range v[i] {
				inner[j] = emulated.ValueOf[FR](v[i][j])
			}
			outer[i] = inner
		}
		final = outer
	default:
		panic("sumcheck: unsupported FinalEvalProof type")
	}
	return Proof[FR]{
		RoundPolyEvaluations: rps,
		FinalEvalProof:       final,
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
