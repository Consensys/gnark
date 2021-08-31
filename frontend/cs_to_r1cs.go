package frontend

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/internal/backend/compiled"

	bls12377r1cs "github.com/consensys/gnark/internal/backend/bls12-377/cs"
	bls12381r1cs "github.com/consensys/gnark/internal/backend/bls12-381/cs"
	bls24315r1cs "github.com/consensys/gnark/internal/backend/bls24-315/cs"
	bn254r1cs "github.com/consensys/gnark/internal/backend/bn254/cs"
	bw6761r1cs "github.com/consensys/gnark/internal/backend/bw6-761/cs"
)

// toR1CS constructs a rank-1 constraint sytem
func (cs *ConstraintSystem) toR1CS(curveID ecc.ID) (CompiledConstraintSystem, error) {

	// wires = public wires  | secret wires | internal wires

	// setting up the result
	res := compiled.R1CS{
		NbInternalVariables: len(cs.internal.variables),
		NbPublicVariables:   len(cs.public.variables),
		NbSecretVariables:   len(cs.secret.variables),
		NbConstraints:       len(cs.constraints) + len(cs.assertions),
		NbCOConstraints:     len(cs.constraints),
		Constraints:         make([]compiled.R1C, len(cs.constraints)+len(cs.assertions)),
		Logs:                make([]compiled.LogEntry, len(cs.logs)),
		DebugInfoAssertion:  make([]compiled.LogEntry, len(cs.debugInfoAssertion)),
	}

	// computational constraints (= gates)
	copy(res.Constraints, cs.constraints)
	copy(res.Constraints[len(cs.constraints):], cs.assertions)

	// we just need to offset our ids, such that wires = [ public wires  | secret wires | internal wires ]
	offsetIDs := func(exp compiled.LinearExpression) error {
		for j := 0; j < len(exp); j++ {
			_, cID, cVisibility := exp[j].Unpack()
			switch cVisibility {
			case compiled.Internal:
				exp[j].SetVariableID(cID + len(cs.public.variables) + len(cs.secret.variables))
			case compiled.Public:
				// exp[j].SetVariableID(cID + len(cs.internal.variables) + len(cs.secret.variables))
			case compiled.Secret:
				exp[j].SetVariableID(cID + len(cs.public.variables))
			case compiled.Unset:
				return fmt.Errorf("%w: %s", ErrInputNotSet, cs.unsetVariables[0].format)
			}
		}
		return nil
	}

	var err error
	for i := 0; i < len(res.Constraints); i++ {
		err = offsetIDs(res.Constraints[i].L)
		if err != nil {
			return &res, err
		}
		err = offsetIDs(res.Constraints[i].R)
		if err != nil {
			return &res, err
		}
		err = offsetIDs(res.Constraints[i].O)
		if err != nil {
			return &res, err
		}
	}

	// we need to offset the ids in logs too
	for i := 0; i < len(cs.logs); i++ {
		entry := compiled.LogEntry{
			Format: cs.logs[i].format,
		}
		for j := 0; j < len(cs.logs[i].toResolve); j++ {
			_, cID, cVisibility := cs.logs[i].toResolve[j].Unpack()
			switch cVisibility {
			case compiled.Internal:
				cID += len(cs.public.variables) + len(cs.secret.variables)
			case compiled.Public:
				// cID += len(cs.internal.variables) + len(cs.secret.variables)
			case compiled.Secret:
				cID += len(cs.public.variables)
			case compiled.Unset:
				panic("encountered unset visibility on a variable in logs id offset routine")
			}
			entry.ToResolve = append(entry.ToResolve, cID)
		}

		res.Logs[i] = entry
	}

	// offset ids in the debugInfoAssertion
	for i := 0; i < len(cs.debugInfoAssertion); i++ {
		entry := compiled.LogEntry{
			Format: cs.debugInfoAssertion[i].format,
		}
		for j := 0; j < len(cs.debugInfoAssertion[i].toResolve); j++ {
			_, cID, cVisibility := cs.debugInfoAssertion[i].toResolve[j].Unpack()
			switch cVisibility {
			case compiled.Internal:
				cID += len(cs.public.variables) + len(cs.secret.variables)
			case compiled.Public:
				// cID += len(cs.internal.variables) + len(cs.secret.variables)
			case compiled.Secret:
				cID += len(cs.public.variables)
			case compiled.Unset:
				panic("encountered unset visibility on a variable in debugInfo id offset routine")
			}
			entry.ToResolve = append(entry.ToResolve, cID)
		}

		res.DebugInfoAssertion[i] = entry
	}

	switch curveID {
	case ecc.BLS12_377:
		return bls12377r1cs.NewR1CS(res, cs.coeffs), nil
	case ecc.BLS12_381:
		return bls12381r1cs.NewR1CS(res, cs.coeffs), nil
	case ecc.BN254:
		return bn254r1cs.NewR1CS(res, cs.coeffs), nil
	case ecc.BW6_761:
		return bw6761r1cs.NewR1CS(res, cs.coeffs), nil
	case ecc.BLS24_315:
		return bls24315r1cs.NewR1CS(res, cs.coeffs), nil
	case ecc.UNKNOWN:
		return &res, nil
	default:
		panic("not implemtented")
	}
}
