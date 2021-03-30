package frontend

import (
	"fmt"

	"github.com/consensys/gnark/internal/backend/compiled"
	"github.com/consensys/gurvy"

	bls377r1cs "github.com/consensys/gnark/internal/backend/bls377/cs"
	bls381r1cs "github.com/consensys/gnark/internal/backend/bls381/cs"
	bn256r1cs "github.com/consensys/gnark/internal/backend/bn256/cs"
	bw761r1cs "github.com/consensys/gnark/internal/backend/bw761/cs"
)

// toR1CS constructs a rank-1 constraint sytem
func (cs *ConstraintSystem) toR1CS(curveID gurvy.ID) (CompiledConstraintSystem, error) {

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
		DebugInfo:           make([]compiled.LogEntry, len(cs.debugInfo)),
	}

	// computational constraints (= gates)
	copy(res.Constraints, cs.constraints)
	copy(res.Constraints[len(cs.constraints):], cs.assertions)

	// we just need to offset our ids, such that wires = [ public wires  | secret wires | internal wires ]
	offsetIDs := func(exp compiled.LinearExpression) error {
		for j := 0; j < len(exp); j++ {
			_, _, cID, cVisibility := exp[j].Unpack()
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
			_, _, cID, cVisibility := cs.logs[i].toResolve[j].Unpack()
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

	// offset ids in the debugInfo
	for i := 0; i < len(cs.debugInfo); i++ {
		entry := compiled.LogEntry{
			Format: cs.debugInfo[i].format,
		}
		for j := 0; j < len(cs.debugInfo[i].toResolve); j++ {
			_, _, cID, cVisibility := cs.debugInfo[i].toResolve[j].Unpack()
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

		res.DebugInfo[i] = entry
	}

	switch curveID {
	case gurvy.BLS377:
		return bls377r1cs.NewR1CS(res, cs.coeffs), nil
	case gurvy.BLS381:
		return bls381r1cs.NewR1CS(res, cs.coeffs), nil
	case gurvy.BN256:
		return bn256r1cs.NewR1CS(res, cs.coeffs), nil
	case gurvy.BW761:
		return bw761r1cs.NewR1CS(res, cs.coeffs), nil
	case gurvy.UNKNOWN:
		return &res, nil
	default:
		panic("not implemtented")
	}
}
