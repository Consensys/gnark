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
		NbInternalVariables:  len(cs.internal.variables),
		NbPublicVariables:    len(cs.public.variables),
		NbSecretVariables:    len(cs.secret.variables),
		NbConstraints:        len(cs.constraints) + len(cs.assertions),
		Constraints:          make([]compiled.R1C, len(cs.constraints)+len(cs.assertions)),
		Logs:                 make([]compiled.LogEntry, len(cs.logs)),
		DebugInfoComputation: make([]compiled.LogEntry, len(cs.debugInfoComputation)+len(cs.debugInfoAssertion)),
		Hints:                make([]compiled.Hint, len(cs.hints)),
	}

	// computational constraints (= gates)
	copy(res.Constraints, cs.constraints)
	copy(res.Constraints[len(cs.constraints):], cs.assertions)

	// note: verbose, but we offset the IDs of the wires where they appear, that is,
	// in the logs, debug info, constraints and hints
	// since we don't use pointers but Terms (uint64), we need to potentially offset
	// the same wireID multiple times.
	copy(res.Hints, cs.hints)

	// offset variable ID depeneding on visibility
	shiftVID := func(oldID int, visibility compiled.Visibility) (int, error) {
		switch visibility {
		case compiled.Internal:
			return oldID + len(cs.public.variables) + len(cs.secret.variables), nil
		case compiled.Public:
			return oldID, nil
		case compiled.Secret:
			return oldID + len(cs.public.variables), nil
		case compiled.Unset:
			return -1, fmt.Errorf("%w: %s", ErrInputNotSet, cs.unsetVariables[0].format)
		// note; we should not have to shift compiled.Virtual variable, since they are not in the resulting
		// compiled constraint system
		default:
			panic("not implemented")
		}
	}

	// we just need to offset our ids, such that wires = [ public wires  | secret wires | internal wires ]
	offsetIDs := func(l compiled.LinearExpression) error {
		var err error
		var newID int
		for j := 0; j < len(l); j++ {
			_, vID, visibility := l[j].Unpack()
			newID, err = shiftVID(vID, visibility)
			if err != nil {
				return err
			}
			l[j].SetVariableID(newID)
		}
		return nil
	}

	for i := 0; i < len(res.Constraints); i++ {
		if err := offsetIDs(res.Constraints[i].L); err != nil {
			return nil, err
		}
		if err := offsetIDs(res.Constraints[i].R); err != nil {
			return nil, err
		}
		if err := offsetIDs(res.Constraints[i].O); err != nil {
			return nil, err
		}
	}

	// we need to offset the ids in the hints
	for i := 0; i < len(res.Hints); i++ {
		newID, err := shiftVID(res.Hints[i].WireID, compiled.Internal)
		if err != nil {
			return nil, err
		}
		res.Hints[i].WireID = newID
		for j := 0; j < len(res.Hints[i].Inputs); j++ {
			if err := offsetIDs(res.Hints[i].Inputs[j]); err != nil {
				return nil, err
			}
		}

	}

	// we need to offset the ids in logs
	for i := 0; i < len(cs.logs); i++ {
		entry := compiled.LogEntry{
			Format: cs.logs[i].format,
		}
		for j := 0; j < len(cs.logs[i].toResolve); j++ {
			_, vID, visibility := cs.logs[i].toResolve[j].Unpack()
			newID, err := shiftVID(vID, visibility)
			if err != nil {
				return nil, err
			}
			entry.ToResolve = append(entry.ToResolve, newID)
		}

		res.Logs[i] = entry
	}

	// offset ids in the debugInfoComputation
	for i := 0; i < len(cs.debugInfoComputation); i++ {
		entry := compiled.LogEntry{
			Format: cs.debugInfoComputation[i].format,
		}
		for j := 0; j < len(cs.debugInfoComputation[i].toResolve); j++ {
			_, vID, visibility := cs.debugInfoComputation[i].toResolve[j].Unpack()
			newID, err := shiftVID(vID, visibility)
			if err != nil {
				return nil, err
			}
			entry.ToResolve = append(entry.ToResolve, newID)
		}

		res.DebugInfoComputation[i] = entry
	}
	for i := 0; i < len(cs.debugInfoAssertion); i++ {
		entry := compiled.LogEntry{
			Format: cs.debugInfoAssertion[i].format,
		}
		for j := 0; j < len(cs.debugInfoAssertion[i].toResolve); j++ {
			_, vID, visibility := cs.debugInfoAssertion[i].toResolve[j].Unpack()
			newID, err := shiftVID(vID, visibility)
			if err != nil {
				return nil, err
			}
			entry.ToResolve = append(entry.ToResolve, newID)
		}

		res.DebugInfoComputation[i+len(cs.debugInfoComputation)] = entry
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
