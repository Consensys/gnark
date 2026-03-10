package gkrcore

import (
	"encoding/binary"
	"fmt"
	"io"
	"math/big"

	"github.com/consensys/gnark/constraint"
)

// Common serialization utilities

func writeUint8(w io.Writer, x int) error {
	if x >= 256 || x < 0 {
		return fmt.Errorf("%d out of range", x)
	}
	_, err := w.Write([]byte{byte(x)})
	return err
}

func writeUint16(w io.Writer, x int) error {
	var buf [2]byte
	if x >= 65536 || x < 0 {
		return fmt.Errorf("%d out of range", x)
	}
	binary.LittleEndian.PutUint16(buf[:], uint16(x))
	_, err := w.Write(buf[:])
	return err
}

func writeBool(w io.Writer, b bool) error {
	var v byte
	if b {
		v = 1
	}
	_, err := w.Write([]byte{v})
	return err
}

func writeBigInt(w io.Writer, x *big.Int) error {
	bytes := x.Bytes()
	if err := writeUint8(w, len(bytes)); err != nil {
		return err
	}
	_, err := w.Write(bytes)
	return err
}

// SerializeCircuit writes a SerializableCircuit to w in deterministic binary format,
// primarily for hashing circuits to create unique identifiers.
//
// The encoding is compact (uint16 for counts/indices, uint8 for bigint byte lengths) and
// uses little-endian throughout. Gate metadata (NbIn, Degree, SolvableVar) is omitted
// since it can be recomputed from bytecode on deserialization.
//
// Format:
//
//	Circuit: [wire_count:u16] [wire...]
//	Wire: [input_count:u16] [input_indices:u16...] [exported:bool] [gate?]
//	Gate (non-input only): [const_count:u16] [constants...] [inst_count:u16] [instructions...]
//	Constant: [byte_len:u8] [bytes...]
//	Instruction: [op:u8] [input_count:u16] [input_indices:u16...]
func SerializeCircuit(w io.Writer, c SerializableCircuit) error {
	if len(c) >= 1<<32 {
		return fmt.Errorf("circuit length too large: %d", len(c))
	}

	// Write number of wires
	if err := writeUint16(w, len(c)); err != nil {
		return err
	}

	// Write each wire
	for i := range c {
		wire := &c[i]

		// Write number of inputs
		if err := writeUint16(w, len(wire.Inputs)); err != nil {
			return err
		}

		// Write each input index
		for _, input := range wire.Inputs {
			if err := writeUint16(w, input); err != nil {
				return err
			}
		}

		// Write exported flag
		if err := writeBool(w, wire.Exported); err != nil {
			return err
		}

		// If not an input wire, write gate information
		if !wire.IsInput() {
			gate := &wire.Gate

			// Write bytecode
			bytecode := &gate.Evaluate

			// Write constants
			if err := writeUint16(w, len(bytecode.Constants)); err != nil {
				return err
			}
			for _, constant := range bytecode.Constants {
				if err := writeBigInt(w, constant); err != nil {
					return err
				}
			}

			// Write instructions
			if err := writeUint16(w, len(bytecode.Instructions)); err != nil {
				return err
			}
			for _, inst := range bytecode.Instructions {
				// Write operation
				if _, err := w.Write([]byte{byte(inst.Op)}); err != nil {
					return err
				}

				// Write number of instruction inputs
				if err := writeUint16(w, len(inst.Inputs)); err != nil {
					return err
				}

				// Write each instruction input
				for _, input := range inst.Inputs {
					if err := writeUint16(w, int(input)); err != nil {
						return err
					}
				}
			}
		}
	}

	return nil
}

// SerializeSchedule writes a GkrProvingSchedule to w in deterministic binary format,
// primarily for hashing schedules to create unique identifiers.
//
// The encoding uses uint16 for counts/indices and little-endian throughout.
//
// Format:
//
//	Schedule: [level_count:u16] [level...]
//	Level: [type:u8] [skip_group | sumcheck_groups]
//	SkipLevel: [claim_group]
//	SumcheckLevel: [group_count:u16] [claim_group...]
//	ClaimGroup: [wire_count:u16] [wire_indices:u16...] [source_count:u16] [source_indices:u16...]
func SerializeSchedule(w io.Writer, s constraint.GkrProvingSchedule) error {
	if len(s) >= 65536 {
		return fmt.Errorf("schedule length too large: %d", len(s))
	}

	writeClaimGroup := func(cg constraint.GkrClaimGroup) error {
		// Write wire count and indices
		if err := writeUint16(w, len(cg.Wires)); err != nil {
			return err
		}
		for _, wireIdx := range cg.Wires {
			if err := writeUint16(w, wireIdx); err != nil {
				return err
			}
		}

		// Write claim source count and indices
		if err := writeUint16(w, len(cg.ClaimSources)); err != nil {
			return err
		}
		for _, srcIdx := range cg.ClaimSources {
			if err := writeUint16(w, srcIdx); err != nil {
				return err
			}
		}
		return nil
	}

	// Write number of levels
	if err := writeUint16(w, len(s)); err != nil {
		return err
	}

	// Write each level
	for _, level := range s {
		switch l := level.(type) {
		case constraint.GkrSkipLevel:
			// Type: 0 for skip
			if _, err := w.Write([]byte{0}); err != nil {
				return err
			}
			if err := writeClaimGroup(constraint.GkrClaimGroup(l)); err != nil {
				return err
			}

		case constraint.GkrSumcheckLevel:
			// Type: 1 for sumcheck
			if _, err := w.Write([]byte{1}); err != nil {
				return err
			}
			// Write number of groups
			if err := writeUint16(w, len(l)); err != nil {
				return err
			}
			// Write each group
			for _, cg := range l {
				if err := writeClaimGroup(cg); err != nil {
					return err
				}
			}

		default:
			return fmt.Errorf("unknown level type: %T", level)
		}
	}

	return nil
}
