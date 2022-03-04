package compiled

import (
	"fmt"
	"math/big"
	"reflect"

	"github.com/consensys/gnark/backend/hint"
	"github.com/fxamacker/cbor/v2"
)

// Hint represents a solver hint
// it enables the solver to compute a Wire with a function provided at solving time
// using pre-defined inputs
type Hint struct {
	ID     hint.ID       // hint function id
	Inputs []interface{} // terms to inject in the hint function
	Wires  []int         // IDs of wires the hint outputs map to
}

func (h Hint) inputsCBORTags() (cbor.TagSet, error) {
	defTagOpts := cbor.TagOptions{EncTag: cbor.EncTagRequired, DecTag: cbor.DecTagRequired}
	tags := cbor.NewTagSet()
	if err := tags.Add(defTagOpts, reflect.TypeOf(LinearExpression{}), 25443); err != nil {
		return nil, fmt.Errorf("new LE tag: %w", err)
	}
	if err := tags.Add(defTagOpts, reflect.TypeOf(Term(0)), 25445); err != nil {
		return nil, fmt.Errorf("new term tag: %w", err)
	}
	return tags, nil
}

func (h Hint) MarshalCBOR() ([]byte, error) {
	tags, err := h.inputsCBORTags()
	if err != nil {
		return nil, fmt.Errorf("cbor tags: %w", err)
	}
	enc, err := cbor.CoreDetEncOptions().EncModeWithTags(tags)
	if err != nil {
		return nil, err
	}
	// v of type vt is Hint but does not implement cbor.Marshaler
	type vt Hint
	inputs := make([]interface{}, len(h.Inputs))
	// map big.Int to bytes
	for i := range h.Inputs {
		switch vit := h.Inputs[i].(type) {
		case big.Int:
			b := vit.Bytes()
			bb, err := enc.Marshal(b)
			if err != nil {
				return nil, fmt.Errorf("marshal big int bytes: %w", err)
			}
			inputs[i] = cbor.RawTag{Number: 25446, Content: cbor.RawMessage(bb)}
		case *big.Int:
			b := vit.Bytes()
			bb, err := enc.Marshal(b)
			if err != nil {
				return nil, fmt.Errorf("marshal big int bytes: %w", err)
			}
			inputs[i] = cbor.RawTag{Number: 25447, Content: cbor.RawMessage(bb)}
		default:
			_ = vit
			// handled by tagset
			inputs[i] = h.Inputs[i]
		}
	}
	v := vt{ID: h.ID, Inputs: inputs, Wires: h.Wires}
	return enc.Marshal(v)
}

func (h *Hint) UnmarshalCBOR(b []byte) error {
	tags, err := h.inputsCBORTags()
	if err != nil {
		return fmt.Errorf("cbor tags: %w", err)
	}
	dec, err := cbor.DecOptions{}.DecModeWithTags(tags)
	if err != nil {
		return fmt.Errorf("decoder: %w", err)
	}
	// v of type vt is Hint but does not implement cbor.Marshaler
	type vt struct {
		ID     hint.ID
		Inputs []cbor.RawTag
		Wires  []int
	}
	var v vt
	if err := dec.Unmarshal(b, &v); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}
	inputs := make([]interface{}, len(v.Inputs))
	for i, vin := range v.Inputs {
		switch vin.Number {
		case 25443:
			var v []Term
			if err := dec.Unmarshal(vin.Content, &v); err != nil {
				return fmt.Errorf("unmarshal linear expression: %w", err)
			}
			inputs[i] = LinearExpression(v)
		case 25445:
			var v uint64
			if err := dec.Unmarshal(vin.Content, &v); err != nil {
				return fmt.Errorf("unmarshal term: %w", err)
			}
			inputs[i] = Term(v)
		case 25446:
			v := new(big.Int)
			var bb []byte
			if err := dec.Unmarshal(vin.Content, &bb); err != nil {
				return fmt.Errorf("unmarshal big int bytes: %w", err)
			}
			v.SetBytes(bb)
			inputs[i] = *v
		case 25447:
			v := new(big.Int)
			var bb []byte
			if err := dec.Unmarshal(vin.Content, &bb); err != nil {
				return fmt.Errorf("unmarshal big int bytes: %w", err)
			}
			v.SetBytes(bb)
			inputs[i] = v
		default:
			return fmt.Errorf("unknown tag %d", vin.Number)
		}
	}
	h.ID = v.ID
	h.Inputs = inputs
	h.Wires = v.Wires
	return nil
}
