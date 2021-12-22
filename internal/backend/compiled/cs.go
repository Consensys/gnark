package compiled

import (
	"fmt"
	"io"
	"math/big"
	"reflect"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/hint"
	"github.com/fxamacker/cbor/v2"
)

// CS contains common element between R1CS and CS
type CS struct {

	// number of wires
	NbInternalVariables int
	NbPublicVariables   int
	NbSecretVariables   int

	// logs (added with cs.Println, resolved when solver sets a value to a wire)
	Logs []LogEntry
	// debug info contains stack trace (including line number) of a call to a cs.API that
	// results in an unsolved constraint
	DebugInfo []LogEntry

	// maps constraint id to debugInfo id
	// several constraints may point to the same debug info
	MDebug map[int]int

	Counters []Counter // TODO @gbotrel no point in serializing these
	// maps wire id to hint

	// a wire may point to at most one hint
	MHints map[int]Hint
}

// Visibility encodes a Variable (or wire) visibility
// Possible values are Unset, Internal, Secret or Public
type Visibility uint8

const (
	Unset Visibility = iota
	Internal
	Secret
	Public
	Virtual
)

// Hint represents a solver hint
// it enables the solver to compute a Wire with a function provided at solving time
// using pre-defined inputs
type Hint struct {
	ID     hint.ID       // hint function id
	Inputs []interface{} // terms to inject in the hint function
}

func (h Hint) inputsCBORTags() (cbor.TagSet, error) {
	defTagOpts := cbor.TagOptions{EncTag: cbor.EncTagRequired, DecTag: cbor.DecTagRequired}
	tags := cbor.NewTagSet()
	if err := tags.Add(defTagOpts, reflect.TypeOf(LinearExpression{}), 25443); err != nil {
		return nil, fmt.Errorf("new LE tag: %w", err)
	}
	if err := tags.Add(defTagOpts, reflect.TypeOf(Variable{}), 25444); err != nil {
		return nil, fmt.Errorf("new variable tag: %w", err)
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
	v := vt{ID: h.ID, Inputs: inputs}
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
		case 25444:
			var v Variable
			if err := dec.Unmarshal(vin.Content, &v); err != nil {
				return fmt.Errorf("unmarshal variable: %w", err)
			}
			inputs[i] = v
		case 25445:
			var v Term
			if err := dec.Unmarshal(vin.Content, &v); err != nil {
				return fmt.Errorf("unmarshal term: %w", err)
			}
			inputs[i] = v
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
	return nil
}

// GetNbVariables return number of internal, secret and public variables
func (cs *CS) GetNbVariables() (internal, secret, public int) {
	return cs.NbInternalVariables, cs.NbSecretVariables, cs.NbPublicVariables
}

// FrSize panics
func (cs *CS) FrSize() int { panic("not implemented") }

// GetNbCoefficients panics
func (cs *CS) GetNbCoefficients() int { panic("not implemented") }

// CurveID returns ecc.UNKNOWN
func (cs *CS) CurveID() ecc.ID { return ecc.UNKNOWN }

// WriteTo panics
func (cs *CS) WriteTo(w io.Writer) (n int64, err error) { panic("not implemented") }

// ReadFrom panics
func (cs *CS) ReadFrom(r io.Reader) (n int64, err error) { panic("not implemented") }

// ToHTML panics
func (cs *CS) ToHTML(w io.Writer) error { panic("not implemtened") }

// GetCounters return the collected constraint counters, if any
func (cs *CS) GetCounters() []Counter { return cs.Counters }

// Counter contains measurements of useful statistics between two Tag
type Counter struct {
	From, To      string
	NbVariables   int
	NbConstraints int
	CurveID       ecc.ID
	BackendID     backend.ID
}

func (c Counter) String() string {
	return fmt.Sprintf("%s[%s] %s - %s: %d variables, %d constraints", c.BackendID, c.CurveID, c.From, c.To, c.NbVariables, c.NbConstraints)
}
