/*
Package hint allows to define computations outside of a circuit.

Usually, it is expected that computations in circuits are performed on
variables. However, in some cases defining the computations in circuits may be
complicated or computationally expensive. By using hints, the computations are
performed outside of the circuit on integers (compared to the frontend.Variable
values inside the circuits) and the result of a hint function is assigned to a
newly created variable in a circuit.

As the computations are perfomed outside of the circuit, then the correctness of
the result is not guaranteed. This also means that the result of a hint function
is unconstrained by default, leading to failure while composing circuit proof.
Thus, it is the circuit developer responsibility to verify the correctness hint
result by adding necessary constraints in the circuit.

As an example, lets say the hint function computes a factorization of a
semiprime n:

    p, q <- hint(n) st. p * q = n

into primes p and q. Then, the circuit developer needs to assert in the circuit
that p*q indeed equals to n:

    n == p * q.

However, if the hint function is incorrectly defined (e.g. in the previous
example, it returns 1 and n instead of p and q), then the assertion may still
hold, but the constructed proof is semantically invalid. Thus, the user
constructing the proof must be extremely cautious when using hints.

Using hint functions in circuits

To use a hint function in a circuit, the developer first needs to define a hint
function hintFn according to the Function interface. Then, in a circuit, the
developer applies the hint function with frontend.API.NewHint(hintFn, vars...),
where vars are the variables the hint function will be applied to (and
correspond to the argument inputs in the Function type) which returns a new
unconstrained variable. The returned variables must be constrained using
frontend.API.Assert[.*] methods.

As explained, the hints are essentially black boxes from the circuit point of
view and thus the defined hints in circuits are not used when constructing a
proof. To allow the particular hint functions to be used during proof
construction, the user needs to supply a backend.ProverOption indicating the
enabled hints. Such options can be optained by a call to
backend.WithHints(hintFns...), where hintFns are the corresponding hint
functions.

Using hint functions in gadgets

Similar considerations apply for hint functions used in gadgets as in
user-defined circuits. However, listing all hint functions used in a particular
gadget for constructing backend.ProverOption puts high overhead for the user to
enable all necessary hints.

For that, this package also provides a registry of trusted hint functions. When
a gadget registers a hint function, then it is automatically enabled during
proof computation and the prover does not need to provide a corresponding
proving option.

In the init() method of the gadget, call the method Register(hintFn) method on
the hint function hintFn to register a hint function in the package registry.
*/
package hint

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"math/big"
	"reflect"
	"runtime"

	"github.com/consensys/gnark-crypto/ecc"
)

// ID is a unique identifier for a hint function used for lookup.
type ID uint32

// Function defines an annotated hint function. To initialize a hint function
// with static number of inputs and outputs, use NewStaticHint().
type Function interface {
	// UUID returns an unique identifier for the hint function. UUID is used for
	// lookup of the hint function.
	UUID() ID

	// Call is invoked by the framework to obtain the result from inputs.
	// The length of res is TotalOutputs() and every element is
	// already initialized (but not necessarily to zero as the elements may be
	// obtained from cache). A returned non-nil error will be propagated.
	Call(curveID ecc.ID, inputs []*big.Int, res []*big.Int) error

	// TotalOutputs returns the total number of outputs by the function when
	// invoked on the curveID with nInputs number of inputs. The number of
	// outputs must be at least one and the framework errors otherwise.
	TotalOutputs(curveID ecc.ID, nInputs int) (nOutputs int)

	// String returns a human-readable description of the function used in logs
	// and debug messages.
	String() string
}

// UUID is a reference function for computing the hint ID based on a function
// and additional context values ctx. A change in any of the inputs modifies the
// returned value and thus this function can be used to compute the hint ID for
// same function in different contexts (for example, for different number of
// inputs and outputs).
func UUID(fn StaticFunction, ctx ...uint64) ID {
	var buf [8]byte
	hf := fnv.New32a()
	name := runtime.FuncForPC(reflect.ValueOf(fn).Pointer()).Name()
	// using a name for identifying different hints should be enough as we get a
	// solve-time error when there are duplicate hints with the same signature.
	hf.Write([]byte(name)) // #nosec G104 -- does not err
	// also feed all context values into the checksum do differentiate different
	// hints based on the same function.
	for _, ct := range ctx {
		binary.BigEndian.PutUint64(buf[:], uint64(ct))
		hf.Write(buf[:]) // #nosec G104 -- does not err
	}
	return ID(hf.Sum32())
}

// StaticFunction is a function which takes a constant number of inputs and
// returns a constant number of outputs. Use NewStaticHint() to construct an
// instance compatible with Function interface.
type StaticFunction func(curveID ecc.ID, inputs []*big.Int, res []*big.Int) error

// staticArgumentsFunction defines a function where the number of inputs and
// outputs is constant.
type staticArgumentsFunction struct {
	fn   StaticFunction
	nIn  int
	nOut int
}

// NewStaticHint returns an Function where the number of inputs and outputs is
// constant. UUID is computed by combining fn, nIn and nOut and thus it is legal
// to defined multiple AnnotatedFunctions on the same fn with different nIn and
// nOut.
func NewStaticHint(fn StaticFunction, nIn, nOut int) Function {
	return &staticArgumentsFunction{
		fn:   fn,
		nIn:  nIn,
		nOut: nOut,
	}
}

func (h *staticArgumentsFunction) Call(curveID ecc.ID, inputs []*big.Int, res []*big.Int) error {
	if len(inputs) != h.nIn {
		return fmt.Errorf("input has %d elements, expected %d", len(inputs), h.nIn)
	}
	if len(res) != h.nOut {
		return fmt.Errorf("result has %d elements, expected %d", len(res), h.nOut)
	}
	return h.fn(curveID, inputs, res)
}

func (h *staticArgumentsFunction) TotalOutputs(_ ecc.ID, _ int) int {
	return h.nOut
}

func (h *staticArgumentsFunction) UUID() ID {
	return UUID(h.fn, uint64(h.nIn), uint64(h.nOut))
}

func (h *staticArgumentsFunction) String() string {
	fnptr := reflect.ValueOf(h.fn).Pointer()
	name := runtime.FuncForPC(fnptr).Name()
	return fmt.Sprintf("%s([%d]*big.Int, [%d]*big.Int) at (%x)", name, h.nIn, h.nOut, fnptr)
}
