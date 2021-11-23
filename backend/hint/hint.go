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
function hintFn according to the Function type. Then, in a circuit, the
developer applies the hint function with frontend.API.NewHint(hintFn, vars...),
where vars are the variables the hint function will be applied to (and
correspond to the argument inputs in the Function type) which returns a new
unconstrained variable. The returned variable must be constrained using
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
	"hash/fnv"
	"math/big"
	"reflect"
	"runtime"

	"github.com/consensys/gnark-crypto/ecc"
)

// ID is a unique identifier for an hint function. It is set by the package in
// is used for lookup.
type ID uint32

// Function defines how a hint is computed from the inputs. The hint value is
// stored in result. If the hint is computable, then the functio must return a
// nil error and non-nil error otherwise.
type Function func(curveID ecc.ID, inputs []*big.Int, result *big.Int) error

// UUID returns a unique ID for the hint function. Multiple calls using same
// function return the same ID.
func UUID(hintFn Function) ID {
	name := runtime.FuncForPC(reflect.ValueOf(hintFn).Pointer()).Name()
	h := fnv.New32a()
	_, _ = h.Write([]byte(name))
	return ID(h.Sum32())
}
