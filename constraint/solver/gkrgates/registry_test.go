package gkrgates

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/gkr/gkrtesting"
	"github.com/consensys/gnark/internal/gkr/gkrtypes"
	"github.com/consensys/gnark/std/gkrapi/gkr"
	"github.com/stretchr/testify/assert"
)

func TestRegister(t *testing.T) {
	testGate := func(name gkr.GateName, f gkr.GateFunction, nbIn, degree int) {
		t.Run(string(name), func(t *testing.T) {
			name = name + "-register-gate-test"

			added, err := Register(f, nbIn, WithDegree(degree), WithName(name+"_given"))
			assert.NoError(t, err, "given degree must be accepted")
			assert.True(t, added, "registration must succeed for given degree")

			registered, err := Register(f, nbIn, WithDegree(degree-1), WithName(name+"_lower"))
			assert.Error(t, err, "error must be returned for lower degree")
			assert.False(t, registered, "registration must fail for lower degree")

			registered, err = Register(f, nbIn, WithDegree(degree+1), WithName(name+"_higher"))
			assert.Error(t, err, "error must be returned for higher degree")
			assert.False(t, registered, "registration must fail for higher degree")

			registered, err = Register(f, nbIn, WithName(name+"_no_degree"))
			assert.NoError(t, err, "no error must be returned when no degree is specified")
			assert.True(t, registered, "registration must succeed when no degree is specified")

			assert.Equal(t, degree, Get(name+"_no_degree").Degree(), "degree must be detected correctly")

			added, err = Register(f, nbIn, WithDegree(degree), WithName(name+"_given"))
			assert.NoError(t, err, "given degree must be accepted")
			assert.False(t, added, "gate must not be re-registered")

			added, err = Register(func(api gkr.GateAPI, x ...frontend.Variable) frontend.Variable {
				return api.Add(f(api, x...), 1)
			}, nbIn, WithDegree(degree), WithName(name+"_given"))
			assert.Error(t, err, "registering another function under the same name must fail")
			assert.False(t, added, "gate must not be re-registered")
		})
	}

	testGate("select", func(api gkr.GateAPI, x ...frontend.Variable) frontend.Variable {
		return x[0]
	}, 3, 1)

	testGate("add3", func(api gkr.GateAPI, x ...frontend.Variable) frontend.Variable {
		return api.Add(x[0], x[1], x[2])
	}, 3, 1)

	testGate("mul2", gkrtypes.Mul2().Evaluate, 2, 2)

	testGate("mimc", gkrtesting.NewCache().GetGate("mimc").Evaluate, 2, 7)

	testGate("sub2PlusOne", func(api gkr.GateAPI, x ...frontend.Variable) frontend.Variable {
		return api.Sub(
			api.Add(1, x[0]),
			x[1],
		)
	}, 2, 1)

	t.Run("zero", func(t *testing.T) {
		const gateName gkr.GateName = "zero-register-gate-test"
		expectedError := fmt.Errorf("for gate \"%s\": %v", gateName, gkrtypes.ErrZeroFunction)
		zeroGate := func(api gkr.GateAPI, x ...frontend.Variable) frontend.Variable {
			return api.Sub(x[0], x[0])
		}

		// Attempt to register the zero gate without specifying a degree
		registered, err := Register(zeroGate, 1, WithName(gateName))
		assert.Error(t, err, "error must be returned for zero polynomial")
		assert.Equal(t, expectedError, err, "error message must match expected error")
		assert.False(t, registered, "registration must fail for zero polynomial")

		// Attempt to register the zero gate with a specified degree
		registered, err = Register(zeroGate, 1, WithName(gateName), WithDegree(2))
		assert.Error(t, err, "error must be returned for zero polynomial with degree")
		assert.Equal(t, expectedError, err, "error message must match expected error")
		assert.False(t, registered, "registration must fail for zero polynomial with degree")
	})
}
