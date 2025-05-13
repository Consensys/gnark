package gkrgates

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/gkr/gkrtesting"
	"github.com/consensys/gnark/internal/gkr/gkrtypes"
	"github.com/consensys/gnark/std/gkr"
	"github.com/stretchr/testify/assert"
)

func TestRegisterDegreeDetection(t *testing.T) {
	testGate := func(name gkr.GateName, f gkr.GateFunction, nbIn, degree int) {
		t.Run(string(name), func(t *testing.T) {
			name = name + "-register-gate-test"

			assert.NoError(t, Register(f, nbIn, WithDegree(degree), WithName(name)), "given degree must be accepted")

			assert.Error(t, Register(f, nbIn, WithDegree(degree-1), WithName(name)), "lower degree must be rejected")

			assert.Error(t, Register(f, nbIn, WithDegree(degree+1), WithName(name)), "higher degree must be rejected")

			assert.NoError(t, Register(f, nbIn), "no degree must be accepted")

			assert.Equal(t, degree, Get(name).Degree(), "degree must be detected correctly")
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

	// zero polynomial must not be accepted
	t.Run("zero", func(t *testing.T) {
		const gateName gkr.GateName = "zero-register-gate-test"
		expectedError := fmt.Errorf("for gate %s: %v", gateName, gkrtypes.ErrZeroFunction)
		zeroGate := func(api gkr.GateAPI, x ...frontend.Variable) frontend.Variable {
			return api.Sub(x[0], x[0])
		}
		assert.Equal(t, expectedError, Register(zeroGate, 1, WithName(gateName)))

		assert.Equal(t, expectedError, Register(zeroGate, 1, WithName(gateName), WithDegree(2)))
	})
}
