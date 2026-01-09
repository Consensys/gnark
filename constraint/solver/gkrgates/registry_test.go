package gkrgates

import (
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

			assert.NoError(t,
				Register(f, nbIn, WithDegree(degree), WithName(name+"_given")),
				"given degree must be accepted",
			)

			assert.Error(t,
				Register(f, nbIn, WithDegree(degree-1), WithName(name+"_lower")),
				"error must be returned for lower degree",
			)

			assert.Error(t,
				Register(f, nbIn, WithDegree(degree+1), WithName(name+"_higher")),
				"error must be returned for higher degree",
			)

			assert.NoError(t,
				Register(f, nbIn, WithName(name+"_no_degree")),
				"no error must be returned when no degree is specified",
			)

			assert.Equal(t, degree, Get(name+"_no_degree").Degree(), "degree must be detected correctly")

			err := Register(func(api gkr.GateAPI, x ...frontend.Variable) frontend.Variable {
				return api.Add(f(api, x...), 1)
			}, nbIn, WithDegree(degree), WithName(name+"_given"))
			assert.Error(t, err, "registering another function under the same name must fail")
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
		zeroGate := func(api gkr.GateAPI, x ...frontend.Variable) frontend.Variable {
			return api.Sub(x[0], x[0])
		}

		// Attempt to register the zero gate without specifying a degree
		assert.Error(t,
			Register(zeroGate, 1, WithName(gateName)),
			"error must be returned for zero polynomial",
		)

		// Attempt to register the zero gate with a specified degree
		assert.Error(t,
			Register(zeroGate, 1, WithName(gateName), WithDegree(2)),
			"error must be returned for zero polynomial with degree",
		)
	})
}
