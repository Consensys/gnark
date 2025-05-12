package gkrgates

/*
func TestRegisterGateDegreeDetection(t *testing.T) {
	testGate := func(name GateName, f func(...fr.Element) fr.Element, nbIn, degree int) {
		t.Run(string(name), func(t *testing.T) {
			name = name + "-register-gate-test"

			assert.NoError(t, RegisterGate(name, f, nbIn, WithDegree(degree)), "given degree must be accepted")

			assert.Error(t, RegisterGate(name, f, nbIn, WithDegree(degree-1)), "lower degree must be rejected")

			assert.Error(t, RegisterGate(name, f, nbIn, WithDegree(degree+1)), "higher degree must be rejected")

			assert.NoError(t, RegisterGate(name, f, nbIn), "no degree must be accepted")

			assert.Equal(t, degree, gkrgate.name).Degree(), "degree must be detected correctly")
		})
	}

	testGate("select", func(x ...fr.Element) fr.Element {
		return x[0]
	}, 3, 1)

	testGate("add2", func(x ...fr.Element) fr.Element {
		var res fr.Element
		res.Add(&x[0], &x[1])
		res.Add(&res, &x[2])
		return res
	}, 3, 1)

	testGate("mul2", func(x ...fr.Element) fr.Element {
		var res fr.Element
		res.Mul(&x[0], &x[1])
		return res
	}, 2, 2)

	testGate("mimc", mimcRound, 2, 7)

	testGate("sub2PlusOne", func(x ...fr.Element) fr.Element {
		var res fr.Element
		res.
			SetOne().
			Add(&res, &x[0]).
			Sub(&res, &x[1])
		return res
	}, 2, 1)

	// zero polynomial must not be accepted
	t.Run("zero", func(t *testing.T) {
		const gateName GateName = "zero-register-gate-test"
		expectedError := fmt.Errorf("for gate %s: %v", gateName, errZeroFunction)
		zeroGate := func(x ...fr.Element) fr.Element {
			var res fr.Element
			return res
		}
		assert.Equal(t, expectedError, RegisterGate(gateName, zeroGate, 1))

		assert.Equal(t, expectedError, RegisterGate(gateName, zeroGate, 1, WithDegree(2)))
	})
}
*/
