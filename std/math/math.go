package math

import "github.com/consensys/gnark/frontend"

type Math struct {
	api frontend.API // underlying constraint system
}

func NewMath(api frontend.API) (Math, error) {
	return Math{api}, nil
}

// Returns 1 if a < b
func (m *Math) LessThan(a, b frontend.Variable) frontend.Variable {
	aBits := m.api.ToBinary(a)
	bBits := m.api.ToBinary(b)

	var output frontend.Variable
	output = 0

	// This section performs Compare()
	// Output is 1 if a > b
	// Output is 0 if a == b
	// Output is -1 if a < b

	// Backwards due to little endian
	for i := len(aBits) - 1; i >= 0; i-- {
		m.api.AssertIsBoolean(aBits[i])
		m.api.AssertIsBoolean(bBits[i])

		aIsOne := aBits[i]
		bIsOne := bBits[i]

		aIsNotOne := m.api.IsZero(aBits[i])
		bIsNotOne := m.api.IsZero(bBits[i])

		aBeatsB := m.api.And(aIsOne, bIsNotOne)
		bBeatsA := m.api.And(bIsOne, aIsNotOne)

		newOutput := m.api.Select(aBeatsB, 1, 0)
		newOutput = m.api.Select(bBeatsA, -1, newOutput)

		output = m.api.Select(m.api.IsZero(output), newOutput, output)
	}

	// Now, convert output of Convert() into LessThan()
	return m.IsEqual(output, -1)
}

func (m *Math) IsEqual(a, b frontend.Variable) frontend.Variable {
	return m.api.IsZero(m.api.Sub(a, b))
}
