package encoding

import (
	"bytes"
	"testing"

	"github.com/consensys/gurvy"

	"github.com/leanovate/gopter/gen"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/prop"
)

func TestRoundTrip(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100

	properties := gopter.NewProperties(parameters)
	properties.Property("deserialization(serialization(string)) == string", prop.ForAll(
		func(a string) bool {
			var buff bytes.Buffer
			Serialize(&buff, a, gurvy.BLS381)
			var result string
			Deserialize(&buff, &result, gurvy.BLS381)
			return a == result
		},
		gen.AnyString(),
	))

	properties.Property("deserialization(serialization(uint64)) == uint64", prop.ForAll(
		func(a uint64) bool {
			var buff bytes.Buffer
			Serialize(&buff, a, gurvy.BLS381)
			var result uint64
			Deserialize(&buff, &result, gurvy.BLS381)
			return a == result
		},
		gen.UInt64(),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

func TestCurveEncoding(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100

	properties := gopter.NewProperties(parameters)
	properties.Property("using different curve ID in Serialize and Deserialize should fail", prop.ForAll(
		func(a uint64) bool {
			curveID := gurvy.ID(a % 4)
			var buff bytes.Buffer
			Serialize(&buff, a, curveID)
			var result uint64
			err := Deserialize(&buff, &result, (curveID+1)%4)
			return err == errInvalidCurve
		},
		gen.UInt64(),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}
