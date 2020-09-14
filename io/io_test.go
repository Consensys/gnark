package io

import (
	"bytes"
	"testing"

	"github.com/consensys/gurvy"

	"github.com/leanovate/gopter/gen"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/prop"
)

type data struct {
	Str     string
	Uint    uint64
	curveID gurvy.ID
}

func (c *data) GetCurveID() gurvy.ID {
	return c.curveID
}

func TestRoundTrip(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100

	properties := gopter.NewProperties(parameters)
	properties.Property("deserialization(serialization(string)) == string", prop.ForAll(
		func(a string) bool {
			var buff bytes.Buffer
			Write(&buff, &data{Str: a})
			var result data
			Read(&buff, &result)
			return a == result.Str
		},
		gen.AnyString(),
	))

	properties.Property("deserialization(serialization(uint64)) == uint64", prop.ForAll(
		func(a uint64) bool {
			var buff bytes.Buffer
			Write(&buff, &data{Uint: a})
			var result data
			Read(&buff, &result)
			return a == result.Uint
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
			Write(&buff, &data{Uint: a, curveID: curveID})
			var result data
			result.curveID = (curveID + 1) % 4
			err := Read(&buff, &result)
			return err == errInvalidCurve
		},
		gen.UInt64(),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}
