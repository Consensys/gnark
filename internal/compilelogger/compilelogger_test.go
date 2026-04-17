package compilelogger_test

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/internal/compilelogger"
	"github.com/consensys/gnark/logger"
	"github.com/rs/zerolog"

	"github.com/consensys/gnark-crypto/ecc"
)

// testCircuit calls LogOnce twice with key "dup" and once with key "unique".
type testCircuit struct {
	X frontend.Variable
}

func (c *testCircuit) Define(api frontend.API) error {
	compiler, ok := api.(frontend.Compiler)
	if !ok {
		panic("api is not a compiler")
	}
	compilelogger.LogOnce(compiler, zerolog.WarnLevel, "dup", "duplicate message")
	compilelogger.LogOnce(compiler, zerolog.WarnLevel, "dup", "duplicate message")
	compilelogger.LogOnce(compiler, zerolog.WarnLevel, "unique", "unique message")
	api.AssertIsEqual(c.X, c.X)
	return nil
}

// exampleCircuit emits two log calls with the same key and one with a distinct key.
type exampleCircuit struct{ X frontend.Variable }

func (c *exampleCircuit) Define(api frontend.API) error {
	compiler := api.(frontend.Compiler)
	compilelogger.LogOnce(compiler, zerolog.WarnLevel, "key-a", "warning A")
	compilelogger.LogOnce(compiler, zerolog.WarnLevel, "key-a", "warning A") // suppressed: same key
	compilelogger.LogOnce(compiler, zerolog.WarnLevel, "key-b", "warning B")
	api.AssertIsEqual(c.X, c.X)
	return nil
}

func ExampleLogOnce() {
	// WarnLevel filters the framework's own info logs so only our messages appear.
	logger.Set(zerolog.New(os.Stdout).Level(zerolog.WarnLevel))
	defer logger.Disable()

	_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &exampleCircuit{})
	if err != nil {
		fmt.Println("compile error:", err)
	}
	// Output:
	// {"level":"warn","message":"warning A"}
	// {"level":"warn","message":"warning B"}
}

func TestLogOnce(t *testing.T) {
	var buf bytes.Buffer
	logger.Set(zerolog.New(&buf).Level(zerolog.WarnLevel))
	defer logger.Disable()

	_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &testCircuit{})
	if err != nil {
		t.Fatal(err)
	}

	output := buf.String()

	dupCount := strings.Count(output, "duplicate message")
	if dupCount != 1 {
		t.Errorf("expected 'duplicate message' to appear 1 time, got %d\noutput:\n%s", dupCount, output)
	}

	uniqueCount := strings.Count(output, "unique message")
	if uniqueCount != 1 {
		t.Errorf("expected 'unique message' to appear 1 time, got %d\noutput:\n%s", uniqueCount, output)
	}
}
