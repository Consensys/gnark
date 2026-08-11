package compilelogger_test

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/internal/compilelogger"

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
	compilelogger.LogOnce(compiler, slog.LevelWarn, "dup", "duplicate message")
	compilelogger.LogOnce(compiler, slog.LevelWarn, "dup", "duplicate message")
	compilelogger.LogOnce(compiler, slog.LevelWarn, "unique", "unique message")
	api.AssertIsEqual(c.X, c.X)
	return nil
}

// exampleCircuit emits two log calls with the same key and one with a distinct key.
type exampleCircuit struct{ X frontend.Variable }

func (c *exampleCircuit) Define(api frontend.API) error {
	compiler := api.(frontend.Compiler)
	compilelogger.LogOnce(compiler, slog.LevelWarn, "key-a", "warning A")
	compilelogger.LogOnce(compiler, slog.LevelWarn, "key-a", "warning A") // suppressed: same key
	compilelogger.LogOnce(compiler, slog.LevelWarn, "key-b", "warning B")
	api.AssertIsEqual(c.X, c.X)
	return nil
}

func ExampleLogOnce() {
	// WarnLevel filters the framework's own info logs so only our messages appear.
	log := slog.New(slog.NewJSONHandler(
		os.Stdout,
		&slog.HandlerOptions{
			Level: slog.LevelWarn,
			ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
				if a.Key == slog.TimeKey && a.Value.Kind() == slog.KindTime {
					return slog.Attr{}
				}
				return a
			}}))

	_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &exampleCircuit{}, frontend.WithLogger(log))
	if err != nil {
		fmt.Println("compile error:", err)
	}
	// Output:
	// {"level":"WARN","msg":"warning A"}
	// {"level":"WARN","msg":"warning B"}
}

func TestLogOnce(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &testCircuit{}, frontend.WithLogger(log))
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
