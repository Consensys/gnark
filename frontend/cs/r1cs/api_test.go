package r1cs

import (
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/schema"
	"github.com/consensys/gnark/internal/tinyfield"
)

func TestPrintf(t *testing.T) {
	var circuit struct {
		X, Y frontend.Variable
	}

	builder := newBuilder(tinyfield.Modulus(), frontend.CompileConfig{})

	// Create LeafInfo for variables
	xInfo := schema.LeafInfo{
		FullName:   func() string { return "X" },
		Visibility: schema.Public,
	}
	yInfo := schema.LeafInfo{
		FullName:   func() string { return "Y" },
		Visibility: schema.Public,
	}

	circuit.X = builder.PublicVariable(xInfo)
	circuit.Y = builder.PublicVariable(yInfo)

	// Test different format specifiers
	builder.Printf("X in different formats: dec=%d hex=%x bin=%b default=%v", circuit.X, circuit.X, circuit.X, circuit.X)

	// Test multiple variables
	builder.Printf("X=%d Y=%d sum=%d", circuit.X, circuit.Y, builder.Add(circuit.X, circuit.Y))

	// Test escaping %%
	builder.Printf("100%% sure that X=%d", circuit.X)

	// Get logs from constraint system
	logs := builder.cs.GetLogs()
	if len(logs) != 3 {
		t.Errorf("expected 3 log entries, got %d", len(logs))
	}

	// Verify format specifiers are stored correctly
	if len(logs[0].FormatSpecifiers) != 4 {
		t.Errorf("expected 4 format specifiers, got %d", len(logs[0].FormatSpecifiers))
	}
	if logs[0].FormatSpecifiers[0] != "d" {
		t.Errorf("expected 'd' format specifier, got %s", logs[0].FormatSpecifiers[0])
	}
}
