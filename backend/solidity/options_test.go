package solidity_test

import (
	"strings"
	"testing"

	"github.com/consensys/gnark/backend/solidity"
)

func TestSortedImports(t *testing.T) {
	cfg, err := solidity.NewExportConfig(
		solidity.WithImport(strings.NewReader(`import { B } from "b.sol";`)),
		solidity.WithImport(strings.NewReader(`import { A } from "a.sol";`)),
		solidity.WithImport(strings.NewReader(`import { C } from "c.sol";`)),
	)
	if err != nil {
		t.Fatal(err)
	}
	imports := cfg.SortedImports()
	if len(imports) != 3 {
		t.Fatalf("expected 3 imports, got %d", len(imports))
	}
	if imports[0] != `import { A } from "a.sol";` {
		t.Errorf("expected first import to be A, got %s", imports[0])
	}
	if imports[1] != `import { B } from "b.sol";` {
		t.Errorf("expected second import to be B, got %s", imports[1])
	}
	if imports[2] != `import { C } from "c.sol";` {
		t.Errorf("expected third import to be C, got %s", imports[2])
	}
}

func TestInterfaceDeclaration(t *testing.T) {
	tests := []struct {
		name       string
		interfaces []string
		expected   string
	}{
		{
			name:       "no interfaces",
			interfaces: nil,
			expected:   "",
		},
		{
			name:       "single interface",
			interfaces: []string{"IVerifier"},
			expected:   " is IVerifier",
		},
		{
			name:       "multiple interfaces",
			interfaces: []string{"IVerifier", "IPlonk"},
			expected:   " is IVerifier, IPlonk",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := make([]solidity.ExportOption, 0, len(tt.interfaces))
			for _, iface := range tt.interfaces {
				opts = append(opts, solidity.WithInterface(strings.NewReader(iface)))
			}
			cfg, err := solidity.NewExportConfig(opts...)
			if err != nil {
				t.Fatal(err)
			}
			if got := cfg.InterfaceDeclaration(); got != tt.expected {
				t.Errorf("InterfaceDeclaration() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestWithConstants(t *testing.T) {
	cfg, err := solidity.NewExportConfig(
		solidity.WithConstants(strings.NewReader("  bytes32 private immutable CHAIN_CONFIG;")),
	)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Constants != "  bytes32 private immutable CHAIN_CONFIG;" {
		t.Errorf("unexpected constants: %s", cfg.Constants)
	}
}

func TestWithConstructor(t *testing.T) {
	constructor := `  constructor(bytes32 config) {
    CHAIN_CONFIG = config;
  }`
	cfg, err := solidity.NewExportConfig(
		solidity.WithConstructor(strings.NewReader(constructor)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Constructor != constructor {
		t.Errorf("unexpected constructor: %s", cfg.Constructor)
	}
}

func TestWithFunctions(t *testing.T) {
	functions := `  function getConfig() external view returns (bytes32) {
    return CHAIN_CONFIG;
  }`
	cfg, err := solidity.NewExportConfig(
		solidity.WithFunctions(strings.NewReader(functions)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Functions != functions {
		t.Errorf("unexpected functions: %s", cfg.Functions)
	}
}

func TestEmptyConfig(t *testing.T) {
	cfg, err := solidity.NewExportConfig()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.SortedImports()) != 0 {
		t.Error("expected no imports")
	}
	if cfg.InterfaceDeclaration() != "" {
		t.Error("expected empty interface declaration")
	}
	if cfg.Constants != "" {
		t.Error("expected empty constants")
	}
	if cfg.Constructor != "" {
		t.Error("expected empty constructor")
	}
	if cfg.Functions != "" {
		t.Error("expected empty functions")
	}
}
