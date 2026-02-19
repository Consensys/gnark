package solidity_test

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/solidity"
	"github.com/consensys/gnark/test"
	"golang.org/x/crypto/sha3"
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

func newGroth16Options() []solidity.ExportOption {
	return []solidity.ExportOption{
		solidity.WithHashToFieldFunction(sha3.NewLegacyKeccak256()),
		solidity.WithImport(strings.NewReader(`import { B } from "b.sol";`)),
		solidity.WithImport(strings.NewReader(`import { A } from "a.sol";`)),
		solidity.WithInterface(strings.NewReader("IVerifier")),
		solidity.WithConstants(strings.NewReader("	bytes32 private immutable CHAIN_CONFIG;")),
		solidity.WithConstructor(strings.NewReader(`	constructor(bytes32 config) {
		CHAIN_CONFIG = config;
  }`)),
		solidity.WithFunctions(strings.NewReader(`	function getConfig() external view returns (bytes32) {
		return CHAIN_CONFIG;
  }`)),
	}
}

func newPlonkOptions() []solidity.ExportOption {
	return []solidity.ExportOption{
		solidity.WithImport(strings.NewReader(`import { B } from "b.sol";`)),
		solidity.WithImport(strings.NewReader(`import { A } from "a.sol";`)),
		solidity.WithInterface(strings.NewReader("IVerifier")),
		solidity.WithConstants(strings.NewReader("	bytes32 private immutable CHAIN_CONFIG;")),
		solidity.WithConstructor(strings.NewReader(`	constructor(bytes32 config) {
		CHAIN_CONFIG = config;
  }`)),
		solidity.WithFunctions(strings.NewReader(`	function getConfig() external view returns (bytes32) {
		return CHAIN_CONFIG;
  }`)),
	}
}

func TestWriteContractsGroth16Options(t *testing.T) {
	t.Skip("temporary test to write out existing contracts")
	assert := test.NewAssert(t)
	for _, curve := range []ecc.ID{ecc.BN254, ecc.BLS12_381} {
		cn := curveShortName(curve)
		// groth16 no commitment
		vk := groth16.NewVerifyingKey(curve)
		vkf, err := os.Open("testdata/blank_groth16_" + cn + "_nocommit.vk")
		assert.NoError(err)
		_, err = vk.ReadFrom(vkf)
		vkf.Close()
		assert.NoError(err)
		solf, err := os.Create("testdata/alloptions_groth16_" + cn + "_nocommit.sol")
		assert.NoError(err)
		err = vk.ExportSolidity(solf, newGroth16Options()...)
		solf.Close()
		assert.NoError(err)
		// groth16 single commitment
		vk = groth16.NewVerifyingKey(curve)
		vkf, err = os.Open("testdata/blank_groth16_" + cn + "_commit.vk")
		assert.NoError(err)
		_, err = vk.ReadFrom(vkf)
		vkf.Close()
		assert.NoError(err)
		solf, err = os.Create("testdata/alloptions_groth16_" + cn + "_commit.sol")
		assert.NoError(err)
		err = vk.ExportSolidity(solf, newGroth16Options()...)
		solf.Close()
		assert.NoError(err)
	}
}

func TestWriteContractsPlonkOptions(t *testing.T) {
	t.Skip("temporary test to write out existing contracts")
	assert := test.NewAssert(t)
	for _, curve := range []ecc.ID{ecc.BN254, ecc.BLS12_381} {
		cn := curveShortName(curve)
		// plonk no commitment
		vk := plonk.NewVerifyingKey(curve)
		vkf, err := os.Open("testdata/blank_plonk_" + cn + "_nocommit.vk")
		assert.NoError(err)
		_, err = vk.ReadFrom(vkf)
		vkf.Close()
		assert.NoError(err)
		solf, err := os.Create("testdata/alloptions_plonk_" + cn + "_nocommit.sol")
		assert.NoError(err)
		err = vk.ExportSolidity(solf, newPlonkOptions()...)
		solf.Close()
		assert.NoError(err)
		// plonk single commitment
		vk = plonk.NewVerifyingKey(curve)
		vkf, err = os.Open("testdata/blank_plonk_" + cn + "_commit.vk")
		assert.NoError(err)
		_, err = vk.ReadFrom(vkf)
		vkf.Close()
		assert.NoError(err)
		solf, err = os.Create("testdata/alloptions_plonk_" + cn + "_commit.sol")
		assert.NoError(err)
		err = vk.ExportSolidity(solf, newPlonkOptions()...)
		solf.Close()
		assert.NoError(err)
	}
}

func TestOutput(t *testing.T) {
	assert := test.NewAssert(t)

	curves := []ecc.ID{ecc.BN254, ecc.BLS12_381}

	// helper to run snapshot comparison for a given VK file
	testSnapshot := func(assert *test.Assert, vk interface {
		io.ReaderFrom
		solidity.VerifyingKey
	}, vkFile, blankFile, optionsFile string, optsFn func() []solidity.ExportOption) {
		vkf, err := os.Open(vkFile)
		assert.NoError(err)
		_, err = vk.ReadFrom(vkf)
		vkf.Close()
		assert.NoError(err)
		assert.Run(func(assert *test.Assert) {
			existing, err := os.ReadFile(blankFile)
			assert.NoError(err)
			var b bytes.Buffer
			err = vk.ExportSolidity(&b)
			assert.NoError(err)
			assert.Equal(existing, b.Bytes())
		}, "blank")
		assert.Run(func(assert *test.Assert) {
			existing, err := os.ReadFile(optionsFile)
			assert.NoError(err)
			var b bytes.Buffer
			err = vk.ExportSolidity(&b, optsFn()...)
			assert.NoError(err)
			assert.Equal(existing, b.Bytes())
		}, "options")
	}

	assert.Run(func(assert *test.Assert) {
		for _, curve := range curves {
			cn := curveShortName(curve)
			assert.Run(func(assert *test.Assert) {
				assert.Run(func(assert *test.Assert) {
					vk := groth16.NewVerifyingKey(curve)
					testSnapshot(assert, vk,
						fmt.Sprintf("testdata/blank_groth16_%s_nocommit.vk", cn),
						fmt.Sprintf("testdata/blank_groth16_%s_nocommit.sol", cn),
						fmt.Sprintf("testdata/alloptions_groth16_%s_nocommit.sol", cn),
						newGroth16Options,
					)
				}, "nocommit")
				assert.Run(func(assert *test.Assert) {
					vk := groth16.NewVerifyingKey(curve)
					testSnapshot(assert, vk,
						fmt.Sprintf("testdata/blank_groth16_%s_commit.vk", cn),
						fmt.Sprintf("testdata/blank_groth16_%s_commit.sol", cn),
						fmt.Sprintf("testdata/alloptions_groth16_%s_commit.sol", cn),
						newGroth16Options,
					)
				}, "commit")
			}, cn)
		}
	}, "groth16")
	assert.Run(func(assert *test.Assert) {
		for _, curve := range curves {
			cn := curveShortName(curve)
			assert.Run(func(assert *test.Assert) {
				assert.Run(func(assert *test.Assert) {
					vk := plonk.NewVerifyingKey(curve)
					testSnapshot(assert, vk,
						fmt.Sprintf("testdata/blank_plonk_%s_nocommit.vk", cn),
						fmt.Sprintf("testdata/blank_plonk_%s_nocommit.sol", cn),
						fmt.Sprintf("testdata/alloptions_plonk_%s_nocommit.sol", cn),
						newPlonkOptions,
					)
				}, "nocommit")
				assert.Run(func(assert *test.Assert) {
					vk := plonk.NewVerifyingKey(curve)
					testSnapshot(assert, vk,
						fmt.Sprintf("testdata/blank_plonk_%s_commit.vk", cn),
						fmt.Sprintf("testdata/blank_plonk_%s_commit.sol", cn),
						fmt.Sprintf("testdata/alloptions_plonk_%s_commit.sol", cn),
						newPlonkOptions,
					)
				}, "commit")
			}, cn)
		}
	}, "plonk")
}
