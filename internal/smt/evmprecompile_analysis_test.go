package smt

import (
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	bls12381fp "github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	bls12381fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	bn254fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/ecdsa"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/evmprecompiles"
	"github.com/consensys/gnark/std/math/emulated"
)

// ===============================
// Circuit wrapper definitions
// ===============================

// ECRecoverCircuit wraps the ECRecover precompile (0x01)
type ECRecoverCircuit struct {
	Message   emulated.Element[emulated.Secp256k1Fr]
	V         frontend.Variable
	R         emulated.Element[emulated.Secp256k1Fr]
	S         emulated.Element[emulated.Secp256k1Fr]
	Strict    frontend.Variable
	IsFailure frontend.Variable
	Expected  sw_emulated.AffinePoint[emulated.Secp256k1Fp]
}

func (c *ECRecoverCircuit) Define(api frontend.API) error {
	curve, err := sw_emulated.New[emulated.Secp256k1Fp, emulated.Secp256k1Fr](api, sw_emulated.GetSecp256k1Params())
	if err != nil {
		return fmt.Errorf("new curve: %w", err)
	}
	res := evmprecompiles.ECRecover(api, c.Message, c.V, c.R, c.S, c.Strict, c.IsFailure)
	curve.AssertIsEqual(&c.Expected, res)
	return nil
}

// ExpmodCircuit wraps the MODEXP precompile (0x05)
type ExpmodCircuit struct {
	Base    emulated.Element[Params4096]
	Exp     emulated.Element[Params4096]
	Modulus emulated.Element[Params4096]
	Result  emulated.Element[Params4096]
}

// Params4096 represents a 4096-bit field for expmod
type Params4096 struct{}

func (Params4096) NbLimbs() uint     { return 64 }
func (Params4096) BitsPerLimb() uint { return 64 }
func (Params4096) IsPrime() bool     { return false }
func (Params4096) Modulus() *big.Int {
	one := big.NewInt(1)
	return new(big.Int).Sub(new(big.Int).Lsh(one, 4096), one)
}

func (c *ExpmodCircuit) Define(api frontend.API) error {
	res := evmprecompiles.Expmod[Params4096](api, &c.Base, &c.Exp, &c.Modulus)
	f, err := emulated.NewField[Params4096](api)
	if err != nil {
		return err
	}
	f.AssertIsEqual(&c.Result, res)
	return nil
}

// ECAddCircuit wraps the ALT_BN128_ADD precompile (0x06)
type ECAddCircuit struct {
	X0       sw_emulated.AffinePoint[emulated.BN254Fp]
	X1       sw_emulated.AffinePoint[emulated.BN254Fp]
	Expected sw_emulated.AffinePoint[emulated.BN254Fp]
}

func (c *ECAddCircuit) Define(api frontend.API) error {
	curve, err := sw_emulated.New[emulated.BN254Fp, emulated.BN254Fr](api, sw_emulated.GetBN254Params())
	if err != nil {
		return err
	}
	res := evmprecompiles.ECAdd(api, &c.X0, &c.X1)
	curve.AssertIsEqual(res, &c.Expected)
	return nil
}

// ECMulCircuit wraps the ALT_BN128_MUL precompile (0x07)
type ECMulCircuit struct {
	X0       sw_emulated.AffinePoint[emulated.BN254Fp]
	U        emulated.Element[emulated.BN254Fr]
	Expected sw_emulated.AffinePoint[emulated.BN254Fp]
}

func (c *ECMulCircuit) Define(api frontend.API) error {
	curve, err := sw_emulated.New[emulated.BN254Fp, emulated.BN254Fr](api, sw_emulated.GetBN254Params())
	if err != nil {
		return err
	}
	res := evmprecompiles.ECMul(api, &c.X0, &c.U)
	curve.AssertIsEqual(res, &c.Expected)
	return nil
}

// ECPairCircuit wraps the ALT_BN128_PAIRING precompile (0x08)
type ECPairCircuit struct {
	P  sw_bn254.G1Affine
	NP sw_bn254.G1Affine
	Q  sw_bn254.G2Affine
}

func (c *ECPairCircuit) Define(api frontend.API) error {
	evmprecompiles.ECPair(api,
		[]*sw_emulated.AffinePoint[emulated.BN254Fp]{&c.P, &c.NP},
		[]*sw_bn254.G2Affine{&c.Q, &c.Q})
	return nil
}

// BLSAddG1Circuit wraps the BLS12_G1ADD precompile (0x0B/11)
type BLSAddG1Circuit struct {
	X0       sw_emulated.AffinePoint[emulated.BLS12381Fp]
	X1       sw_emulated.AffinePoint[emulated.BLS12381Fp]
	Expected sw_emulated.AffinePoint[emulated.BLS12381Fp]
}

func (c *BLSAddG1Circuit) Define(api frontend.API) error {
	evmprecompiles.ECAddG1BLS(api, &c.X0, &c.X1, &c.Expected)
	return nil
}

// BLSMSMG1Circuit wraps the BLS12_G1MSM precompile (0x0C/12)
type BLSMSMG1Circuit struct {
	Accumulator sw_emulated.AffinePoint[emulated.BLS12381Fp]
	Point       sw_emulated.AffinePoint[emulated.BLS12381Fp]
	Scalar      emulated.Element[emulated.BLS12381Fr]
	Result      sw_emulated.AffinePoint[emulated.BLS12381Fp]
}

func (c *BLSMSMG1Circuit) Define(api frontend.API) error {
	return evmprecompiles.ECG1ScalarMulSumBLS(api, &c.Accumulator, &c.Point, &c.Scalar, &c.Result)
}

// BLSAddG2Circuit wraps the BLS12_G2ADD precompile (0x0D/13)
type BLSAddG2Circuit struct {
	X0       sw_bls12381.G2Affine
	X1       sw_bls12381.G2Affine
	Expected sw_bls12381.G2Affine
}

func (c *BLSAddG2Circuit) Define(api frontend.API) error {
	evmprecompiles.ECAddG2BLS(api, &c.X0, &c.X1, &c.Expected)
	return nil
}

// BLSMSMG2Circuit wraps the BLS12_G2MSM precompile (0x0E/14)
type BLSMSMG2Circuit struct {
	Accumulator sw_bls12381.G2Affine
	Point       sw_bls12381.G2Affine
	Scalar      sw_bls12381.Scalar
	Result      sw_bls12381.G2Affine
}

func (c *BLSMSMG2Circuit) Define(api frontend.API) error {
	return evmprecompiles.ECG2ScalarMulSumBLS(api, &c.Accumulator, &c.Point, &c.Scalar, &c.Result)
}

// BLSPairCircuit wraps the BLS12_PAIRING precompile (0x0F/15)
type BLSPairCircuit struct {
	P  sw_bls12381.G1Affine
	NP sw_bls12381.G1Affine
	Q  sw_bls12381.G2Affine
}

func (c *BLSPairCircuit) Define(api frontend.API) error {
	evmprecompiles.ECPairBLS(api,
		[]*sw_emulated.AffinePoint[emulated.BLS12381Fp]{&c.P, &c.NP},
		[]*sw_bls12381.G2Affine{&c.Q, &c.Q})
	return nil
}

// BLSMapToG1Circuit wraps the BLS12_MAP_FP_TO_G1 precompile (0x10/16)
type BLSMapToG1Circuit struct {
	A emulated.Element[emulated.BLS12381Fp]
	R sw_bls12381.G1Affine
}

func (c *BLSMapToG1Circuit) Define(api frontend.API) error {
	return evmprecompiles.ECMapToG1BLS(api, &c.A, &c.R)
}

// BLSMapToG2Circuit wraps the BLS12_MAP_FP2_TO_G2 precompile (0x11/17)
type BLSMapToG2Circuit struct {
	A fields_bls12381.E2
	R sw_bls12381.G2Affine
}

func (c *BLSMapToG2Circuit) Define(api frontend.API) error {
	return evmprecompiles.ECMapToG2BLS(api, &c.A, &c.R)
}

// P256VerifyCircuit wraps the P256VERIFY precompile (0x100/256)
type P256VerifyCircuit struct {
	Msg emulated.Element[emulated.P256Fr]
	R   emulated.Element[emulated.P256Fr]
	S   emulated.Element[emulated.P256Fr]
	Qx  emulated.Element[emulated.P256Fp]
	Qy  emulated.Element[emulated.P256Fp]
}

func (c *P256VerifyCircuit) Define(api frontend.API) error {
	evmprecompiles.P256Verify(api, &c.Msg, &c.R, &c.S, &c.Qx, &c.Qy)
	return nil
}

// ===============================
// Analysis test
// ===============================

type precompileInfo struct {
	name        string
	address     string
	circuit     frontend.Circuit
	description string
}

func getPrecompiles() []precompileInfo {
	// Generate test data for BN254
	_, _, gBN254, _ := bn254.Generators()
	var uBN254, vBN254 bn254fr.Element
	uBN254.SetRandom()
	vBN254.SetRandom()
	var pBN254, qBN254 bn254.G1Affine
	pBN254.ScalarMultiplication(&gBN254, uBN254.BigInt(new(big.Int)))
	qBN254.ScalarMultiplication(&gBN254, vBN254.BigInt(new(big.Int)))
	var npBN254 bn254.G1Affine
	npBN254.Neg(&pBN254)
	_, _, _, gBN254G2 := bn254.Generators()
	var qBN254G2 bn254.G2Affine
	qBN254G2.ScalarMultiplication(&gBN254G2, vBN254.BigInt(new(big.Int)))

	// Generate test data for BLS12-381
	_, _, gBLS, _ := bls12381.Generators()
	var uBLS, vBLS bls12381fr.Element
	uBLS.SetRandom()
	vBLS.SetRandom()
	var pBLS, qBLS bls12381.G1Affine
	pBLS.ScalarMultiplication(&gBLS, uBLS.BigInt(new(big.Int)))
	qBLS.ScalarMultiplication(&gBLS, vBLS.BigInt(new(big.Int)))
	var npBLS bls12381.G1Affine
	npBLS.Neg(&pBLS)
	_, _, _, gBLSG2 := bls12381.Generators()
	var pBLSG2, qBLSG2 bls12381.G2Affine
	pBLSG2.ScalarMultiplication(&gBLSG2, uBLS.BigInt(new(big.Int)))
	qBLSG2.ScalarMultiplication(&gBLSG2, vBLS.BigInt(new(big.Int)))

	var zeroBLS bls12381.G1Affine
	zeroBLS.SetInfinity()
	var zeroBLSG2 bls12381.G2Affine
	zeroBLSG2.SetInfinity()

	var fpBLS bls12381fp.Element
	fpBLS.SetRandom()
	mapG1 := bls12381.MapToG1(fpBLS)

	var e2BLS bls12381.E2
	e2BLS.A0.SetRandom()
	e2BLS.A1.SetRandom()
	mapG2 := bls12381.MapToG2(e2BLS)

	return []precompileInfo{
		{
			name:        "ECRecover",
			address:     "0x01",
			circuit:     &ECRecoverCircuit{},
			description: "ECDSA signature recovery on secp256k1",
		},
		{
			name:        "ECAdd",
			address:     "0x06",
			circuit:     &ECAddCircuit{},
			description: "BN254 elliptic curve point addition",
		},
		{
			name:        "ECMul",
			address:     "0x07",
			circuit:     &ECMulCircuit{},
			description: "BN254 elliptic curve scalar multiplication",
		},
		{
			name:        "ECPair",
			address:     "0x08",
			circuit: &ECPairCircuit{
				P:  sw_bn254.NewG1Affine(pBN254),
				NP: sw_bn254.NewG1Affine(npBN254),
				Q:  sw_bn254.NewG2Affine(qBN254G2),
			},
			description: "BN254 pairing check",
		},
		{
			name:        "BLS_G1Add",
			address:     "0x0B",
			circuit:     &BLSAddG1Circuit{},
			description: "BLS12-381 G1 point addition",
		},
		{
			name:        "BLS_G1MSM",
			address:     "0x0C",
			circuit: &BLSMSMG1Circuit{
				Accumulator: sw_bls12381.NewG1Affine(zeroBLS),
				Point:       sw_bls12381.NewG1Affine(pBLS),
				Scalar:      emulated.ValueOf[emulated.BLS12381Fr](uBLS),
				Result:      sw_bls12381.NewG1Affine(pBLS),
			},
			description: "BLS12-381 G1 multi-scalar multiplication",
		},
		{
			name:        "BLS_G2Add",
			address:     "0x0D",
			circuit:     &BLSAddG2Circuit{},
			description: "BLS12-381 G2 point addition",
		},
		{
			name:        "BLS_G2MSM",
			address:     "0x0E",
			circuit: &BLSMSMG2Circuit{
				Accumulator: sw_bls12381.NewG2Affine(zeroBLSG2),
				Point:       sw_bls12381.NewG2Affine(pBLSG2),
				Scalar:      emulated.ValueOf[emulated.BLS12381Fr](uBLS),
				Result:      sw_bls12381.NewG2Affine(pBLSG2),
			},
			description: "BLS12-381 G2 multi-scalar multiplication",
		},
		{
			name:        "BLS_Pair",
			address:     "0x0F",
			circuit: &BLSPairCircuit{
				P:  sw_bls12381.NewG1Affine(pBLS),
				NP: sw_bls12381.NewG1Affine(npBLS),
				Q:  sw_bls12381.NewG2Affine(qBLSG2),
			},
			description: "BLS12-381 pairing check",
		},
		{
			name:        "BLS_MapToG1",
			address:     "0x10",
			circuit: &BLSMapToG1Circuit{
				A: emulated.ValueOf[emulated.BLS12381Fp](fpBLS.String()),
				R: sw_bls12381.NewG1Affine(mapG1),
			},
			description: "BLS12-381 hash to G1 curve",
		},
		{
			name:        "BLS_MapToG2",
			address:     "0x11",
			circuit: &BLSMapToG2Circuit{
				A: fields_bls12381.FromE2(&e2BLS),
				R: sw_bls12381.NewG2Affine(mapG2),
			},
			description: "BLS12-381 hash to G2 curve",
		},
		{
			name:        "P256Verify",
			address:     "0x100",
			circuit:     &P256VerifyCircuit{},
			description: "P-256 (secp256r1) signature verification",
		},
	}
}

// TestAnalyzeEVMPrecompiles analyzes all EVM precompile circuits and generates HTML reports
func TestAnalyzeEVMPrecompiles(t *testing.T) {
	// Create output directory
	outputDir := filepath.Join(os.TempDir(), "gnark-smt-reports")
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		t.Fatalf("Failed to create output directory: %v", err)
	}
	t.Logf("Output directory: %s", outputDir)

	precompiles := getPrecompiles()
	var summaries []string

	for _, pc := range precompiles {
		t.Run(pc.name, func(t *testing.T) {
			t.Logf("Analyzing %s (%s): %s", pc.name, pc.address, pc.description)

			opts := DefaultCompileOptions()
			opts.TestName = pc.name
			opts.WithProfiling = true

			result, err := CompileCircuit(pc.circuit, opts)
			if err != nil {
				t.Logf("WARNING: Failed to compile %s: %v", pc.name, err)
				summaries = append(summaries, fmt.Sprintf("%s (%s): COMPILE ERROR - %v", pc.name, pc.address, err))
				return
			}

			// Run analysis
			analysis := result.Analyze(pc.name)

			// Generate summary
			summary := fmt.Sprintf("%s (%s): %d constraints, %d public, %d secret, %d internal vars",
				pc.name, pc.address,
				len(result.Extracted.Constraints),
				result.Extracted.NbPublic,
				result.Extracted.NbSecret,
				result.Extracted.NbInternal)

			if len(analysis.Issues) > 0 {
				criticalCount := 0
				warningCount := 0
				for _, issue := range analysis.Issues {
					if issue.Severity == "critical" {
						criticalCount++
					} else if issue.Severity == "warning" {
						warningCount++
					}
				}
				summary += fmt.Sprintf(" | Issues: %d critical, %d warnings", criticalCount, warningCount)
			} else {
				summary += " | No issues found"
			}
			summaries = append(summaries, summary)

			// Write HTML report
			reportPath := filepath.Join(outputDir, fmt.Sprintf("%s_report.html", pc.name))
			if err := result.WriteReportToFile(reportPath, pc.name); err != nil {
				t.Logf("WARNING: Failed to write report for %s: %v", pc.name, err)
			} else {
				t.Logf("Report written to: %s", reportPath)
			}

			// Print analysis summary to test output
			t.Logf("  Constraints: %d", len(result.Extracted.Constraints))
			t.Logf("  Variables: %d public, %d secret, %d internal",
				result.Extracted.NbPublic, result.Extracted.NbSecret, result.Extracted.NbInternal)

			// Print constraint patterns
			patterns := AnalyzeConstraintPatterns(result.Extracted)
			for _, p := range patterns {
				t.Logf("  Pattern: %s", p)
			}

			// Print issues
			if len(analysis.Issues) > 0 {
				t.Logf("  Issues found:")
				for _, issue := range analysis.Issues {
					t.Logf("    [%s] %s: %s", issue.Severity, issue.Type, issue.Description)
				}
			} else {
				t.Logf("  No issues found")
			}
		})
	}

	// Print overall summary
	t.Log("\n========================================")
	t.Log("EVM PRECOMPILES ANALYSIS SUMMARY")
	t.Log("========================================")
	for _, s := range summaries {
		t.Log(s)
	}
	t.Logf("\nHTML reports written to: %s", outputDir)
}

// TestAnalyzeECRecover runs detailed analysis on ECRecover
func TestAnalyzeECRecover(t *testing.T) {
	// Generate real test data
	sk, err := ecdsa.GenerateKey(nil)
	if err != nil {
		// Use simple circuit if we can't generate keys
		circuit := &ECRecoverCircuit{}
		opts := DefaultCompileOptions()
		opts.TestName = "ECRecover"

		result, err := CompileCircuit(circuit, opts)
		if err != nil {
			t.Fatalf("Failed to compile: %v", err)
		}

		result.PrintSummary()
		analysis := result.Analyze("ECRecover")
		t.Logf("Issues: %d", len(analysis.Issues))
		return
	}

	msg := []byte("test message")
	v, r, s, err := sk.SignForRecover(msg, nil)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	pk := sk.PublicKey
	circuit := &ECRecoverCircuit{}
	witness := &ECRecoverCircuit{
		Message:   emulated.ValueOf[emulated.Secp256k1Fr](ecdsa.HashToInt(msg)),
		V:         v + 27,
		R:         emulated.ValueOf[emulated.Secp256k1Fr](r),
		S:         emulated.ValueOf[emulated.Secp256k1Fr](s),
		Strict:    1,
		IsFailure: 0,
		Expected: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](pk.A.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](pk.A.Y),
		},
	}
	_ = witness // witness would be used for actual proving

	opts := DefaultCompileOptions()
	opts.TestName = "ECRecover"
	opts.WithProfiling = true

	result, err := CompileCircuit(circuit, opts)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	result.PrintSummary()

	// Run detailed analysis
	analysis := result.Analyze("ECRecover")

	t.Logf("Constraint Patterns:")
	for _, p := range AnalyzeConstraintPatterns(result.Extracted) {
		t.Logf("  %s", p)
	}

	if len(analysis.Issues) > 0 {
		t.Logf("Issues found: %d", len(analysis.Issues))
		for _, issue := range analysis.Issues {
			t.Logf("  [%s] %s: %s", issue.Severity, issue.Type, issue.Description)
			if issue.Details != "" {
				t.Logf("    Details: %s", issue.Details)
			}
		}
	} else {
		t.Log("No issues found")
	}

	// Write report
	outputDir := filepath.Join(os.TempDir(), "gnark-smt-reports")
	os.MkdirAll(outputDir, 0755)
	reportPath := filepath.Join(outputDir, "ECRecover_detailed.html")
	if err := result.WriteReportToFile(reportPath, "ECRecover"); err != nil {
		t.Logf("Failed to write report: %v", err)
	} else {
		t.Logf("Report written to: %s", reportPath)
	}
}

// TestAnalyzeECAdd runs detailed analysis on ECAdd (BN254)
func TestAnalyzeECAdd(t *testing.T) {
	circuit := &ECAddCircuit{}

	opts := DefaultCompileOptions()
	opts.TestName = "ECAdd_BN254"
	opts.WithProfiling = true

	result, err := CompileCircuit(circuit, opts)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	result.PrintSummary()

	analysis := result.Analyze("ECAdd_BN254")
	t.Logf("Issues: %d", len(analysis.Issues))
	for _, issue := range analysis.Issues {
		t.Logf("  [%s] %s: %s", issue.Severity, issue.Type, issue.Description)
	}

	// Write report
	outputDir := filepath.Join(os.TempDir(), "gnark-smt-reports")
	os.MkdirAll(outputDir, 0755)
	reportPath := filepath.Join(outputDir, "ECAdd_BN254_detailed.html")
	result.WriteReportToFile(reportPath, "ECAdd_BN254")
	t.Logf("Report written to: %s", reportPath)
}
