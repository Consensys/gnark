package evmprecompiles

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	bls12381fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	bn254fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	secp256k1ecdsa "github.com/consensys/gnark-crypto/ecc/secp256k1/ecdsa"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

func BenchmarkSolveEvmprecompiles(b *testing.B) {
	benchmarks := []struct {
		name   string
		build  func(testing.TB) (frontend.Circuit, frontend.Circuit)
		curves []ecc.ID
	}{
		{
			name:   "bn254_ecmul",
			build:  buildBenchmarkBN254ECMul,
			curves: []ecc.ID{ecc.BN254, ecc.BLS12_377},
		},
		{
			name:   "ecrecover",
			build:  buildBenchmarkECRecover,
			curves: []ecc.ID{ecc.BN254, ecc.BLS12_377},
		},
		{
			name:   "bls12381_g1_msm_2",
			build:  buildBenchmarkBLSG1MSM2,
			curves: []ecc.ID{ecc.BN254, ecc.BLS12_377},
		},
	}

	for _, bench := range benchmarks {
		bench := bench
		b.Run(bench.name, func(b *testing.B) {
			for _, curve := range bench.curves {
				curve := curve
				b.Run(curve.String(), func(b *testing.B) {
					circuit, assignment := bench.build(b)
					benchmarkSolvePrecompile(b, curve, circuit, assignment)
				})
			}
		})
	}
}

func benchmarkSolvePrecompile(b *testing.B, curve ecc.ID, circuit, assignment frontend.Circuit) {
	b.Helper()
	field := curve.ScalarField()
	ccs, err := frontend.Compile(field, scs.NewBuilder, circuit)
	if err != nil {
		b.Fatal(err)
	}
	witness, err := frontend.NewWitness(assignment, field)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportMetric(float64(ccs.GetNbConstraints()), "constraints")
	b.ReportMetric(float64(ccs.GetNbInstructions()), "instructions")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ccs.Solve(witness); err != nil {
			b.Fatal(err)
		}
	}
}

func buildBenchmarkBN254ECMul(testing.TB) (frontend.Circuit, frontend.Circuit) {
	_, _, generator, _ := bn254.Generators()
	var u, v bn254fr.Element
	u.SetUint64(123456789)
	v.SetUint64(987654321)

	var p, expected bn254.G1Affine
	p.ScalarMultiplication(&generator, u.BigInt(new(big.Int)))
	expected.ScalarMultiplication(&p, v.BigInt(new(big.Int)))

	circuit := ecmulCircuit{}
	witness := ecmulCircuit{
		X0: sw_emulated.AffinePoint[emulated.BN254Fp]{
			X: emulated.ValueOf[emulated.BN254Fp](p.X),
			Y: emulated.ValueOf[emulated.BN254Fp](p.Y),
		},
		U: emulated.ValueOf[emulated.BN254Fr](v),
		Expected: sw_emulated.AffinePoint[emulated.BN254Fp]{
			X: emulated.ValueOf[emulated.BN254Fp](expected.X),
			Y: emulated.ValueOf[emulated.BN254Fp](expected.Y),
		},
	}
	return &circuit, &witness
}

func buildBenchmarkECRecover(tb testing.TB) (frontend.Circuit, frontend.Circuit) {
	tb.Helper()
	sk, err := secp256k1ecdsa.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	msg := []byte("solver benchmark")
	v, r, s, err := sk.SignForRecover(msg, nil)
	if err != nil {
		tb.Fatal(err)
	}
	circuit := ecrecoverCircuit{}
	witness := ecrecoverCircuit{
		Message:   emulated.ValueOf[emulated.Secp256k1Fr](secp256k1ecdsa.HashToInt(msg)),
		V:         v + 27,
		R:         emulated.ValueOf[emulated.Secp256k1Fr](r),
		S:         emulated.ValueOf[emulated.Secp256k1Fr](s),
		Strict:    1,
		IsFailure: 0,
		Expected: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](sk.PublicKey.A.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](sk.PublicKey.A.Y),
		},
	}
	return &circuit, &witness
}

type benchmarkBLSG1MSM2Circuit struct {
	Accumulator [3]sw_emulated.AffinePoint[emulated.BLS12381Fp]
	Points      [2]sw_emulated.AffinePoint[emulated.BLS12381Fp]
	Scalars     [2]emulated.Element[emulated.BLS12381Fr]
}

func (c *benchmarkBLSG1MSM2Circuit) Define(api frontend.API) error {
	for i := range c.Points {
		if err := ECG1ScalarMulSumBLS(api, &c.Accumulator[i], &c.Points[i], &c.Scalars[i], &c.Accumulator[i+1]); err != nil {
			return err
		}
	}
	return nil
}

func buildBenchmarkBLSG1MSM2(testing.TB) (frontend.Circuit, frontend.Circuit) {
	var points [2]bls12381.G1Affine
	var scalars [2]bls12381fr.Element
	for i := range points {
		scalars[i].SetUint64(uint64(17 + i))
		points[i].ScalarMultiplicationBase(new(big.Int).SetUint64(uint64(31 + i)))
	}

	var cPoints [2]sw_emulated.AffinePoint[emulated.BLS12381Fp]
	var cScalars [2]emulated.Element[emulated.BLS12381Fr]
	for i := range cPoints {
		cPoints[i] = sw_bls12381.NewG1Affine(points[i])
		cScalars[i] = emulated.ValueOf[emulated.BLS12381Fr](scalars[i])
	}

	var accumulators [3]sw_emulated.AffinePoint[emulated.BLS12381Fp]
	var zero, acc bls12381.G1Affine
	zero.SetInfinity()
	accumulators[0] = sw_bls12381.NewG1Affine(zero)
	for i := range points {
		var tmp bls12381.G1Affine
		tmp.ScalarMultiplication(&points[i], scalars[i].BigInt(new(big.Int)))
		acc.Add(&acc, &tmp)
		accumulators[i+1] = sw_bls12381.NewG1Affine(acc)
	}

	circuit := benchmarkBLSG1MSM2Circuit{}
	witness := benchmarkBLSG1MSM2Circuit{
		Accumulator: accumulators,
		Points:      cPoints,
		Scalars:     cScalars,
	}
	return &circuit, &witness
}
