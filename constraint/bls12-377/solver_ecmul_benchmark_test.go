package cs_test

import (
	"encoding/binary"
	"math/big"
	"strconv"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377fr "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	bn254crypto "github.com/consensys/gnark-crypto/ecc/bn254"
	bn254fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bls12-377"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

// ecmulCircuit proves N independent BN254 ECMul checks inside one BLS12-377 PLONK circuit.
// It mirrors BenchmarkPlonkECMul30 from linea-monorepo/prover/gpu/plonk/plonk_test.go.
type ecmulCircuit struct {
	Points   []sw_emulated.AffinePoint[emulated.BN254Fp]
	Scalars  []emulated.Element[emulated.BN254Fr]
	Expected []sw_emulated.AffinePoint[emulated.BN254Fp]
	N        int `gnark:"-"`
}

func (c *ecmulCircuit) Define(api frontend.API) error {
	curve, err := sw_emulated.New[emulated.BN254Fp, emulated.BN254Fr](api, sw_emulated.GetBN254Params())
	if err != nil {
		return err
	}
	for i := 0; i < c.N; i++ {
		res := curve.ScalarMul(&c.Points[i], &c.Scalars[i])
		curve.AssertIsEqual(res, &c.Expected[i])
	}
	return nil
}

func makeECMulCircuit(n int) *ecmulCircuit {
	return &ecmulCircuit{
		Points:   make([]sw_emulated.AffinePoint[emulated.BN254Fp], n),
		Scalars:  make([]emulated.Element[emulated.BN254Fr], n),
		Expected: make([]sw_emulated.AffinePoint[emulated.BN254Fp], n),
		N:        n,
	}
}

func deterministicScalar(seed, index uint64) bn254fr.Element {
	var buf [32]byte
	binary.LittleEndian.PutUint64(buf[0:8], seed)
	binary.LittleEndian.PutUint64(buf[8:16], index)
	binary.LittleEndian.PutUint64(buf[16:24], seed^0xdeadbeefcafebabe)
	binary.LittleEndian.PutUint64(buf[24:32], index^0x0123456789abcdef)
	var e bn254fr.Element
	e.SetBytes(buf[:])
	return e
}

func makeECMulWitness(n int) *ecmulCircuit {
	_, _, G, _ := bn254crypto.Generators()
	points := make([]sw_emulated.AffinePoint[emulated.BN254Fp], n)
	scalars := make([]emulated.Element[emulated.BN254Fr], n)
	expected := make([]sw_emulated.AffinePoint[emulated.BN254Fp], n)
	for i := 0; i < n; i++ {
		u := deterministicScalar(0x42, uint64(i))
		v := deterministicScalar(0x43, uint64(i))
		var p, exp bn254crypto.G1Affine
		p.ScalarMultiplication(&G, u.BigInt(new(big.Int)))
		exp.ScalarMultiplication(&p, v.BigInt(new(big.Int)))
		points[i] = sw_emulated.AffinePoint[emulated.BN254Fp]{
			X: emulated.ValueOf[emulated.BN254Fp](p.X),
			Y: emulated.ValueOf[emulated.BN254Fp](p.Y),
		}
		scalars[i] = emulated.ValueOf[emulated.BN254Fr](v)
		expected[i] = sw_emulated.AffinePoint[emulated.BN254Fp]{
			X: emulated.ValueOf[emulated.BN254Fp](exp.X),
			Y: emulated.ValueOf[emulated.BN254Fp](exp.Y),
		}
	}
	return &ecmulCircuit{Points: points, Scalars: scalars, Expected: expected, N: n}
}

func compileECMulSparseR1CS(b testing.TB, n int) *cs.SparseR1CS {
	b.Helper()
	ccs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder[constraint.U64], makeECMulCircuit(n))
	if err != nil {
		b.Fatal(err)
	}
	return ccs.(*cs.SparseR1CS)
}

func buildECMulWitness(b testing.TB, n int) witness.Witness {
	b.Helper()
	full, err := frontend.NewWitness(makeECMulWitness(n), ecc.BLS12_377.ScalarField())
	if err != nil {
		b.Fatal(err)
	}
	return full
}

func BenchmarkPlonkECMul30Solve(b *testing.B) {
	const nInstances = 30
	spr := compileECMulSparseR1CS(b, nInstances)
	fullWitness := buildECMulWitness(b, nInstances)
	b.ReportMetric(float64(spr.GetNbConstraints()), "constraints")
	b.ReportMetric(float64(len(spr.Levels)), "levels")
	b.ReportMetric(float64(len(spr.Instructions)), "instructions")
	b.ReportMetric(float64(len(fullWitness.Vector().(bls12377fr.Vector))), "witness_values")
	for b.Loop() {
		if _, err := spr.Solve(fullWitness); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPlonkECMul30SolveSingleThread(b *testing.B) {
	const nInstances = 30
	spr := compileECMulSparseR1CS(b, nInstances)
	fullWitness := buildECMulWitness(b, nInstances)
	for b.Loop() {
		if _, err := spr.Solve(fullWitness, solver.WithNbTasks(1)); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPlonkECMul30SolveTasks(b *testing.B) {
	const nInstances = 30
	spr := compileECMulSparseR1CS(b, nInstances)
	fullWitness := buildECMulWitness(b, nInstances)
	for _, nbTasks := range []int{2, 4, 8, 12, 18} {
		b.Run(strconv.Itoa(nbTasks), func(b *testing.B) {
			for b.Loop() {
				if _, err := spr.Solve(fullWitness, solver.WithNbTasks(nbTasks)); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
