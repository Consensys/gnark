package mpcsetup

import (
	"bytes"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	groth16Impl "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/stretchr/testify/require"
	"math/big"
	"slices"
	"testing"
)

// small tests for sub-functionalities of the mpc setup
// this file is not autogenerated, and not generified for other curves

func TestContributionPok(t *testing.T) {
	const (
		pokChallenge = "challenge"
		pokDst       = 1
	)
	x0, err := curve.HashToG1([]byte("contribution test"), nil)
	require.NoError(t, err)
	proof, d := updateValue(x0, []byte(pokChallenge), pokDst)
	var (
		x1 curve.G1Affine
		dI big.Int
	)
	d.BigInt(&dI)
	x1.ScalarMultiplication(&x0, &dI)

	// verify proof - no G2
	require.NoError(t, proof.verify(pair{x0, nil}, pair{x1, nil}, []byte(pokChallenge), pokDst))

	// verify proof - with G2
	y0, err := curve.RandomOnG2()
	require.NoError(t, err)
	var y1 curve.G2Affine
	y1.ScalarMultiplication(&y0, &dI)

	require.NoError(t, proof.verify(pair{x0, &y0}, pair{x1, &y1}, []byte(pokChallenge), pokDst))

	// read/write round-trip
	var bb bytes.Buffer
	n0, err := proof.WriteTo(&bb)
	require.NoError(t, err)
	var proofBack valueUpdate
	n1, err := proofBack.ReadFrom(&bb)
	require.NoError(t, err)
	require.Equal(t, n0, n1)

	require.NoError(t, proofBack.verify(pair{x0, nil}, pair{x1, nil}, []byte(pokChallenge), pokDst))
	require.NoError(t, proofBack.verify(pair{x0, &y0}, pair{x1, &y1}, []byte(pokChallenge), pokDst))
}

// TestSetupBeaconOnly tests the setup/key extraction
// as well as the random beacon contribution
// without any untrusted contributors
func TestSetupBeaconOnly(t *testing.T) {

	// Compile the circuit
	ccs := getTestCircuit(t)
	domainSize := ecc.NextPowerOfTwo(uint64(ccs.GetNbConstraints()))

	var (
		p1 Phase1
		p2 Phase2
	)
	p1.Initialize(domainSize)
	commons := p1.Seal([]byte("beacon 1"))

	evals := p2.Initialize(ccs, &commons)
	pk, vk := p2.Seal(&commons, &evals, []byte("beacon 2"))

	_pk := pk.(*groth16Impl.ProvingKey)

	rpk, rvk, err := groth16.Setup(ccs)
	require.NoError(t, err)
	_rpk := rpk.(*groth16Impl.ProvingKey)

	// assert everything is of the same size
	require.Equal(t, _rpk.Domain.Cardinality, _pk.Domain.Cardinality)
	require.Equal(t, len(_rpk.G1.A), len(_pk.G1.A))
	require.Equal(t, len(_rpk.G1.B), len(_pk.G1.B))
	require.Equal(t, len(_rpk.G1.K), len(_pk.G1.K))
	require.Equal(t, len(_rpk.G1.Z), len(_pk.G1.Z))
	require.Equal(t, len(_rpk.G2.B), len(_pk.G2.B))
	require.Equal(t, len(_rpk.CommitmentKeys), len(_pk.CommitmentKeys))
	for i := range _rpk.CommitmentKeys {
		require.Equal(t, len(_rpk.CommitmentKeys[i].BasisExpSigma), len(_pk.CommitmentKeys[i].BasisExpSigma))
		require.Equal(t, len(_rpk.CommitmentKeys[i].Basis), len(_pk.CommitmentKeys[i].Basis))
	}

	proveVerifyCircuit(t, rpk, rvk)
	fmt.Println("regular proof verified")
	proveVerifyCircuit(t, pk, vk)
	fmt.Println("mpc proof verified")
}

// TestNoContributors tests the beacon and some of the serialization
func TestNoContributors(t *testing.T) {
	testAll(t, 0, 0)
}

func TestOnePhase1Contribute(t *testing.T) {
	testAll(t, 1, 0)
}

func TestUpdateCheck(t *testing.T) {
	_, _, g1, g2 := curve.Generators()
	g1Slice := []curve.G1Affine{g1, g1, g1}
	g2Slice := []curve.G2Affine{g2, g2}
	require.NoError(t, multiValueUpdateCheck(g1Slice, g2Slice, g1Slice, g1Slice))
}

func commonsSmallValues(N, tau, alpha, beta uint64) SrsCommons {
	var (
		res   SrsCommons
		I     big.Int
		coeff fr.Element
	)
	_, _, g1, g2 := curve.Generators()
	tauPowers := powersI(tau, int(2*N-1))
	res.G1.Tau = make([]curve.G1Affine, 2*N-1)
	for i := range res.G1.Tau {
		tauPowers[i].BigInt(&I)
		res.G1.Tau[i].ScalarMultiplication(&g1, &I)
	}

	res.G2.Tau = make([]curve.G2Affine, N)
	for i := range res.G2.Tau {
		tauPowers[i].BigInt(&I)
		res.G2.Tau[i].ScalarMultiplication(&g2, &I)
	}

	res.G1.AlphaTau = make([]curve.G1Affine, N)
	coeff.SetUint64(alpha)
	for i := range res.G1.AlphaTau {
		var x fr.Element
		x.Mul(&tauPowers[i], &coeff)
		x.BigInt(&I)
		res.G1.AlphaTau[i].ScalarMultiplication(&g1, &I)
	}

	res.G1.BetaTau = make([]curve.G1Affine, N)
	coeff.SetUint64(beta)
	for i := range res.G1.BetaTau {
		var x fr.Element
		x.Mul(&tauPowers[i], &coeff)
		x.BigInt(&I)
		res.G1.BetaTau[i].ScalarMultiplication(&g1, &I)
	}

	I.SetUint64(beta)
	res.G2.Beta.ScalarMultiplication(&g2, &I)

	return res
}

func powersI(x uint64, n int) []fr.Element {
	var y fr.Element
	y.SetUint64(x)
	return powers(&y, n)
}

func TestPowers(t *testing.T) {
	var x fr.Element
	x.SetUint64(2)
	x2 := powers(&x, 10)
	for i := range x2 {
		require.True(t, x2[i].IsUint64())
		require.Equal(t, x2[i].Uint64(), uint64(1<<i))
	}
}

func TestCommons(t *testing.T) {

	// Compile the circuit
	ccs := getTestCircuit(t)
	domainSize := ecc.NextPowerOfTwo(uint64(ccs.GetNbConstraints()))

	var p1 Phase1
	p1.Initialize(domainSize)

	assertG1G2Equal(t, p1.parameters.G1.BetaTau[0], p1.parameters.G2.Beta)

	commons := p1.Seal([]byte("beacon 1"))

	for i := range commons.G2.Tau {
		assertG1G2Equal(t, commons.G1.Tau[i], commons.G2.Tau[i])
	}

	assertG1G2Equal(t, commons.G1.BetaTau[0], commons.G2.Beta)
}

func TestCommonsUpdate(t *testing.T) {
	var c SrsCommons
	c.setOne(1)
	assertG1G2Equal(t, c.G1.BetaTau[0], c.G2.Beta)
	one := fr.One()
	var zero fr.Element
	c.update(&zero, &zero, &one)
	assertG1G2Equal(t, c.G1.BetaTau[0], c.G2.Beta)
}

func assertG1G2Equal(t *testing.T, p1 curve.G1Affine, p2 curve.G2Affine) {
	_, _, g1, g2 := curve.Generators()
	assertPairingsEqual(t, p1, g2, g1, p2)
}

// asserts e(p1, q1) = r(p2, q2)
func assertPairingsEqual(t *testing.T, p1 curve.G1Affine, p2 curve.G2Affine, q1 curve.G1Affine, q2 curve.G2Affine) {
	q1.Neg(&q1)
	ok, err := curve.PairingCheck([]curve.G1Affine{p1, q1}, []curve.G2Affine{p2, q2})
	require.NoError(t, err)
	require.True(t, ok)
}

func TestPedersen(t *testing.T) {
	cs := getTestCircuit(t)
	domainSize := ecc.NextPowerOfTwo(uint64(cs.GetNbConstraints()))

	commons := commonsSmallValues(domainSize, 2, 3, 4)
	var p Phase2
	evals := p.Initialize(cs, &commons)
	contributions := make([]fr.Element, 1+len(p.Sigmas))
	for i := range contributions {
		contributions[i].SetOne()
	}
	contributions[1].SetUint64(2)
	p.update(&contributions[0], contributions[1:])
	_, _, _, g2 := curve.Generators()
	for i := range p.Sigmas {
		assertPairingsEqual(t, evals.G1.CKK[0][i], p.Parameters.G2.Sigma[i], p.Parameters.G1.SigmaCKK[0][i], g2)
	}
}

func TestBivariateRandomMonomials(t *testing.T) {
	xDeg := []int{3, 2, 3}
	ends := partialSums(xDeg...)
	values := bivariateRandomMonomials(ends...)
	//extract the variables
	x := make([]fr.Element, slices.Max(xDeg))
	y := make([]fr.Element, len(ends))
	x[1].Div(&values[1], &values[0])
	y[1].Div(&values[xDeg[0]], &values[0])

	x[0].SetOne()
	y[0].SetOne()

	for i := range x[:len(x)-1] {
		x[i+1].Mul(&x[i], &x[1])
	}

	for i := range y[:len(x)-1] {
		y[i+1].Mul(&y[i], &y[1])
	}

	prevEnd := 0
	for i := range ends {
		for j := range xDeg[i] {
			var z fr.Element
			z.Mul(&y[i], &x[j])
			require.Equal(t, z.String(), values[prevEnd+j].String(), "X^%d Y^%d: expected %s, encountered %s", j, i)
		}
		prevEnd = ends[i]
	}
}

func TestLinearCombinationsG1(t *testing.T) {

	testLinearCombinationsG1 := func(ends []int, powers, truncatedPowers, shiftedPowers []fr.Element, A ...curve.G1Affine) {

		multiExpConfig := ecc.MultiExpConfig{
			NbTasks: 1,
		}

		if len(A) == 0 {
			A = make([]curve.G1Affine, ends[len(ends)-1])
			var err error
			for i := range A {
				A[i], err = curve.HashToG1([]byte{byte(i)}, nil)
				require.NoError(t, err)
			}
		}

		truncated, shifted := linearCombinationsG1(slices.Clone(A), powers, ends)

		var res curve.G1Affine

		_, err := res.MultiExp(A, truncatedPowers, multiExpConfig)
		require.NoError(t, err)
		require.Equal(t, res, truncated, "truncated")

		_, err = res.MultiExp(A, shiftedPowers, multiExpConfig)
		require.NoError(t, err)
		require.Equal(t, res, shifted, "shifted")
	}

	_, _, g1, _ := curve.Generators()
	var infty curve.G1Affine

	for i := range 10 {
		x0 := fr.NewElement(uint64(i - 5))[0]
		fmt.Printf("%d: %d 0x%x\n", i-5, x0, x0)
	}
	var acc curve.G1Affine
	for i := range 5 {
		fmt.Printf("%dg: %d 0x%x\n", i, acc.X[0], acc.X[0])
		acc.Add(&acc, &g1)
	}

	testLinearCombinationsG1(
		[]int{3},
		frs(1, 1, 1),
		frs(1, 1, 0),
		frs(0, 1, 1),
		infty, g1, infty,
	)

	testLinearCombinationsG1(
		[]int{3},
		frs(1, 1, 1),
		frs(1, 1, 0),
		frs(0, 1, 1),
		infty, infty, g1,
	)

	testLinearCombinationsG1(
		[]int{3},
		frs(1, 1, 1),
		frs(1, 1, 0),
		frs(0, 1, 1),
		g1, infty, infty,
	)

	testLinearCombinationsG1(
		[]int{3},
		frs(1, 2, 4),
		frs(1, 2, 0),
		frs(0, 1, 2),
	)

	testLinearCombinationsG1(
		[]int{4, 7},
		frs(1, 2, 4, 8, 3, 6, 12),
		frs(1, 2, 4, 0, 3, 6, 0),
		frs(0, 1, 2, 4, 0, 3, 6),
	)
}

func frs(x ...int) []fr.Element {
	res := make([]fr.Element, len(x))
	for i := range res {
		res[i].SetUint64(uint64(x[i]))
	}
	return res
}
