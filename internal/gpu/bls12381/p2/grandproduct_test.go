//go:build cuda

package p2

import (
	"math/big"
	"math/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/fft"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/iop"
)

func randVec(n int) []fr.Element {
	v := make([]fr.Element, n)
	for i := range v {
		v[i].SetRandom()
	}
	return v
}

func assertEq(t *testing.T, name string, got, want []fr.Element) {
	t.Helper()
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s: mismatch at %d: got %s want %s", name, i, got[i].String(), want[i].String())
		}
	}
}

// TestGrandProductDevice proves the resident permutation grand-product (the
// ~4.5s buildRatioCopyConstraint phase) byte-matches iop.BuildRatioCopyConstraint
// for the same inputs — validating the gpu_ratio_* pipeline end-to-end on
// device-resident wire/permutation/identity vectors (m3 core).
func TestGrandProductDevice(t *testing.T) {
	dev, err := NewDevice()
	if err != nil {
		t.Skipf("no device: %v", err)
	}
	const n = 1 << 10
	dom := fft.NewDomain(n)
	lagReg := iop.Form{Basis: iop.Lagrange, Layout: iop.Regular}

	L, R, O := randVec(n), randVec(n), randVec(n)
	var beta, gamma fr.Element
	beta.SetRandom()
	gamma.SetRandom()

	// a valid random permutation of [0, 3n)
	perm := make([]int64, 3*n)
	for i := range perm {
		perm[i] = int64(i)
	}
	rand.Shuffle(len(perm), func(i, j int) { perm[i], perm[j] = perm[j], perm[i] })

	// CPU reference (clone inputs; BuildRatioCopyConstraint mutates entries)
	Lc := append([]fr.Element(nil), L...)
	Rc := append([]fr.Element(nil), R...)
	Oc := append([]fr.Element(nil), O...)
	entries := []*iop.Polynomial{
		iop.NewPolynomial(&Lc, lagReg),
		iop.NewPolynomial(&Rc, lagReg),
		iop.NewPolynomial(&Oc, lagReg),
	}
	zc, err := iop.BuildRatioCopyConstraint(entries, perm, beta, gamma, lagReg, dom)
	if err != nil {
		t.Fatal(err)
	}
	want := zc.Coefficients()

	// identity support: evalID[i+j*n] = u^j · ω^i  (u = FrMultiplicativeGen)
	u := dom.FrMultiplicativeGen
	evalID := make([]fr.Element, 3*n)
	evalID[0].SetOne()
	for i := 1; i < n; i++ {
		evalID[i].Mul(&evalID[i-1], &dom.Generator)
	}
	for j := 1; j < 3; j++ {
		var coset fr.Element
		coset.Exp(u, big.NewInt(int64(j)))
		for i := 0; i < n; i++ {
			evalID[j*n+i].Mul(&evalID[i], &coset)
		}
	}

	// σⱼ[i] = evalID[perm[i+j*n]] ; twiddles0[i] = evalID[i] = ω^i
	s1, s2, s3 := make([]fr.Element, n), make([]fr.Element, n), make([]fr.Element, n)
	tw0 := make([]fr.Element, n)
	for i := 0; i < n; i++ {
		s1[i] = evalID[perm[i]]
		s2[i] = evalID[perm[i+n]]
		s3[i] = evalID[perm[i+2*n]]
		tw0[i] = evalID[i]
	}
	var u2 fr.Element
	u2.Mul(&u, &u)
	challenges := [4]fr.Element{beta, gamma, u, u2}

	mk := func(h []fr.Element) *FrVector {
		v, e := dev.NewFrVector(n)
		if e != nil {
			t.Fatal(e)
		}
		if e := v.CopyFromHost(h); e != nil {
			t.Fatal(e)
		}
		return v
	}
	vl, vr, vo := mk(L), mk(R), mk(O)
	vs1, vs2, vs3 := mk(s1), mk(s2), mk(s3)
	vtw := mk(tw0)
	z, _ := dev.NewFrVector(n)
	defer func() {
		for _, v := range []*FrVector{vl, vr, vo, vs1, vs2, vs3, vtw, z} {
			v.Free()
		}
	}()

	if err := dev.RatioBuildZ(z, vl, vr, vo, vs1, vs2, vs3, vtw, challenges); err != nil {
		t.Fatal(err)
	}
	got := make([]fr.Element, n)
	if err := z.CopyToHost(got); err != nil {
		t.Fatal(err)
	}
	assertEq(t, "GrandProductZ", got, want)
	t.Logf("resident grand-product Z byte-matches iop.BuildRatioCopyConstraint (n=%d)", n)
}
