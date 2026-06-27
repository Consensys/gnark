//go:build cuda

package p2

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/fft"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/iop"
)

// TestFFTToCanonical proves the resident inverse-FFT (Lagrange/Regular ->
// Canonical/Regular) byte-matches iop.ToCanonical — the selector/wire iFFT used
// by the resident proving-key cache and commit phases.
func TestFFTToCanonical(t *testing.T) {
	dev, err := NewDevice()
	if err != nil {
		t.Skipf("no device: %v", err)
	}
	const n = 1 << 12
	dom := fft.NewDomain(n)
	fdm, err := dev.NewFFTDomain(n)
	if err != nil {
		t.Fatal(err)
	}

	lag := randVec(n)
	v, err := dev.NewFrVector(n)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Free()
	if err := v.CopyFromHost(lag); err != nil {
		t.Fatal(err)
	}
	if err := fdm.ToCanonical(v); err != nil {
		t.Fatal(err)
	}
	got := make([]fr.Element, n)
	if err := v.CopyToHost(got); err != nil {
		t.Fatal(err)
	}

	// CPU reference: Lagrange/Regular -> Canonical/Regular
	cp := append([]fr.Element(nil), lag...)
	p := iop.NewPolynomial(&cp, iop.Form{Basis: iop.Lagrange, Layout: iop.Regular})
	p.ToCanonical(dom).ToRegular()
	assertEq(t, "FFT.ToCanonical", got, p.Coefficients())
	t.Logf("resident inverse-FFT byte-matches iop.ToCanonical (n=%d)", n)
}

// TestG1MSMWrapper proves the G1MSM handle (resident scalars + Jac->Affine +
// offset window) reproduces gnark-crypto's MultiExp exactly.
func TestG1MSMWrapper(t *testing.T) {
	dev, err := NewDevice()
	if err != nil {
		t.Skipf("no device: %v", err)
	}
	const n = 512
	_, _, g1gen, _ := curve.Generators()
	bases := make([]curve.G1Affine, n)
	scalars := make([]fr.Element, n)
	for i := range bases {
		scalars[i].SetRandom()
		var s fr.Element
		s.SetRandom()
		var bi big.Int
		s.BigInt(&bi)
		bases[i].ScalarMultiplication(&g1gen, &bi)
	}

	v, err := dev.NewFrVector(n)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Free()
	if err := v.CopyFromHost(scalars); err != nil {
		t.Fatal(err)
	}
	msm, err := dev.NewG1MSM(bases)
	if err != nil {
		t.Fatal(err)
	}
	got, err := msm.MultiExp(v)
	if err != nil {
		t.Fatal(err)
	}

	var want curve.G1Affine
	if _, err := want.MultiExp(bases, scalars, ecc.MultiExpConfig{}); err != nil {
		t.Fatal(err)
	}
	if !got.Equal(&want) {
		t.Fatalf("G1MSM mismatch:\n got  %s\n want %s", got.String(), want.String())
	}

	// offset window [128, 128+256) must match the same sub-MSM on CPU
	const off, m = 128, 256
	vw, _ := dev.NewFrVector(m)
	defer vw.Free()
	if err := vw.CopyFromHost(scalars[:m]); err != nil {
		t.Fatal(err)
	}
	gotW, err := msm.MultiExpOffset(vw, off, m)
	if err != nil {
		t.Fatal(err)
	}
	var wantW curve.G1Affine
	if _, err := wantW.MultiExp(bases[off:off+m], scalars[:m], ecc.MultiExpConfig{}); err != nil {
		t.Fatal(err)
	}
	if !gotW.Equal(&wantW) {
		t.Fatalf("G1MSM offset mismatch")
	}
	t.Logf("G1MSM (full + offset window) byte-matches gnark-crypto MultiExp (n=%d)", n)
}
