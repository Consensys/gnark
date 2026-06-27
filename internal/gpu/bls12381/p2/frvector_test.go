//go:build cuda

package p2

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
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

// TestFrVectorOps proves every device FrVector op against a CPU fr.Element
// reference — this is where Montgomery-form correctness of the new kernels
// (batch_invert, scale_by_powers, addmul, add_scalar_mul) is pinned down in
// isolation before any pipeline use (blueprint risk R2).
func TestFrVectorOps(t *testing.T) {
	dev, err := NewDevice()
	if err != nil {
		t.Skipf("no device: %v", err)
	}

	const n = 4096
	a := randVec(n)
	b := randVec(n)
	out := make([]fr.Element, n)

	va, err := dev.NewFrVector(n)
	if err != nil {
		t.Fatal(err)
	}
	defer va.Free()
	vb, _ := dev.NewFrVector(n)
	defer vb.Free()
	vr, _ := dev.NewFrVector(n)
	defer vr.Free()
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	must(va.CopyFromHost(a))
	must(vb.CopyFromHost(b))

	// round-trip
	must(va.CopyToHost(out))
	assertEq(t, "roundtrip", out, a)

	// Mul
	must(vr.Mul(va, vb))
	must(vr.CopyToHost(out))
	want := make([]fr.Element, n)
	for i := range want {
		want[i].Mul(&a[i], &b[i])
	}
	assertEq(t, "Mul", out, want)

	// Add
	must(vr.Add(va, vb))
	must(vr.CopyToHost(out))
	for i := range want {
		want[i].Add(&a[i], &b[i])
	}
	assertEq(t, "Add", out, want)

	// Sub
	must(vr.Sub(va, vb))
	must(vr.CopyToHost(out))
	for i := range want {
		want[i].Sub(&a[i], &b[i])
	}
	assertEq(t, "Sub", out, want)

	// AddMul: vr = a; vr += a*b
	must(vr.CopyFromHost(a))
	must(vr.AddMul(va, vb))
	must(vr.CopyToHost(out))
	for i := range want {
		var t0 fr.Element
		t0.Mul(&a[i], &b[i])
		want[i].Add(&a[i], &t0)
	}
	assertEq(t, "AddMul", out, want)

	// ScalarMul: vr = b; vr *= c
	var c fr.Element
	c.SetRandom()
	must(vr.CopyFromHost(b))
	must(vr.ScalarMul(c))
	must(vr.CopyToHost(out))
	for i := range want {
		want[i].Mul(&b[i], &c)
	}
	assertEq(t, "ScalarMul", out, want)

	// AddScalarMul: vr = a; vr += b*c
	must(vr.CopyFromHost(a))
	must(vr.AddScalarMul(vb, c))
	must(vr.CopyToHost(out))
	for i := range want {
		var t0 fr.Element
		t0.Mul(&b[i], &c)
		want[i].Add(&a[i], &t0)
	}
	assertEq(t, "AddScalarMul", out, want)

	// SetZero
	must(vr.SetZero())
	must(vr.CopyToHost(out))
	for i := range want {
		want[i].SetZero()
	}
	assertEq(t, "SetZero", out, want)

	// ScaleByPowers: vr = a; vr[i] *= g^i
	var g fr.Element
	g.SetRandom()
	must(vr.CopyFromHost(a))
	must(vr.ScaleByPowers(g))
	must(vr.CopyToHost(out))
	var gp fr.Element
	gp.SetOne()
	for i := range want {
		want[i].Mul(&a[i], &gp)
		gp.Mul(&gp, &g)
	}
	assertEq(t, "ScaleByPowers", out, want)

	// BatchInvert: vr = a; vr[i] = 1/a[i]
	must(vr.CopyFromHost(a))
	must(vr.BatchInvert())
	must(vr.CopyToHost(out))
	for i := range want {
		want[i].Inverse(&a[i])
	}
	assertEq(t, "BatchInvert", out, want)

	t.Logf("all FrVector ops verified against CPU reference (n=%d)", n)
}
