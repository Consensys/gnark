//go:build cuda

package p2

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// TestStreamOverlapOrdering proves the m6 overlap mechanism is correct: an async
// pinned H2D on StreamTransfer, fenced by an event, is observed by a compute
// kernel on a different stream (StreamMSM). If the event ordering were wrong the
// kernel would read pre-upload garbage and the product would mismatch. A correct
// byte-match confirms streams + events + pinned memory compose safely — the
// machinery the references use to overlap transfers with compute.
func TestStreamOverlapOrdering(t *testing.T) {
	dev, err := NewDevice()
	if err != nil {
		t.Skipf("no device: %v", err)
	}
	dev.Bind()
	defer dev.Unbind()
	dev.EnsureStreams()
	defer dev.Close()

	const n = 1 << 14
	a := randVec(n)
	b := randVec(n)

	// stage A in pinned host memory
	pa, err := NewPinnedFrBuffer(n)
	if err != nil {
		t.Fatal(err)
	}
	defer pa.Free()
	copy(pa.Data, a)

	va, _ := dev.NewFrVector(n)
	vb, _ := dev.NewFrVector(n)
	vr, _ := dev.NewFrVector(n)
	defer func() {
		va.Free()
		vb.Free()
		vr.Free()
	}()

	if err := vb.CopyFromHost(b); err != nil {
		t.Fatal(err)
	}

	const ev EventID = 0
	// async upload of A on the transfer stream …
	if err := va.CopyFromPinnedStream(pa, StreamTransfer); err != nil {
		t.Fatal(err)
	}
	dev.RecordEvent(StreamTransfer, ev)
	// … the MSM stream waits for it, then multiplies — must see the uploaded A
	dev.WaitEvent(StreamMSM, ev)
	if err := vr.MulStream(va, vb, StreamMSM); err != nil {
		t.Fatal(err)
	}
	dev.SyncStream(StreamMSM)

	got := make([]fr.Element, n)
	if err := vr.CopyToHost(got); err != nil {
		t.Fatal(err)
	}
	want := make([]fr.Element, n)
	for i := range want {
		want[i].Mul(&a[i], &b[i])
	}
	assertEq(t, "StreamOverlap", got, want)
	t.Logf("cross-stream async upload + event fence + compute verified (n=%d)", n)
}
