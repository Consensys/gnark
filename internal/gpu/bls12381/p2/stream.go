//go:build cuda

package p2

/*
#include <stdint.h>
#include <stddef.h>
int gpu_memcpy_h2d_on_stream(void* dst, const void* src, size_t size, void* stream);
int gpu_vec_mul(void* r, const void* a, const void* b, uint32_t n, void* stream);
*/
import "C"

import (
	"fmt"
)

// CopyFromPinnedStream issues an asynchronous H2D from page-locked host memory on
// the given stream. The caller must hold dev.Bind() and fence the transfer with
// an event (RecordEvent/WaitEvent) before any consumer reads this vector. This is
// the transfer half of the Transfer/Compute overlap (m6).
func (v *FrVector) CopyFromPinnedStream(p *PinnedFrBuffer, id StreamID) error {
	if len(p.Data) != v.n {
		return fmt.Errorf("p2: CopyFromPinnedStream size mismatch %d != %d", len(p.Data), v.n)
	}
	if C.gpu_memcpy_h2d_on_stream(v.ptr, p.ptr, C.size_t(v.n*frBytes), v.dev.stream(id)) != 0 {
		return fmt.Errorf("p2: async H2D failed")
	}
	return nil
}

// MulStream sets v[i] = a[i]·b[i] on the given stream (caller holds dev.Bind()).
// Compute half of the overlap: runs on StreamCompute/StreamMSM while the next
// phase's inputs stage on StreamTransfer.
func (v *FrVector) MulStream(a, b *FrVector, id StreamID) error {
	if C.gpu_vec_mul(v.ptr, a.ptr, b.ptr, C.uint32_t(v.n), v.dev.stream(id)) != 0 {
		return fmt.Errorf("p2: vec_mul stream failed")
	}
	return nil
}
