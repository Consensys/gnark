//go:build cuda

package p2

/*
#include <stddef.h>
int  gpu_alloc_pinned(void** ptr, size_t bytes);
void gpu_free_pinned(void* ptr);
*/
import "C"

import (
	"fmt"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// PinnedFrBuffer is page-locked host memory aliased as an fr.Element slice. The
// resident prover writes the unavoidable host fences (quotient h1/h2/h3, FS
// commit scalars) directly into Data so the matching device transfer is a fast
// async DMA rather than a pageable bounce.
type PinnedFrBuffer struct {
	ptr  unsafe.Pointer
	Data []fr.Element
}

// NewPinnedFrBuffer allocates n page-locked Fr elements.
func NewPinnedFrBuffer(n int) (*PinnedFrBuffer, error) {
	var ptr unsafe.Pointer
	if C.gpu_alloc_pinned(&ptr, C.size_t(n*frBytes)) != 0 || ptr == nil {
		return nil, fmt.Errorf("p2: pinned alloc of %d Fr failed", n)
	}
	return &PinnedFrBuffer{
		ptr:  ptr,
		Data: unsafe.Slice((*fr.Element)(ptr), n),
	}, nil
}

// Free releases the page-locked memory. Idempotent.
func (b *PinnedFrBuffer) Free() {
	if b.ptr != nil {
		C.gpu_free_pinned(b.ptr)
		b.ptr = nil
		b.Data = nil
	}
}
