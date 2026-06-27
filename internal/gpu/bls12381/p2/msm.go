//go:build cuda

package p2

import (
	"fmt"
	"unsafe"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	gpu "github.com/consensys/gnark/internal/gpu/bls12381"
)

// G1MSM commits resident FrVectors against a fixed SRS base array. The bases are
// referenced by their host pointer; the underlying MSMDeviceScalarsWithStats
// caches the canonical-form device points by that pointer, so the SRS is
// converted+uploaded exactly once across all proves.
type G1MSM struct {
	hostBases unsafe.Pointer // &bases[0]
	maxN      int
	dev       *Device
}

// NewG1MSM wraps an SRS base slice (pk.KzgLagrange.G1 or pk.Kzg.G1) as a resident
// MSM handle. The slice must outlive the handle (it backs the points cache key).
func (d *Device) NewG1MSM(bases []curve.G1Affine) (*G1MSM, error) {
	if len(bases) == 0 {
		return nil, fmt.Errorf("p2: empty SRS bases")
	}
	return &G1MSM{hostBases: unsafe.Pointer(&bases[0]), maxN: len(bases), dev: d}, nil
}

// MultiExp computes sum_i scalars[i]·bases[i] over the first v.Len() bases from a
// resident scalar vector, returning the affine result. The scalar vector stays
// on the device (no H2D); only the single result point comes back.
func (m *G1MSM) MultiExp(v *FrVector) (curve.G1Affine, error) {
	var aff curve.G1Affine
	if v.Len() > m.maxN {
		return aff, fmt.Errorf("p2: MSM size %d exceeds %d SRS bases", v.Len(), m.maxN)
	}
	var jac curve.G1Jac
	if _, err := gpu.MSMDeviceScalarsWithStats(m.hostBases, v.Ptr(), v.Len(), unsafe.Pointer(&jac)); err != nil {
		return aff, err
	}
	aff.FromJacobian(&jac)
	return aff, nil
}

// MultiExpOffset commits n scalars against bases starting at base index off — for
// the L-vs-R/O windows of commitToLRO and the H1/H2/H3 chunks of the quotient.
func (m *G1MSM) MultiExpOffset(v *FrVector, off, n int) (curve.G1Affine, error) {
	var aff curve.G1Affine
	if off+n > m.maxN {
		return aff, fmt.Errorf("p2: MSM window [%d,%d) exceeds %d SRS bases", off, off+n, m.maxN)
	}
	basesOff := unsafe.Add(m.hostBases, off*int(unsafe.Sizeof(curve.G1Affine{})))
	var jac curve.G1Jac
	if _, err := gpu.MSMDeviceScalarsWithStats(basesOff, v.Ptr(), n, unsafe.Pointer(&jac)); err != nil {
		return aff, err
	}
	aff.FromJacobian(&jac)
	return aff, nil
}
