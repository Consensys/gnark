//go:build cuda

package cuda

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	gpu "github.com/consensys/gnark/internal/gpu/bls12381"
)

const gpuMSMMinThreshold = 1 << 10 // 1024

var gpuMu sync.Mutex
var gpuShadowGuard atomic.Bool

func gpuMultiExp(p *bls12381.G1Jac, points []bls12381.G1Affine, scalars []fr.Element, config ecc.MultiExpConfig) bool {
	n := len(points)
	if os.Getenv("GNARK_DISABLE_GPU_MSM") != "" || n < gpuMSMMinThreshold || gpuShadowGuard.Load() || !gpu.Available() {
		return false
	}
	// Serialize all GPU MSM calls — the GPU kernel uses static global buffers
	// and the point cache is single-entry. Concurrent access corrupts both.
	gpuMu.Lock()
	defer gpuMu.Unlock()

	t0 := time.Now()
	defer func() {
		fmt.Fprintf(os.Stderr, "[GPU MSM] n=%-8d  %v\n", n, time.Since(t0))
	}()

	stats, err := gpu.MSMWithStats(
		unsafe.Pointer(&points[0]),
		unsafe.Pointer(&scalars[0]),
		n,
		unsafe.Pointer(p),
	)
	if err != nil {
		return false
	}
	if os.Getenv("GNARK_GPU_TRACE_MSM") != "" {
		fmt.Fprintf(os.Stderr,
			"[GPU MSM call] n=%-8d cache=%s point_h2d=%v scalar_h2d=%v kernel=%v total=%v\n",
			n, stats.PointCacheStatus, stats.PointTransfer, stats.ScalarTransfer, stats.Kernel, stats.Total,
		)
	}
	if os.Getenv("MSM_SHADOW_CHECK") != "" {
		var ref bls12381.G1Jac
		gpuShadowGuard.Store(true)
		_, shadowErr := ref.MultiExp(points, scalars, config)
		gpuShadowGuard.Store(false)
		if shadowErr != nil {
			panic(fmt.Sprintf("MSM shadow check failed to compute CPU reference: n=%d err=%v", n, shadowErr))
		}
		if !p.Equal(&ref) {
			var gotAff, wantAff bls12381.G1Affine
			gotAff.FromJacobian(p)
			wantAff.FromJacobian(&ref)
			panic(fmt.Sprintf(
				"MSM shadow mismatch: n=%d cache=%s point_h2d=%v scalar_h2d=%v kernel=%v total=%v host_points=%p host_scalars=%p gpu=%s cpu=%s",
				n, stats.PointCacheStatus, stats.PointTransfer, stats.ScalarTransfer, stats.Kernel, stats.Total, unsafe.Pointer(&points[0]), unsafe.Pointer(&scalars[0]), gotAff.String(), wantAff.String(),
			))
		}
	}
	return true
}

func gpuMultiExpDeviceScalars(p *bls12381.G1Jac, points []bls12381.G1Affine, dScalars unsafe.Pointer, n int) bool {
	if os.Getenv("GNARK_DISABLE_GPU_MSM") != "" || n < gpuMSMMinThreshold || gpuShadowGuard.Load() || !gpu.Available() || len(points) < n {
		return false
	}
	gpuMu.Lock()
	defer gpuMu.Unlock()

	t0 := time.Now()
	defer func() {
		fmt.Fprintf(os.Stderr, "[GPU MSM device] n=%-8d  %v\n", n, time.Since(t0))
	}()

	stats, err := gpu.MSMDeviceScalarsWithStats(
		unsafe.Pointer(&points[0]),
		dScalars,
		n,
		unsafe.Pointer(p),
	)
	if err != nil {
		return false
	}
	if os.Getenv("GNARK_GPU_TRACE_MSM") != "" {
		fmt.Fprintf(os.Stderr,
			"[GPU MSM device call] n=%-8d cache=%s point_h2d=%v kernel=%v total=%v\n",
			n, stats.PointCacheStatus, stats.PointTransfer, stats.Kernel, stats.Total,
		)
	}
	return true
}

func MultiExpDeviceScalars(p *bls12381.G1Jac, points []bls12381.G1Affine, dScalars unsafe.Pointer, n int) bool {
	return gpuMultiExpDeviceScalars(p, points, dScalars, n)
}
