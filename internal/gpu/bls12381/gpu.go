//go:build cuda

// Package gpu provides CUDA GPU acceleration for BLS12-381 operations.
// This package wraps libgnark_cuda via cgo and provides Go-friendly interfaces
// for MSM and FFT operations.
//
// Build with -tags cuda to enable.
package gpu

/*
// Build with -tags cuda; provide the libgnark_cuda + icicle paths via the env:
//   CGO_CFLAGS="-I<gnark-cuda>/include"
//   CGO_LDFLAGS="-L<gnark-cuda>/build -L<icicle-install>/lib -L/usr/local/cuda/lib64"
#cgo LDFLAGS: -lgnark_cuda -licicle_field_bls12_381 -licicle_curve_bls12_381 -licicle_device -lcudart -lstdc++

#include <stdint.h>
#include <stdlib.h>

// Device management
int gpu_init(int device_id);
int gpu_set_device(int device_id);
int gpu_device_count();
void gpu_sync();

// Memory management
void* gpu_malloc(size_t size);
void gpu_free(void* ptr);
int gpu_memcpy_h2d(void* dst, const void* src, size_t size);
int gpu_memcpy_d2h(void* dst, const void* src, size_t size);
int gpu_memcpy_h2d_on_stream(void* dst, const void* src, size_t size, void* stream);
int gpu_memcpy_d2h_on_stream(void* dst, const void* src, size_t size, void* stream);

// Streams
void* gpu_stream_create();
void gpu_stream_sync(void* stream);
void gpu_stream_destroy(void* stream);

// NTT
int gpu_ntt_init(uint32_t log_n);
void gpu_ntt_cleanup();
int gpu_ntt_dit(void* d_data, uint32_t log_n, int direction, void* stream);
int gpu_ntt_dif(void* d_data, uint32_t log_n, int direction, void* stream);
int gpu_ntt_dit_noscale(void* d_data, uint32_t log_n, int direction, void* stream);
int gpu_ntt_dif_noscale(void* d_data, uint32_t log_n, int direction, void* stream);

// MSM
int gpu_msm(const void* d_points, const void* d_scalars, uint32_t n,
            void* h_result, uint32_t window_size, void* stream);

// Fused FFT: IFFT → element-wise multiply → FFT, all on device
int gpu_fft_scale_fft(void* d_data, void* d_scale, uint32_t log_n,
                      int ifft_dir, int fft_dir, void* stream);

// PLONK constraint evaluation

// Vector operations
int vec_from_mont(void* d_r, const void* d_a, uint32_t n, void* stream);
int gpu_affine_from_mont(void* d_dst, const void* d_src, uint32_t n, void* stream);
int gpu_vec_denominators(void* d_r, const void* d_twiddles, const void* d_coset, uint32_t n, void* stream);
*/
import "C"

import (
	"fmt"
	"math/bits"
	"os"
	"runtime"
	"sync"
	"time"
	"unsafe"
)

var (
	initOnce    sync.Once
	initialized bool
	initErr     error

	// NTT domain tracking
	nttMu   sync.Mutex
	nttLogN uint32

	// Multi-entry GPU points cache for MSM.
	// PLONK uses ~3 different point arrays; caching all avoids 768MB re-uploads.
	// LRU eviction when cache exceeds pointsCacheMax entries.
	pointsMu       sync.Mutex
	pointsCache    []pointsCacheEntry
	pointsCacheMax = 8 // 8 entries × 768MB max = 6GB of 20GB VRAM

	// FFT device buffer pool — eliminates per-call cudaMalloc/cudaFree.
	fftPoolMu  sync.Mutex
	fftPool    []fftBufEntry
	fftPoolCap = 8

	// CUDA stream pool
	streamPoolMu  sync.Mutex
	streamPool    []unsafe.Pointer
	streamPoolCap = 16
)

func releaseReusableMemory() {
	freeCanonicalPoints()

	pointsMu.Lock()
	for _, entry := range pointsCache {
		if entry.devPtr != nil {
			C.gpu_free(entry.devPtr)
		}
	}
	pointsCache = nil
	pointsMu.Unlock()

	fftPoolMu.Lock()
	for _, buf := range fftPool {
		if buf.devPtr != nil {
			C.gpu_free(buf.devPtr)
		}
	}
	fftPool = nil
	fftPoolMu.Unlock()

	streamPoolMu.Lock()
	for _, s := range streamPool {
		if s != nil {
			C.gpu_stream_destroy(s)
		}
	}
	streamPool = nil
	streamPoolMu.Unlock()
}

type fftBufEntry struct {
	devPtr unsafe.Pointer
	size   int // capacity in bytes
}

type pointsCacheEntry struct {
	hostPtr unsafe.Pointer // host base pointer (identity key)
	devPtr  unsafe.Pointer // device pointer
	n       int            // number of points cached
}

type MSMStats struct {
	PointCacheStatus string
	PointTransfer    time.Duration
	ScalarTransfer   time.Duration
	Kernel           time.Duration
	Total            time.Duration
}

// Init initializes the GPU. Safe to call multiple times.
// SetDevice (re)selects CUDA on the calling OS thread. icicle's active device is
// per-thread; goroutines doing a sequence of GPU calls should LockOSThread and
// call this first, else icicle silently uses the CPU backend on device pointers.
func SetDevice() {
	C.gpu_set_device(0)
}

func Init() error {
	initOnce.Do(func() {
		count := C.gpu_device_count()
		if count <= 0 {
			initErr = fmt.Errorf("no GPU devices found")
			return
		}
		if C.gpu_init(0) != 0 {
			initErr = fmt.Errorf("failed to initialize GPU device 0")
			return
		}
		initialized = true
	})
	return initErr
}

// Available returns whether GPU acceleration is available.
func Available() bool {
	Init()
	return initialized
}

// --- Canonical-points cache --------------------------------------------------
// icicle's in-MSM Montgomery conversion is buggy when the MSM is chunked under
// memory pressure (see gnark-cuda/ICICLE_MSM_MONTGOMERY_CHUNKING_BUG.md), so we
// convert points Montgomery->canonical ourselves. Since the SRS bases are reused
// across a prove's ~20 MSMs, cache the canonical device buffer keyed by host ptr
// and convert each base array only once.
type canonEntry struct {
	dev unsafe.Pointer
	n   int
}

var (
	canonMu    sync.Mutex
	canonCache = map[uintptr]canonEntry{}
)

func getCanonicalPoints(pointsPtr unsafe.Pointer, n int) (unsafe.Pointer, string, error) {
	key := uintptr(pointsPtr)
	canonMu.Lock()
	defer canonMu.Unlock()
	if e, ok := canonCache[key]; ok {
		if e.n >= n {
			return e.dev, "hit", nil
		}
		C.gpu_free(e.dev) // host array grew: rebuild
		delete(canonCache, key)
	}
	sz := C.size_t(n * 96)
	dev := C.gpu_malloc(sz)
	if dev == nil {
		return nil, "", fmt.Errorf("GPU malloc failed for points")
	}
	if C.gpu_memcpy_h2d(dev, pointsPtr, sz) != 0 {
		C.gpu_free(dev)
		return nil, "", fmt.Errorf("GPU memcpy H2D failed for points")
	}
	if C.gpu_affine_from_mont(dev, dev, C.uint32_t(n), nil) != 0 { // in-place Montgomery->canonical
		C.gpu_free(dev)
		return nil, "", fmt.Errorf("GPU affine from_mont failed")
	}
	canonCache[key] = canonEntry{dev: dev, n: n}
	return dev, "miss", nil
}

func freeCanonicalPoints() {
	canonMu.Lock()
	for _, e := range canonCache {
		if e.dev != nil {
			C.gpu_free(e.dev)
		}
	}
	canonCache = map[uintptr]canonEntry{}
	canonMu.Unlock()
}

func MSMWithStats(pointsPtr unsafe.Pointer, scalarsPtr unsafe.Pointer, n int, resultPtr unsafe.Pointer) (MSMStats, error) {
	var stats MSMStats
	if n == 0 {
		return stats, nil
	}
	// icicle's device is per-thread; pin this goroutine and select CUDA so all
	// cgo calls below run on a CUDA thread (else icicle uses the CPU backend and
	// segfaults on our device pointers).
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	C.gpu_set_device(0)
	tStart := time.Now()

	scalarsSize := C.size_t(n * 32)

	// Points: converted Montgomery->canonical once and cached by host pointer
	// (the SRS bases are reused across the prove's ~20 MSMs).
	tPoints := time.Now()
	dPoints, pstatus, perr := getCanonicalPoints(pointsPtr, n)
	if perr != nil {
		return stats, perr
	}
	stats.PointTransfer = time.Since(tPoints)
	stats.PointCacheStatus = pstatus

	// Scalars: upload + convert Montgomery->canonical each call (they change).
	tScalars := time.Now()
	dScalars := C.gpu_malloc(scalarsSize)
	if dScalars == nil {
		return stats, fmt.Errorf("GPU malloc failed for scalars")
	}
	defer C.gpu_free(dScalars)
	if C.gpu_memcpy_h2d(dScalars, scalarsPtr, scalarsSize) != 0 {
		return stats, fmt.Errorf("GPU memcpy H2D failed for scalars")
	}
	if C.vec_from_mont(dScalars, dScalars, C.uint32_t(n), nil) != 0 {
		return stats, fmt.Errorf("GPU scalar from_mont failed")
	}
	stats.ScalarTransfer = time.Since(tScalars)

	if os.Getenv("GNARK_GPU_TRACE_MSM") != "" {
		fmt.Fprintf(os.Stderr, "[MSM attempt] MSMWithStats n=%d cache=%s ptr=%p\n", n, pstatus, pointsPtr)
	}
	tKernel := time.Now()
	if C.gpu_msm(dPoints, dScalars, C.uint32_t(n), resultPtr, 0, nil) != 0 {
		return stats, fmt.Errorf("GPU MSM execution failed")
	}

	C.gpu_sync()
	stats.Kernel = time.Since(tKernel)
	stats.Total = time.Since(tStart)

	if os.Getenv("GNARK_GPU_TRACE_MSM") != "" {
		fmt.Fprintf(os.Stderr,
			"[GPU MSM trace] n=%-8d points=%s point_h2d=%v scalar_h2d=%v kernel=%v total=%v host_points=%p host_scalars=%p\n",
			n, stats.PointCacheStatus, stats.PointTransfer, stats.ScalarTransfer, stats.Kernel, stats.Total, pointsPtr, scalarsPtr,
		)
	}

	return stats, nil
}

// MSMDeviceScalarsWithStats computes MSM on GPU where points are identified by the
// host pointer for cache lookup, and scalars are already resident on device.
func MSMDeviceScalarsWithStats(pointsPtr unsafe.Pointer, dScalars unsafe.Pointer, n int, resultPtr unsafe.Pointer) (MSMStats, error) {
	var stats MSMStats
	if n == 0 {
		return stats, nil
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	C.gpu_set_device(0)
	tStart := time.Now()

	// Points: canonical, cached by host pointer (converted once).
	tPoints := time.Now()
	dPoints, pstatus, perr := getCanonicalPoints(pointsPtr, n)
	if perr != nil {
		return stats, perr
	}
	stats.PointTransfer = time.Since(tPoints)
	stats.PointCacheStatus = pstatus

	// Device-resident scalars are Montgomery; convert to canonical in a temp buffer.
	dCanonScalars := C.gpu_malloc(C.size_t(n * 32))
	if dCanonScalars == nil {
		return stats, fmt.Errorf("GPU malloc failed for scalars")
	}
	defer C.gpu_free(dCanonScalars)
	if C.vec_from_mont(dCanonScalars, dScalars, C.uint32_t(n), nil) != 0 {
		return stats, fmt.Errorf("GPU scalar from_mont failed")
	}

	tKernel := time.Now()
	if C.gpu_msm(dPoints, dCanonScalars, C.uint32_t(n), resultPtr, 0, nil) != 0 {
		return stats, fmt.Errorf("GPU MSM execution failed")
	}
	C.gpu_sync()
	stats.Kernel = time.Since(tKernel)
	stats.Total = time.Since(tStart)

	if os.Getenv("GNARK_GPU_TRACE_MSM") != "" {
		fmt.Fprintf(os.Stderr,
			"[GPU MSM device-scalars] n=%-8d points=%s point_h2d=%v kernel=%v total=%v host_points=%p device_scalars=%p\n",
			n, stats.PointCacheStatus, stats.PointTransfer, stats.Kernel, stats.Total, pointsPtr, dScalars,
		)
	}

	return stats, nil
}

// pointsCacheLookupFull finds a cached device pointer for the given host pointer.
// Returns (devPtr, cachedN). If devPtr is nil, no entry exists.
// If cachedN < n, the entry exists but needs growing.
// Moves found entry to front (MRU). Must be called with pointsMu held.
func pointsCacheLookupFull(hostPtr unsafe.Pointer, n int) (unsafe.Pointer, int) {
	for i, e := range pointsCache {
		if e.hostPtr == hostPtr {
			if i > 0 {
				entry := pointsCache[i]
				copy(pointsCache[1:i+1], pointsCache[:i])
				pointsCache[0] = entry
			}
			return e.devPtr, e.n
		}
	}
	return nil, 0
}

// pointsCacheUpdate replaces an existing entry's device pointer and size.
// Must be called with pointsMu held.
func pointsCacheUpdate(hostPtr unsafe.Pointer, newDev unsafe.Pointer, n int, oldDev unsafe.Pointer) {
	for i := range pointsCache {
		if pointsCache[i].hostPtr == hostPtr {
			C.gpu_free(oldDev)
			pointsCache[i].devPtr = newDev
			pointsCache[i].n = n
			return
		}
	}
}

// pointsCacheInsert adds a new entry at front, evicting LRU if at capacity.
// Must be called with pointsMu held.
func pointsCacheInsert(hostPtr unsafe.Pointer, devPtr unsafe.Pointer, n int) {
	entry := pointsCacheEntry{hostPtr: hostPtr, devPtr: devPtr, n: n}
	if len(pointsCache) >= pointsCacheMax {
		evicted := pointsCache[len(pointsCache)-1]
		C.gpu_free(evicted.devPtr)
		pointsCache = pointsCache[:len(pointsCache)-1]
	}
	pointsCache = append([]pointsCacheEntry{entry}, pointsCache...)
}

// NTTMaxLogN is the maximum NTT domain size to pre-allocate.
// PLONK uses up to 2^25 for coset inverse FFT (4× the constraint count).
// Pre-allocating avoids dangerous mid-prove reallocation that races with
// concurrent FFT goroutines.
const NTTMaxLogN = 25

// NTTInit initializes the NTT domain for size 2^logN.
// On first call, pre-allocates for NTTMaxLogN to avoid reallocation races.
func NTTInit(logN uint32) error {
	if err := Init(); err != nil {
		return err
	}

	nttMu.Lock()
	defer nttMu.Unlock()

	if nttLogN >= logN {
		return nil
	}

	// Pre-allocate for max size on first init to avoid dangerous realloc
	// while other goroutines have in-flight FFT kernels.
	targetLogN := logN
	if targetLogN < NTTMaxLogN {
		targetLogN = NTTMaxLogN
	}

	if nttLogN > 0 {
		C.gpu_sync()
		C.gpu_ntt_cleanup()
	}

	if C.gpu_ntt_init(C.uint32_t(targetLogN)) != 0 {
		// NTT twiddles compete with persistent MSM/FFT caches for VRAM.
		// Drop all reusable buffers and retry before falling back.
		C.gpu_sync()
		releaseReusableMemory()

		if C.gpu_ntt_init(C.uint32_t(targetLogN)) == 0 {
			nttLogN = targetLogN
			return nil
		}

		// If max size fails, retry the requested size after the cleanup.
		if targetLogN > logN {
			C.gpu_sync()
			releaseReusableMemory()
			if C.gpu_ntt_init(C.uint32_t(logN)) != 0 {
				return fmt.Errorf("GPU NTT init failed for logN=%d", logN)
			}
			nttLogN = logN
			return nil
		}
		return fmt.Errorf("GPU NTT init failed for logN=%d", logN)
	}
	nttLogN = targetLogN
	return nil
}

// FFTMode specifies DIT or DIF decimation.
type FFTMode int

const (
	FFT_DIT FFTMode = 0 // Decimation in time: bit-reversed input → normal output
	FFT_DIF FFTMode = 1 // Decimation in frequency: normal input → bit-reversed output
)

// Malloc allocates GPU device memory.
func Malloc(size int) unsafe.Pointer {
	return C.gpu_malloc(C.size_t(size))
}

// Free frees GPU device memory.
func Free(ptr unsafe.Pointer) {
	C.gpu_free(ptr)
}

// MemcpyH2D copies from host to device.
func MemcpyH2D(dst unsafe.Pointer, src unsafe.Pointer, size int) error {
	if C.gpu_memcpy_h2d(dst, src, C.size_t(size)) != 0 {
		return fmt.Errorf("GPU H2D failed (%d bytes)", size)
	}
	return nil
}

// MemcpyD2H copies from device to host.
func MemcpyD2H(dst unsafe.Pointer, src unsafe.Pointer, size int) error {
	if C.gpu_memcpy_d2h(dst, src, C.size_t(size)) != 0 {
		return fmt.Errorf("GPU D2H failed (%d bytes)", size)
	}
	return nil
}

// StreamAcquire gets a CUDA stream from the pool or creates one.
func StreamAcquire() unsafe.Pointer {
	return streamAcquire()
}

// StreamRelease returns a stream to the pool or destroys it.
func StreamRelease(s unsafe.Pointer) {
	streamRelease(s)
}

// StreamSync waits for work submitted to a CUDA stream.
func StreamSync(s unsafe.Pointer) {
	C.gpu_stream_sync(s)
}

// VecDenominators computes r[i] = 1 / (coset * twiddles[i] - 1) on device.
func VecDenominators(dst, twiddles, coset unsafe.Pointer, n int, stream unsafe.Pointer) error {
	if n == 0 {
		return nil
	}
	if C.gpu_vec_denominators(dst, twiddles, coset, C.uint32_t(n), stream) != 0 {
		return fmt.Errorf("GPU denominator kernel failed")
	}
	return nil
}

// fftBufAcquire gets a device buffer from the pool, or allocates one.
func fftBufAcquire(size int) unsafe.Pointer {
	fftPoolMu.Lock()
	for i, buf := range fftPool {
		if buf.size >= size {
			// Remove from pool and return
			fftPool[i] = fftPool[len(fftPool)-1]
			fftPool = fftPool[:len(fftPool)-1]
			fftPoolMu.Unlock()
			return buf.devPtr
		}
	}
	fftPoolMu.Unlock()
	// Pool empty or no buffer big enough — allocate new
	return C.gpu_malloc(C.size_t(size))
}

// fftBufRelease returns a device buffer to the pool (or frees if pool full).
func fftBufRelease(devPtr unsafe.Pointer, size int) {
	fftPoolMu.Lock()
	if len(fftPool) < fftPoolCap {
		fftPool = append(fftPool, fftBufEntry{devPtr: devPtr, size: size})
		fftPoolMu.Unlock()
		return
	}
	fftPoolMu.Unlock()
	C.gpu_free(devPtr)
}

// streamAcquire gets a CUDA stream from the pool or creates one.
func streamAcquire() unsafe.Pointer {
	streamPoolMu.Lock()
	if len(streamPool) > 0 {
		s := streamPool[len(streamPool)-1]
		streamPool = streamPool[:len(streamPool)-1]
		streamPoolMu.Unlock()
		return s
	}
	streamPoolMu.Unlock()
	return C.gpu_stream_create()
}

// streamRelease returns a stream to the pool or destroys it.
func streamRelease(s unsafe.Pointer) {
	streamPoolMu.Lock()
	if len(streamPool) < streamPoolCap {
		streamPool = append(streamPool, s)
		streamPoolMu.Unlock()
		return
	}
	streamPoolMu.Unlock()
	C.gpu_stream_destroy(s)
}

// FFTScaleFFT performs fused IFFT → element-wise multiply → FFT on GPU.
// Eliminates H2D→D2H round-trip between IFFT and FFT phases.
// dataPtr: polynomial data, scalePtr: scaling vector (both n fr.Elements).
// ifftMode/fftMode: FFT_DIT or FFT_DIF for respective phases.
func FFTScaleFFT(dataPtr unsafe.Pointer, scalePtr unsafe.Pointer, n int,
	ifftMode FFTMode, fftMode FFTMode) error {
	if n == 0 {
		return nil
	}

	logN := uint32(bits.TrailingZeros64(uint64(n)))
	if 1<<logN != n {
		return fmt.Errorf("FFT size must be a power of 2, got %d", n)
	}

	if err := NTTInit(logN); err != nil {
		return err
	}

	dataBytes := n * 32
	dataSize := C.size_t(dataBytes)

	// Allocate device buffers for data and scaling vector
	dData := fftBufAcquire(dataBytes)
	if dData == nil {
		return fmt.Errorf("GPU malloc failed for FFTScaleFFT data")
	}
	defer fftBufRelease(dData, dataBytes)

	dScale := fftBufAcquire(dataBytes)
	if dScale == nil {
		return fmt.Errorf("GPU malloc failed for FFTScaleFFT scale")
	}
	defer fftBufRelease(dScale, dataBytes)

	stream := streamAcquire()
	if stream == nil {
		return fmt.Errorf("GPU stream create failed")
	}
	defer streamRelease(stream)

	// Upload data and scaling vector
	if C.gpu_memcpy_h2d_on_stream(dData, dataPtr, dataSize, stream) != 0 {
		return fmt.Errorf("FFTScaleFFT: H2D data failed")
	}
	if C.gpu_memcpy_h2d_on_stream(dScale, scalePtr, dataSize, stream) != 0 {
		return fmt.Errorf("FFTScaleFFT: H2D scale failed")
	}

	// Fused IFFT → multiply → FFT on device
	ifftDir := C.int(0) // DIT
	if ifftMode == FFT_DIF {
		ifftDir = 1
	}
	fftDir := C.int(0) // DIT
	if fftMode == FFT_DIF {
		fftDir = 1
	}

	if C.gpu_fft_scale_fft(dData, dScale, C.uint32_t(logN), ifftDir, fftDir, stream) != 0 {
		return fmt.Errorf("FFTScaleFFT: kernel failed")
	}

	// Download result
	if C.gpu_memcpy_d2h_on_stream(dataPtr, dData, dataSize, stream) != 0 {
		return fmt.Errorf("FFTScaleFFT: D2H failed")
	}

	C.gpu_stream_sync(stream)
	return nil
}

// fftExec runs an FFT on GPU with a pooled buffer and per-call stream.
// The per-call stream ensures cudaStreamSynchronize only waits for THIS FFT,
// not all GPU work from other goroutines.
func fftExec(dataPtr unsafe.Pointer, n int, logN uint32, kernelFn func(unsafe.Pointer, C.uint32_t, unsafe.Pointer) C.int) error {
	dataBytes := n * 32
	dataSize := C.size_t(dataBytes)

	dData := fftBufAcquire(dataBytes)
	if dData == nil {
		return fmt.Errorf("GPU malloc failed for FFT data (%d bytes)", dataBytes)
	}
	defer fftBufRelease(dData, dataBytes)

	stream := streamAcquire()
	if stream == nil {
		return fmt.Errorf("GPU stream create failed")
	}
	defer streamRelease(stream)

	if C.gpu_memcpy_h2d_on_stream(dData, dataPtr, dataSize, stream) != 0 {
		return fmt.Errorf("GPU H2D failed for FFT data")
	}

	if kernelFn(dData, C.uint32_t(logN), stream) != 0 {
		return fmt.Errorf("GPU NTT kernel failed")
	}

	if C.gpu_memcpy_d2h_on_stream(dataPtr, dData, dataSize, stream) != 0 {
		return fmt.Errorf("GPU D2H failed for FFT data")
	}

	// Only waits for this stream's work — other goroutines' FFTs proceed independently
	C.gpu_stream_sync(stream)
	return nil
}

// FFTInverseNoScale performs inverse FFT on GPU WITHOUT 1/n scaling.
// Used for coset inverse FFT where the caller handles cosetTableInv * CardinalityInv.
func FFTInverseNoScale(dataPtr unsafe.Pointer, n int, mode FFTMode) error {
	if n == 0 {
		return nil
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	C.gpu_set_device(0)

	logN := uint32(bits.TrailingZeros64(uint64(n)))
	if 1<<logN != n {
		return fmt.Errorf("FFT size must be a power of 2, got %d", n)
	}

	if err := NTTInit(logN); err != nil {
		return fmt.Errorf("FFTInverseNoScale: NTTInit(logN=%d) failed: %w", logN, err)
	}

	return fftExec(dataPtr, n, logN, func(dData unsafe.Pointer, ln C.uint32_t, stream unsafe.Pointer) C.int {
		if mode == FFT_DIF {
			return C.gpu_ntt_dif_noscale(dData, ln, 1, stream)
		}
		return C.gpu_ntt_dit_noscale(dData, ln, 1, stream)
	})
}

// FFT performs forward or inverse FFT on GPU.
// Uses pooled buffers and per-call streams for concurrent goroutine safety.
func FFT(dataPtr unsafe.Pointer, n int, inverse bool, mode FFTMode) error {
	if n == 0 {
		return nil
	}
	// icicle's device is per-thread; pin + select CUDA (else CPU-backend NTT
	// segfaults on our device pointers).
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	C.gpu_set_device(0)

	logN := uint32(bits.TrailingZeros64(uint64(n)))
	if 1<<logN != n {
		return fmt.Errorf("FFT size must be a power of 2, got %d", n)
	}

	if err := NTTInit(logN); err != nil {
		return err
	}

	direction := C.int(0)
	if inverse {
		direction = 1
	}

	return fftExec(dataPtr, n, logN, func(dData unsafe.Pointer, ln C.uint32_t, stream unsafe.Pointer) C.int {
		if mode == FFT_DIF {
			return C.gpu_ntt_dif(dData, ln, direction, stream)
		}
		return C.gpu_ntt_dit(dData, ln, direction, stream)
	})
}
