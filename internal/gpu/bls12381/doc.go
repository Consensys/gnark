// Package gpu provides the cgo bindings to libgnark_cuda used by the CUDA
// accelerated PLONK backend (backend/accelerated/cuda) and the device-resident
// rho-loop. The implementation is behind the cuda build tag (see gpu.go); this
// file keeps the package present without the tag.
package gpu
