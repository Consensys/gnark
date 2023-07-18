//go:build gpu

package groth16

import (
	"fmt"
	"unsafe"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	cudawrapper "github.com/ingonyama-zk/icicle/goicicle"
	icicle "github.com/ingonyama-zk/icicle/goicicle/curves/bn254"
)

type OnDeviceData struct {
	p unsafe.Pointer
	size int
}

func INttOnDevice(scalars_d, twiddles_d, cosetPowers_d unsafe.Pointer, size, sizeBytes int, isCoset bool) unsafe.Pointer {
	icicle.ReverseScalars(scalars_d, size)

	scalarsInterp := icicle.Interpolate(scalars_d, twiddles_d, cosetPowers_d, size, isCoset)

	return scalarsInterp
}


func NttOnDevice(scalars_out, scalars_d, twiddles_d, coset_powers_d unsafe.Pointer, size, twid_size, size_bytes int, isCoset bool) {
	res := icicle.Evaluate(scalars_out, scalars_d, twiddles_d, coset_powers_d, size, twid_size, isCoset)

	if res != 0 {
		fmt.Print("Issue evaluating")
	}

	icicle.ReverseScalars(scalars_out, size)

	return
}

func MsmOnDevice(scalars_d, points_d unsafe.Pointer, count int, convert bool) (curve.G1Jac, unsafe.Pointer, error) {
	out_d, _ := cudawrapper.CudaMalloc(96)

	icicle.Commit(out_d, scalars_d, points_d, count, 10)

	if convert {
		outHost := make([]icicle.PointBN254, 1)
		cudawrapper.CudaMemCpyDtoH[icicle.PointBN254](outHost, out_d, 96)
		return *outHost[0].ToGnarkJac(), nil, nil
	}

	return curve.G1Jac{}, out_d, nil
}

func MsmG2OnDevice(scalars_d, points_d unsafe.Pointer, count int, convert bool) (curve.G2Jac, unsafe.Pointer, error) {
	out_d, _ := cudawrapper.CudaMalloc(192)
	
	icicle.CommitG2(out_d, scalars_d, points_d, count, 10)
	
	if convert {
		outHost := make([]icicle.G2Point, 1)
		cudawrapper.CudaMemCpyDtoH[icicle.G2Point](outHost, out_d, 192)
		return *outHost[0].ToGnarkJac(), nil, nil
	}

	return curve.G2Jac{}, out_d, nil
}

func PolyOps(a_d, b_d, c_d, den_d unsafe.Pointer, size int) {
	ret := icicle.VecScalarMulMod(a_d, b_d, size)

	if ret != 0 {
		fmt.Print("Vector mult a*b issue")
	}
	ret = icicle.VecScalarSub(a_d, c_d, size)

	if ret != 0 {
		fmt.Print("Vector sub issue")
	}
	ret = icicle.VecScalarMulMod(a_d, den_d, size)

	if ret != 0 {
		fmt.Print("Vector mult a*den issue")
	}
	
	return
}

func MontConvOnDevice(scalars_d unsafe.Pointer, size int, is_into bool) {
	if is_into {
		icicle.ToMontgomery(scalars_d, size)
	} else {
		icicle.FromMontgomery(scalars_d, size)
	}

	return
}

func CopyToDevice(scalars []fr.Element, bytes int, copyDone chan unsafe.Pointer) {
	devicePtr, _ := cudawrapper.CudaMalloc(bytes)
	cudawrapper.CudaMemCpyHtoD[fr.Element](devicePtr, scalars, bytes)
	MontConvOnDevice(devicePtr, len(scalars), false)

	copyDone <- devicePtr
}
