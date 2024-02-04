package icicle_bn254

import (
	"errors"
	"fmt"
	"sync"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	iciclegnark "github.com/ingonyama-zk/iciclegnark/curves/bn254"
)

var (
	ErrInvalidPolynomialSize = errors.New("invalid polynomial size (larger than SRS or == 0)")
)

// Digest commitment of a polynomial.
type Digest = bn254.G1Affine

// Commit commits to a polynomial using a multi exponentiation with the SRS.
// It is assumed that the polynomial is in canonical form, in Montgomery form.
func kzgDeviceCommit(p []fr.Element, G1 unsafe.Pointer, nbTasks ...int) (Digest, error) {
	// Size of the polynomial
	np := len(p)

	// Size of the polynomial in bytes
	sizeBytesScalars := np * fr.Bytes

	// Initialize Scalar channels
	copyCpDone := make(chan unsafe.Pointer, 1)
	cpDeviceData := make(chan iciclegnark.OnDeviceData, 1)

	// Copy Scalar to device
	go func() {
		// Perform copy operation
		iciclegnark.CopyToDevice(p, sizeBytesScalars, copyCpDone)

		// Receive result once copy operation is done
		cpDevice := <-copyCpDone

		// Create OnDeviceData
		cpDeviceValue := iciclegnark.OnDeviceData{
			P:    cpDevice,
			Size: sizeBytesScalars,
		}

		// Send OnDeviceData to respective channel
		cpDeviceData <- cpDeviceValue

		// Close channels
		close(copyCpDone)
		close(cpDeviceData)
	}()

	// Wait for copy operation to finish
	cpDeviceValue := <-cpDeviceData

	// KZG Committment on device
	var wg sync.WaitGroup

	// Perform multi exponentiation on device
	wg.Add(1)
	tmpChan := make(chan bn254.G1Affine, 1)
	go func() {
		defer wg.Done()
		tmp, _, err := iciclegnark.MsmOnDevice(cpDeviceValue.P, G1, np, true)
		//fmt.Println("tmp", tmp)
		if err != nil {
			fmt.Print("error", err)
		}
		var res bn254.G1Affine
		res.FromJacobian(&tmp)
		tmpChan <- res
	}()
	wg.Wait()

	// Receive result once copy operation is done
	res := <-tmpChan

	// Free device memory
	go func() {
		iciclegnark.FreeDevicePointer(unsafe.Pointer(&cpDeviceValue))
	}()

	return res, nil
}

// Open computes an opening proof of polynomial p at given point.
// fft.Domain Cardinality must be larger than p.Degree()
func kzgDeviceOpen(p []fr.Element, point fr.Element, pk *ProvingKey) (kzg.OpeningProof, error) {
	// build the proof
	res := kzg.OpeningProof{
		ClaimedValue: eval(p, point),
	}

	// compute H
	// h reuses memory from _p
	_p := make([]fr.Element, len(p))
	copy(_p, p)
	h := dividePolyByXminusA(_p, res.ClaimedValue, point)

	// commit to H
	hCommit, err := kzgDeviceCommit(h, pk.deviceInfo.G1Device.G1)
	if err != nil {
		return kzg.OpeningProof{}, err
	}
	res.H.Set(&hCommit)

	return res, nil
}

// dividePolyByXminusA computes (f-f(a))/(x-a), in canonical basis, in regular form
// f memory is re-used for the result
func dividePolyByXminusA(f []fr.Element, fa, a fr.Element) []fr.Element {

	// first we compute f-f(a)
	f[0].Sub(&f[0], &fa)

	// now we use synthetic division to divide by x-a
	var t fr.Element
	for i := len(f) - 2; i >= 0; i-- {
		t.Mul(&f[i+1], &a)

		f[i].Add(&f[i], &t)
	}

	// the result is of degree deg(f)-1
	return f[1:]
}

// eval returns p(point) where p is interpreted as a polynomial
// ∑_{i<len(p)}p[i]Xⁱ
func eval(p []fr.Element, point fr.Element) fr.Element {
	var res fr.Element
	n := len(p)
	res.Set(&p[n-1])
	for i := n - 2; i >= 0; i-- {
		res.Mul(&res, &point).Add(&res, &p[i])
	}
	return res
}
