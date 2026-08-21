//go:build js && wasm

package bls12381

import (
	"encoding/binary"
	"fmt"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const (
	frBytes           = 32
	g1CoordinateBytes = 48
	g1PointBytes      = 144
	g2ComponentBytes  = 48
	g2PointBytes      = 288
)

func packFrVectorRegularLEInto(dst []byte, values []fr.Element) []byte {
	required := len(values) * frBytes
	if cap(dst) < required {
		dst = make([]byte, required)
	} else {
		dst = dst[:required]
	}
	for i := range values {
		base := i * frBytes
		writeFrRegularLE(dst[base:base+frBytes], &values[i])
	}
	return dst
}

func packFrVectorRegularLEFilteredOutInto(dst []byte, values []fr.Element, firstIndex int, remove []int) []byte {
	if len(remove) == 0 {
		return packFrVectorRegularLEInto(dst, values)
	}
	removeSet := make(map[int]struct{}, len(remove))
	for _, idx := range remove {
		removeSet[idx] = struct{}{}
	}
	count := 0
	for i := range values {
		if _, ok := removeSet[firstIndex+i]; !ok {
			count++
		}
	}
	required := count * frBytes
	if cap(dst) < required {
		dst = make([]byte, required)
	} else {
		dst = dst[:required]
	}
	offset := 0
	for i := range values {
		if _, ok := removeSet[firstIndex+i]; ok {
			continue
		}
		writeFrRegularLE(dst[offset:offset+frBytes], &values[i])
		offset += frBytes
	}
	return dst
}

func packFrVectorMontLEPaddedInto(dst []byte, values []fr.Element, size int) []byte {
	required := size * frBytes
	if cap(dst) < required {
		dst = make([]byte, required)
	} else {
		dst = dst[:required]
		clear(dst)
	}
	for i := range values {
		base := i * frBytes
		writeFrMontLE(dst[base:base+frBytes], &values[i])
	}
	return dst
}

func packFrVectorFilteredInto(dst []byte, values []fr.Element, keptPrefixIndices []int, prefixLen int) ([]byte, int) {
	limit := prefixLen
	if limit > len(values) {
		limit = len(values)
	}
	count := len(values) - limit
	for _, idx := range keptPrefixIndices {
		if idx >= limit {
			break
		}
		count++
	}
	required := count * frBytes
	if cap(dst) < required {
		dst = make([]byte, required)
	} else {
		dst = dst[:required]
	}
	offset := 0
	for _, idx := range keptPrefixIndices {
		if idx >= limit {
			break
		}
		writeFrRegularLE(dst[offset:offset+frBytes], &values[idx])
		offset += frBytes
	}
	for i := limit; i < len(values); i++ {
		writeFrRegularLE(dst[offset:offset+frBytes], &values[i])
		offset += frBytes
	}
	return dst, count
}

func writeFrRegularLE(dst []byte, value *fr.Element) {
	be := value.Bytes()
	for i := 0; i < frBytes; i++ {
		dst[i] = be[frBytes-1-i]
	}
}

func writeFrMontLE(dst []byte, value *fr.Element) {
	for i, word := range [4]uint64(*value) {
		binary.LittleEndian.PutUint64(dst[i*8:(i+1)*8], word)
	}
}

func packG1AffineJacobianBatch(points []bls12381.G1Affine) []byte {
	out := make([]byte, len(points)*g1PointBytes)
	one := fpOneMontLE()
	for i := range points {
		if points[i].IsInfinity() {
			continue
		}
		base := i * g1PointBytes
		writeFPMontLE(out[base:base+g1CoordinateBytes], &points[i].X)
		writeFPMontLE(out[base+g1CoordinateBytes:base+2*g1CoordinateBytes], &points[i].Y)
		copy(out[base+2*g1CoordinateBytes:base+3*g1CoordinateBytes], one)
	}
	return out
}

func packG2AffineJacobianBatch(points []bls12381.G2Affine) []byte {
	out := make([]byte, len(points)*g2PointBytes)
	one := fpOneMontLE()
	for i := range points {
		if points[i].IsInfinity() {
			continue
		}
		base := i * g2PointBytes
		writeFPMontLE(out[base:base+g2ComponentBytes], &points[i].X.A0)
		writeFPMontLE(out[base+g2ComponentBytes:base+2*g2ComponentBytes], &points[i].X.A1)
		writeFPMontLE(out[base+2*g2ComponentBytes:base+3*g2ComponentBytes], &points[i].Y.A0)
		writeFPMontLE(out[base+3*g2ComponentBytes:base+4*g2ComponentBytes], &points[i].Y.A1)
		copy(out[base+4*g2ComponentBytes:base+5*g2ComponentBytes], one)
	}
	return out
}

func decodeG1AffineFromPacked(packed []byte, err error) (bls12381.G1Affine, error) {
	if err != nil {
		return bls12381.G1Affine{}, err
	}
	if len(packed) != 2*g1CoordinateBytes {
		return bls12381.G1Affine{}, fmt.Errorf("webgpu groth16 bls12_381: expected %d G1 bytes, got %d", 2*g1CoordinateBytes, len(packed))
	}
	return bls12381.G1Affine{
		X: readFPMontLE(packed[:g1CoordinateBytes]),
		Y: readFPMontLE(packed[g1CoordinateBytes:]),
	}, nil
}

func decodeG2AffineFromPacked(packed []byte, err error) (bls12381.G2Affine, error) {
	if err != nil {
		return bls12381.G2Affine{}, err
	}
	if len(packed) != 4*g2ComponentBytes {
		return bls12381.G2Affine{}, fmt.Errorf("webgpu groth16 bls12_381: expected %d G2 bytes, got %d", 4*g2ComponentBytes, len(packed))
	}
	var out bls12381.G2Affine
	out.X.A0 = readFPMontLE(packed[0*g2ComponentBytes : 1*g2ComponentBytes])
	out.X.A1 = readFPMontLE(packed[1*g2ComponentBytes : 2*g2ComponentBytes])
	out.Y.A0 = readFPMontLE(packed[2*g2ComponentBytes : 3*g2ComponentBytes])
	out.Y.A1 = readFPMontLE(packed[3*g2ComponentBytes : 4*g2ComponentBytes])
	return out, nil
}

// WebGPU point buffers use raw Montgomery little-endian coordinates. The
// fp.LittleEndian helpers convert to/from regular representation, so they are
// not equivalent here.
func readFPMontLE(src []byte) fp.Element {
	var words [6]uint64
	for i := range words {
		words[i] = binary.LittleEndian.Uint64(src[i*8 : (i+1)*8])
	}
	return fp.Element(words)
}

func writeFPMontLE(dst []byte, value *fp.Element) {
	for i, word := range [6]uint64(*value) {
		binary.LittleEndian.PutUint64(dst[i*8:(i+1)*8], word)
	}
}

func fpOneMontLE() []byte {
	out := make([]byte, g1CoordinateBytes)
	var one fp.Element
	one.SetOne()
	writeFPMontLE(out, &one)
	return out
}
