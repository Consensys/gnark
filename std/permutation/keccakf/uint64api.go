package keccakf

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
)

// Uint64api performs binary operations on Xuint64 variables. In the
// future possibly using lookup tables.
//
// TODO: we could possibly optimise using hints if working over many inputs. For
// example, if we OR many bits, then the result is 0 if the sum of the bits is
// larger than 1. And AND is 1 if the sum of bits is the number of inputs. BUt
// this probably helps only if we have a lot of similar operations in a row
// (more than 4). We could probably unroll the whole permutation and expand all
// the formulas to see. But long term tables are still better.
type Uint64api struct {
	api frontend.API
}

func NewUint64API(api frontend.API) *Uint64api {
	return &Uint64api{
		api: api,
	}
}

// varUint64 represents 64-bit unsigned integer. We use this type to ensure that
// we work over constrained bits. Do not initialize directly, use [wideBinaryOpsApi.asUint64].
type Xuint64 [64]frontend.Variable

func ConstUint64(a uint64) Xuint64 {
	var res Xuint64
	for i := 0; i < 64; i++ {
		res[i] = (a >> i) & 1
	}
	return res
}

func (w *Uint64api) AsUint64FromBytes(in ...frontend.Variable) Xuint64 {
	return w.AsUint64(bits.FromBinary(w.api, in))
}

func (w *Uint64api) AsUint64(in frontend.Variable) Xuint64 {
	bits := bits.ToBinary(w.api, in, bits.WithNbDigits(64))
	var res Xuint64
	copy(res[:], bits)
	return res
}

func (w *Uint64api) FromUint64(in Xuint64) frontend.Variable {
	return bits.FromBinary(w.api, in[:], bits.WithUnconstrainedInputs())
}

func (w *Uint64api) And(in ...Xuint64) Xuint64 {
	var res Xuint64
	for i := range res {
		res[i] = 1
	}
	for i := range res {
		for _, v := range in {
			res[i] = w.api.And(res[i], v[i])
		}
	}
	return res
}

func (w *Uint64api) Or(in ...Xuint64) Xuint64 {
	var res Xuint64
	for i := range res {
		res[i] = 0
	}
	for i := range res {
		for _, v := range in {
			res[i] = w.api.Or(res[i], v[i])
		}
	}
	return res
}

func (w *Uint64api) Xor(in ...Xuint64) Xuint64 {
	var res Xuint64
	for i := range res {
		res[i] = 0
	}
	for i := range res {
		for _, v := range in {
			if v[i] != nil {
				res[i] = w.api.Xor(res[i], v[i])
			}
		}
	}
	return res
}

func (w *Uint64api) Lrot(in Xuint64, shift int) Xuint64 {
	var res Xuint64
	for i := range res {
		res[i] = in[(i-shift+64)%64]
	}
	return res
}

func (w *Uint64api) not(in Xuint64) Xuint64 {
	// TODO: it would be better to have separate method for it. If we have
	// native API support, then in R1CS would be free (1-X) and in PLONK 1
	// constraint (1-X). But if we do XOR, then we always have a constraint with
	// R1CS (not sure if 1-2 with PLONK). If we do 1-X ourselves, then compiler
	// marks as binary which is 1-2 (R1CS-PLONK).
	var res Xuint64
	for i := range res {
		res[i] = w.api.Xor(in[i], 1)
	}
	return res
}

func (w *Uint64api) assertEq(a, b Xuint64) {
	for i := range a {
		w.api.AssertIsEqual(a[i], b[i])
	}
}

func (w *Uint64api) EncodeToXuint8(b []Xuint8, x Xuint64) []Xuint8 {
	var res [8]Xuint8
	copy(res[0][:], x[0:8])
	copy(res[1][:], x[8:16])
	copy(res[2][:], x[16:24])
	copy(res[3][:], x[24:32])
	copy(res[4][:], x[32:40])
	copy(res[5][:], x[40:48])
	copy(res[6][:], x[48:56])
	copy(res[7][:], x[56:64])
	return append(b, res[0], res[1], res[2], res[3], res[4], res[5], res[6], res[7])
}
