package maptocurve

import (
	"fmt"
	"math/big"

	bn254fp "github.com/consensys/gnark-crypto/ecc/bn254/fp"
	secp256k1fp "github.com/consensys/gnark-crypto/ecc/secp256k1/fp"
	secp256r1fp "github.com/consensys/gnark-crypto/ecc/secp256r1/fp"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
)

func init() {
	solver.RegisterHint(GetHints()...)
}

// GetHints returns all hint functions used in the package.
func GetHints() []solver.Hint {
	return []solver.Hint{
		xIncrementHint,
		yIncrementHint,
	}
}

// parseHintInputs extracts the field modulus and message from the hint inputs.
// Format: [nbLimbs, q_limbs..., msg_limbs...]
func parseHintInputs(inputs []*big.Int) (q *big.Int, nbLimbs int, msg *big.Int, err error) {
	if len(inputs) < 1 {
		return nil, 0, nil, fmt.Errorf("empty inputs")
	}
	nbLimbs = int(inputs[0].Int64())
	expected := 1 + 2*nbLimbs
	if len(inputs) != expected {
		return nil, 0, nil, fmt.Errorf("expected %d inputs, got %d", expected, len(inputs))
	}
	q = recompose(inputs[1:1+nbLimbs], nbLimbs)
	msg = recompose(inputs[1+nbLimbs:1+2*nbLimbs], nbLimbs)
	return q, nbLimbs, msg, nil
}

// xIncrementHint computes the x-increment witness for a given message.
//
// Inputs: [nbLimbs, q_limbs..., msg_limbs...]
// Outputs: [k, x_limbs..., y_limbs..., z_limbs...]
//
// Searches k ∈ [0, T) such that x = msg*T + k lies on the curve and y has a
// 2^s-th root. Only practical for low 2-adicity fields (S ≤ 4).
func xIncrementHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	q, nbLimbs, msg, err := parseHintInputs(inputs)
	if err != nil {
		return fmt.Errorf("xIncrementHint: %w", err)
	}

	switch {
	case q.Cmp(bn254fp.Modulus()) == 0:
		return xIncrementBN254(nbLimbs, msg, outputs)
	case q.Cmp(secp256k1fp.Modulus()) == 0:
		return xIncrementSecp256k1(nbLimbs, msg, outputs)
	case q.Cmp(secp256r1fp.Modulus()) == 0:
		return xIncrementSecp256r1(nbLimbs, msg, outputs)
	default:
		return fmt.Errorf("xIncrementHint: unsupported field modulus")
	}
}

// yIncrementHint computes the y-increment witness for a given message.
//
// Inputs: [nbLimbs, q_limbs..., msg_limbs...]
// Outputs: [k, x_limbs...]
//
// For j=0 curves (a=0): x = cbrt(y² - b) where y = msg*T + k.
// For P-256 (a≠0): x is found via Cardano's formula on x³ − 3x + (b − y²) = 0.
func yIncrementHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	q, nbLimbs, msg, err := parseHintInputs(inputs)
	if err != nil {
		return fmt.Errorf("yIncrementHint: %w", err)
	}

	switch {
	case q.Cmp(bn254fp.Modulus()) == 0:
		return yIncrementBN254(nbLimbs, msg, outputs)
	case q.Cmp(secp256k1fp.Modulus()) == 0:
		return yIncrementSecp256k1(nbLimbs, msg, outputs)
	case q.Cmp(secp256r1fp.Modulus()) == 0:
		return yIncrementSecp256r1(nbLimbs, msg, outputs)
	default:
		return fmt.Errorf("yIncrementHint: unsupported field modulus")
	}
}

// --- BN254 ---

// BN254: y² = x³ + 3, S=1
func xIncrementBN254(nbLimbs int, msg *big.Int, outputs []*big.Int) error {
	const s = 1
	var msgFp, bFp, tFp, xBase bn254fp.Element
	msgFp.SetBigInt(msg)
	bFp.SetUint64(3)
	tFp.SetUint64(T)
	xBase.Mul(&msgFp, &tFp)

	for k := uint64(0); k < T; k++ {
		var kFp, x, x2, rhs, y bn254fp.Element
		kFp.SetUint64(k)
		x.Add(&xBase, &kFp)

		x2.Square(&x)
		rhs.Mul(&x2, &x)
		rhs.Add(&rhs, &bFp)

		if y.Sqrt(&rhs) == nil {
			continue
		}

		z := nthRoot2SBN254(&y, s)
		if z == nil {
			y.Neg(&y)
			z = nthRoot2SBN254(&y, s)
			if z == nil {
				continue
			}
		}

		var xBig, yBig, zBig big.Int
		outputs[0].SetUint64(k)
		decompose(x.BigInt(&xBig), nbLimbs, outputs[1:1+nbLimbs])
		decompose(y.BigInt(&yBig), nbLimbs, outputs[1+nbLimbs:1+2*nbLimbs])
		decompose(z.BigInt(&zBig), nbLimbs, outputs[1+2*nbLimbs:1+3*nbLimbs])
		return nil
	}
	return fmt.Errorf("xIncrementHint: no valid k found for BN254 (s=%d)", s)
}

func nthRoot2SBN254(a *bn254fp.Element, s int) *bn254fp.Element {
	z := new(bn254fp.Element).Set(a)
	for i := 0; i < s; i++ {
		if z.Sqrt(z) == nil {
			return nil
		}
	}
	return z
}

func yIncrementBN254(nbLimbs int, msg *big.Int, outputs []*big.Int) error {
	var msgFp, bFp, tFp, yBase bn254fp.Element
	msgFp.SetBigInt(msg)
	bFp.SetUint64(3)
	tFp.SetUint64(T)
	yBase.Mul(&msgFp, &tFp)

	for k := uint64(0); k < T; k++ {
		var kFp, y, y2, rhs, x bn254fp.Element
		kFp.SetUint64(k)
		y.Add(&yBase, &kFp)

		y2.Square(&y)
		rhs.Sub(&y2, &bFp)

		if x.Cbrt(&rhs) == nil {
			continue
		}

		var xBig big.Int
		outputs[0].SetUint64(k)
		decompose(x.BigInt(&xBig), nbLimbs, outputs[1:1+nbLimbs])
		return nil
	}
	return fmt.Errorf("yIncrementHint: no valid k found for BN254")
}

// --- secp256k1 (y² = x³ + 7, a=0, S=1) ---

// secp256k1: y² = x³ + 7, S=1
func xIncrementSecp256k1(nbLimbs int, msg *big.Int, outputs []*big.Int) error {
	const s = 1
	var msgFp, bFp, tFp, xBase secp256k1fp.Element
	msgFp.SetBigInt(msg)
	bFp.SetUint64(7)
	tFp.SetUint64(T)
	xBase.Mul(&msgFp, &tFp)

	for k := uint64(0); k < T; k++ {
		var kFp, x, x2, rhs, y secp256k1fp.Element
		kFp.SetUint64(k)
		x.Add(&xBase, &kFp)

		x2.Square(&x)
		rhs.Mul(&x2, &x)
		rhs.Add(&rhs, &bFp)

		if y.Sqrt(&rhs) == nil {
			continue
		}

		z := nthRoot2SSecp256k1(&y, s)
		if z == nil {
			y.Neg(&y)
			z = nthRoot2SSecp256k1(&y, s)
			if z == nil {
				continue
			}
		}

		var xBig, yBig, zBig big.Int
		outputs[0].SetUint64(k)
		decompose(x.BigInt(&xBig), nbLimbs, outputs[1:1+nbLimbs])
		decompose(y.BigInt(&yBig), nbLimbs, outputs[1+nbLimbs:1+2*nbLimbs])
		decompose(z.BigInt(&zBig), nbLimbs, outputs[1+2*nbLimbs:1+3*nbLimbs])
		return nil
	}
	return fmt.Errorf("xIncrementHint: no valid k found for secp256k1 (s=%d)", s)
}

func nthRoot2SSecp256k1(a *secp256k1fp.Element, s int) *secp256k1fp.Element {
	z := new(secp256k1fp.Element).Set(a)
	for i := 0; i < s; i++ {
		if z.Sqrt(z) == nil {
			return nil
		}
	}
	return z
}

func yIncrementSecp256k1(nbLimbs int, msg *big.Int, outputs []*big.Int) error {
	var msgFp, bFp, tFp, yBase secp256k1fp.Element
	msgFp.SetBigInt(msg)
	bFp.SetUint64(7)
	tFp.SetUint64(T)
	yBase.Mul(&msgFp, &tFp)

	for k := uint64(0); k < T; k++ {
		var kFp, y, y2, rhs, x secp256k1fp.Element
		kFp.SetUint64(k)
		y.Add(&yBase, &kFp)

		y2.Square(&y)
		rhs.Sub(&y2, &bFp)

		if x.Cbrt(&rhs) == nil {
			continue
		}

		var xBig big.Int
		outputs[0].SetUint64(k)
		decompose(x.BigInt(&xBig), nbLimbs, outputs[1:1+nbLimbs])
		return nil
	}
	return fmt.Errorf("yIncrementHint: no valid k found for secp256k1")
}

// --- secp256r1 / P-256 (y² = x³ + ax + b, a≠0, S=1) ---

// secp256r1 / P-256: y² = x³ - 3x + b, S=1
func xIncrementSecp256r1(nbLimbs int, msg *big.Int, outputs []*big.Int) error {
	const s = 1
	// a = -3 mod q, b from curve params
	p := sw_emulated.GetP256Params()
	var msgFp, aFp, bFp, tFp, xBase secp256r1fp.Element
	msgFp.SetBigInt(msg)
	aFp.SetBigInt(p.A)
	bFp.SetBigInt(p.B)
	tFp.SetUint64(T)
	xBase.Mul(&msgFp, &tFp)

	for k := uint64(0); k < T; k++ {
		var kFp, x, x2, rhs, y secp256r1fp.Element
		kFp.SetUint64(k)
		x.Add(&xBase, &kFp)

		// rhs = x³ + a·x + b
		x2.Square(&x)
		rhs.Mul(&x2, &x)
		var ax secp256r1fp.Element
		ax.Mul(&aFp, &x)
		rhs.Add(&rhs, &ax)
		rhs.Add(&rhs, &bFp)

		if y.Sqrt(&rhs) == nil {
			continue
		}

		z := nthRoot2SSecp256r1(&y, s)
		if z == nil {
			y.Neg(&y)
			z = nthRoot2SSecp256r1(&y, s)
			if z == nil {
				continue
			}
		}

		var xBig, yBig, zBig big.Int
		outputs[0].SetUint64(k)
		decompose(x.BigInt(&xBig), nbLimbs, outputs[1:1+nbLimbs])
		decompose(y.BigInt(&yBig), nbLimbs, outputs[1+nbLimbs:1+2*nbLimbs])
		decompose(z.BigInt(&zBig), nbLimbs, outputs[1+2*nbLimbs:1+3*nbLimbs])
		return nil
	}
	return fmt.Errorf("xIncrementHint: no valid k found for secp256r1 (s=%d)", s)
}

func nthRoot2SSecp256r1(a *secp256r1fp.Element, s int) *secp256r1fp.Element {
	z := new(secp256r1fp.Element).Set(a)
	for i := 0; i < s; i++ {
		if z.Sqrt(z) == nil {
			return nil
		}
	}
	return z
}

// secp256r1 / P-256: y² = x³ − 3x + b, y-increment uses Cardano solver.
func yIncrementSecp256r1(nbLimbs int, msg *big.Int, outputs []*big.Int) error {
	p := sw_emulated.GetP256Params()
	var bFp, tFp, msgFp, yBase secp256r1fp.Element
	msgFp.SetBigInt(msg)
	bFp.SetBigInt(p.B)
	tFp.SetUint64(T)
	yBase.Mul(&msgFp, &tFp)

	for k := uint64(0); k < T; k++ {
		var kFp, y, y2, c secp256r1fp.Element
		kFp.SetUint64(k)
		y.Add(&yBase, &kFp)

		// x³ − 3x + c = 0 where c = b − y²
		y2.Square(&y)
		c.Sub(&bFp, &y2)

		roots := cardanoRootsP256(c)
		if len(roots) == 0 {
			continue
		}

		var xBig big.Int
		outputs[0].SetUint64(k)
		decompose(roots[0].BigInt(&xBig), nbLimbs, outputs[1:1+nbLimbs])
		return nil
	}
	return fmt.Errorf("yIncrementHint: no valid k found for secp256r1")
}

// --- limb helpers ---

// recompose reconstructs a big.Int from its limbs (little-endian, 64-bit each).
func recompose(limbs []*big.Int, nbLimbs int) *big.Int {
	result := new(big.Int)
	for i := nbLimbs - 1; i >= 0; i-- {
		result.Lsh(result, 64)
		result.Add(result, limbs[i])
	}
	return result
}

// decompose splits v into nbLimbs 64-bit limbs (little-endian).
func decompose(v *big.Int, nbLimbs int, outputs []*big.Int) {
	mask := new(big.Int).SetUint64(^uint64(0))
	tmp := new(big.Int).Set(v)
	for i := 0; i < nbLimbs; i++ {
		outputs[i].And(tmp, mask)
		tmp.Rsh(tmp, 64)
	}
}
