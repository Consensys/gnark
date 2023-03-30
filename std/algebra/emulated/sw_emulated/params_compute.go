package sw_emulated

import (
	"crypto/elliptic"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
)

func computeSecp256k1Table() [][2]*big.Int {
	Gjac, _ := secp256k1.Generators()
	table := make([][2]*big.Int, 256)
	tmp := new(secp256k1.G1Jac).Set(&Gjac)
	aff := new(secp256k1.G1Affine)
	jac := new(secp256k1.G1Jac)
	for i := 1; i < 256; i++ {
		tmp = tmp.Double(tmp)
		switch i {
		case 1, 2:
			jac.Set(tmp).AddAssign(&Gjac)
			aff.FromJacobian(jac)
			table[i-1] = [2]*big.Int{aff.X.BigInt(new(big.Int)), aff.Y.BigInt(new(big.Int))}
		case 3:
			jac.Set(tmp).SubAssign(&Gjac)
			aff.FromJacobian(jac)
			table[i-1] = [2]*big.Int{aff.X.BigInt(new(big.Int)), aff.Y.BigInt(new(big.Int))}
			fallthrough
		default:
			aff.FromJacobian(tmp)
			table[i] = [2]*big.Int{aff.X.BigInt(new(big.Int)), aff.Y.BigInt(new(big.Int))}
		}
	}
	return table[:]
}

func computeSecp256r1Table() [][2]*big.Int {
	curve := elliptic.P256()
	curveParams := curve.Params()
	table := make([][2]*big.Int, 256)
	tmpX := new(big.Int).Set(curveParams.Gx)
	tmpY := new(big.Int).Set(curveParams.Gy)
	// TODO pre compute here
	for i := 1; i < 256; i++ {
		tmpX, tmpY = curve.Double(tmpX, tmpY)
		if i == 1 {
			x, y := curve.ScalarBaseMult(big.NewInt(3).Bytes())
			table[i-1] = [2]*big.Int{x, y}
			continue
		} else if i == 2 {
			x, y := curve.ScalarBaseMult(big.NewInt(5).Bytes())
			table[i-1] = [2]*big.Int{x, y}
			continue
		} else if i == 3 {
			x, y := curve.ScalarBaseMult(big.NewInt(7).Bytes())
			table[i-1] = [2]*big.Int{x, y}
		}
		table[i] = [2]*big.Int{new(big.Int).Set(tmpX), new(big.Int).Set(tmpY)}
	}
	return table[:]
}

func computeBN254Table() [][2]*big.Int {
	Gjac, _, _, _ := bn254.Generators()
	table := make([][2]*big.Int, 256)
	tmp := new(bn254.G1Jac).Set(&Gjac)
	aff := new(bn254.G1Affine)
	jac := new(bn254.G1Jac)
	for i := 1; i < 256; i++ {
		tmp = tmp.Double(tmp)
		switch i {
		case 1, 2:
			jac.Set(tmp).AddAssign(&Gjac)
			aff.FromJacobian(jac)
			table[i-1] = [2]*big.Int{aff.X.BigInt(new(big.Int)), aff.Y.BigInt(new(big.Int))}
		case 3:
			jac.Set(tmp).SubAssign(&Gjac)
			aff.FromJacobian(jac)
			table[i-1] = [2]*big.Int{aff.X.BigInt(new(big.Int)), aff.Y.BigInt(new(big.Int))}
			fallthrough
		default:
			aff.FromJacobian(tmp)
			table[i] = [2]*big.Int{aff.X.BigInt(new(big.Int)), aff.Y.BigInt(new(big.Int))}
		}
	}
	return table
}
