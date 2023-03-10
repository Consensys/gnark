package sw_bls24315

import (
	"math/big"

	bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315"
)

func computeCurveTable() [][2]*big.Int {
	G1jac, _, _, _ := bls24315.Generators()
	table := make([][2]*big.Int, 253)
	tmp := new(bls24315.G1Jac).Set(&G1jac)
	aff := new(bls24315.G1Affine)
	jac := new(bls24315.G1Jac)
	for i := 1; i < 253; i++ {
		tmp = tmp.Double(tmp)
		switch i {
		case 1, 2:
			jac.Set(tmp).AddAssign(&G1jac)
			aff.FromJacobian(jac)
			table[i-1] = [2]*big.Int{aff.X.BigInt(new(big.Int)), aff.Y.BigInt(new(big.Int))}
		case 3:
			jac.Set(tmp).SubAssign(&G1jac)
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

func computeTwistTable() [][8]*big.Int {
	_, G2jac, _, _ := bls24315.Generators()
	table := make([][8]*big.Int, 253)
	tmp := new(bls24315.G2Jac).Set(&G2jac)
	aff := new(bls24315.G2Affine)
	jac := new(bls24315.G2Jac)
	for i := 1; i < 253; i++ {
		tmp = tmp.Double(tmp)
		switch i {
		case 1, 2:
			jac.Set(tmp).AddAssign(&G2jac)
			aff.FromJacobian(jac)
			table[i-1] = [8]*big.Int{aff.X.B0.A0.BigInt(new(big.Int)), aff.X.B0.A1.BigInt(new(big.Int)), aff.X.B1.A0.BigInt(new(big.Int)), aff.X.B1.A1.BigInt(new(big.Int)), aff.Y.B0.A0.BigInt(new(big.Int)), aff.Y.B0.A1.BigInt(new(big.Int)), aff.Y.B1.A0.BigInt(new(big.Int)), aff.Y.B1.A1.BigInt(new(big.Int))}
		case 3:
			jac.Set(tmp).SubAssign(&G2jac)
			aff.FromJacobian(jac)
			table[i-1] = [8]*big.Int{aff.X.B0.A0.BigInt(new(big.Int)), aff.X.B0.A1.BigInt(new(big.Int)), aff.X.B1.A0.BigInt(new(big.Int)), aff.X.B1.A1.BigInt(new(big.Int)), aff.Y.B0.A0.BigInt(new(big.Int)), aff.Y.B0.A1.BigInt(new(big.Int)), aff.Y.B1.A0.BigInt(new(big.Int)), aff.Y.B1.A1.BigInt(new(big.Int))}
			fallthrough
		default:
			aff.FromJacobian(tmp)
			table[i] = [8]*big.Int{aff.X.B0.A0.BigInt(new(big.Int)), aff.X.B0.A1.BigInt(new(big.Int)), aff.X.B1.A0.BigInt(new(big.Int)), aff.X.B1.A1.BigInt(new(big.Int)), aff.Y.B0.A0.BigInt(new(big.Int)), aff.Y.B0.A1.BigInt(new(big.Int)), aff.Y.B1.A0.BigInt(new(big.Int)), aff.Y.B1.A1.BigInt(new(big.Int))}
		}
	}
	return table[:]
}
