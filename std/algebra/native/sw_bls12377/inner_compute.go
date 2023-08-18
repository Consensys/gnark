package sw_bls12377

import (
	"math/big"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
)

func computeCurveTable() [][2]*big.Int {
	G1jac, _, _, _ := bls12377.Generators()
	table := make([][2]*big.Int, 253)
	tmp := new(bls12377.G1Jac).Set(&G1jac)
	aff := new(bls12377.G1Affine)
	jac := new(bls12377.G1Jac)
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

func computeTwistTable() [][4]*big.Int {
	_, G2jac, _, _ := bls12377.Generators()
	table := make([][4]*big.Int, 253)
	tmp := new(bls12377.G2Jac).Set(&G2jac)
	aff := new(bls12377.G2Affine)
	jac := new(bls12377.G2Jac)
	for i := 1; i < 253; i++ {
		tmp = tmp.Double(tmp)
		switch i {
		case 1, 2:
			jac.Set(tmp).AddAssign(&G2jac)
			aff.FromJacobian(jac)
			table[i-1] = [4]*big.Int{aff.X.A0.BigInt(new(big.Int)), aff.X.A1.BigInt(new(big.Int)), aff.Y.A0.BigInt(new(big.Int)), aff.Y.A1.BigInt(new(big.Int))}
		case 3:
			jac.Set(tmp).SubAssign(&G2jac)
			aff.FromJacobian(jac)
			table[i-1] = [4]*big.Int{aff.X.A0.BigInt(new(big.Int)), aff.X.A1.BigInt(new(big.Int)), aff.Y.A0.BigInt(new(big.Int)), aff.Y.A1.BigInt(new(big.Int))}
			fallthrough
		default:
			aff.FromJacobian(tmp)
			table[i] = [4]*big.Int{aff.X.A0.BigInt(new(big.Int)), aff.X.A1.BigInt(new(big.Int)), aff.Y.A0.BigInt(new(big.Int)), aff.Y.A1.BigInt(new(big.Int))}
		}
	}
	return table[:]
}
