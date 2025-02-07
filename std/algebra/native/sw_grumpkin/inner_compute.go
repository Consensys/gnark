package sw_grumpkin

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/grumpkin"
)

func computeCurveTable() [][2]*big.Int {
	G1jac, _ := grumpkin.Generators()
	table := make([][2]*big.Int, 254)
	tmp := new(grumpkin.G1Jac).Set(&G1jac)
	aff := new(grumpkin.G1Affine)
	jac := new(grumpkin.G1Jac)
	for i := 1; i < 254; i++ {
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
