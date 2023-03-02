package sw_bls12377

import (
	"math/big"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
)

func computeBLS12377Table() [][2]*big.Int {
	Gjac, _, _, _ := bls12377.Generators()
	table := make([][2]*big.Int, 253)
	tmp := new(bls12377.G1Jac).Set(&Gjac)
	aff := new(bls12377.G1Affine)
	jac := new(bls12377.G1Jac)
	for i := 1; i < 253; i++ {
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
