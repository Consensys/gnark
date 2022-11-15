package std

import "math/big"

func Decompose(rawBytes []byte, modulos *big.Int) (decomposed []byte) {
	raw := big.NewInt(0).SetBytes(rawBytes)

	var chunk [32]byte
	decomposed = make([]byte, 0, len(rawBytes))
	for raw.Cmp(modulos) >= 0 {
		mod := big.NewInt(0).Mod(raw, modulos)
		mod.FillBytes(chunk[:])
		decomposed = append(decomposed, chunk[:]...)

		raw.Div(raw, modulos)
	}

	raw.FillBytes(chunk[:])
	decomposed = append(decomposed, chunk[:]...)
	return decomposed
}
