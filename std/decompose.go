package std

import "math/big"

func Decompose(rawBytes []byte, modulos *big.Int) (decomposed []byte) {
	raw := big.NewInt(0).SetBytes(rawBytes)

	decomposed = make([]byte, 0, len(rawBytes))
	for raw.Cmp(modulos) >= 0 {
		mod := big.NewInt(0).Mod(raw, modulos)
		decomposed = append(decomposed, mod.Bytes()...)

		raw.Div(raw, modulos)
	}

	decomposed = append(decomposed, raw.Bytes()...)
	return decomposed
}
