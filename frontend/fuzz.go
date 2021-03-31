// +build gofuzz

package frontend

import (
	"bytes"
	"fmt"
	"io"
	"math/big"
	"math/rand"

	"github.com/consensys/gnark-crypto/ecc"
	frbls377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	frbls381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	frbn256 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	frbw761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
)

func Fuzz(data []byte) int {

	curves := []ecc.ID{ecc.BN254, ecc.BLS12_381}
	for _, curveID := range curves {
		_, _ = CsFuzzed(data, curveID)
	}

	return 1
}

func CsFuzzed(data []byte, curveID ecc.ID) (ccs CompiledConstraintSystem, nbAssertions int) {
	cs := newConstraintSystem()
	reader := bytes.NewReader(data)

	for {
		b, err := reader.ReadByte()
		if err != nil {
			if err == io.EOF {
				goto compile
			}
			panic(fmt.Sprintf("reading byte from reader errored: %v", err))
		}
		if b&0b00000001 == 1 {
			cs.newPublicVariable()
		}
		if b&0b00000010 == 0b00000010 {
			cs.newSecretVariable()
		}
		if b&0b00000100 == 0b00000100 {
			// multiplication
			nbVariadic := int(b >> 4)
			v := cs.shuffleVariables(int64(b), true)
			if len(v) == 2 {
				cs.Mul(v[0], v[1])
			} else if len(v) > 2 {
				bound := 2 + nbVariadic
				if bound > len(v) {
					bound = len(v)
				}
				cs.Mul(v[0], v[1], v[2:bound]...)
			}
		}
		if b&0b00001000 == 0b00001000 {
			// addition
			nbVariadic := int(b >> 4)
			v := cs.shuffleVariables(int64(b), true)
			if len(v) == 2 {
				cs.Add(v[0], v[1])
			} else if len(v) > 2 {
				bound := 2 + nbVariadic
				if bound > len(v) {
					bound = len(v)
				}
				cs.Add(v[0], v[1], v[2:bound]...)
			}
		}
		if b&0b00010000 == 0b00010000 {
			// div
			v := cs.shuffleVariables(int64(b), true)
			if len(v) >= 2 {
				cs.Div(v[0], v[1])
			}

		}
		if b&0b00100000 == 0b00100000 {
			// inv
			vv := cs.shuffleVariables(int64(b), false)
			if len(vv) >= 1 {
				cs.Inverse(vv[0].(Variable))
			}
		}
		if b&0b01000000 == 0b01000000 {
			v := cs.shuffleVariables(int64(b), false)
			if len(v) >= 1 {
				vc := cs.shuffleVariables(int64(b), true)
				cs.AssertIsLessOrEqual(v[0].(Variable), vc[0])
				if len(vc) >= 2 {
					cs.AssertIsEqual(vc[0], vc[1])
				}
				if len(v) >= 2 {
					cs.AssertIsBoolean(v[1].(Variable))
				}
			}
		}

		if b&0b10000000 == 0b10000000 {
			v := cs.shuffleVariables(int64(b), false)
			if len(v) >= 2 {
				x1 := cs.Xor(v[0].(Variable), v[1].(Variable))
				x2 := cs.And(x1, v[0].(Variable))
				cs.Or(v[0].(Variable), v[1].(Variable))
				cs.Or(x1, x2)
			}
		}

		if b&0b00000011 == 0b00000011 {
			vc := cs.shuffleVariables(int64(b), true)
			if len(vc) >= 2 {
				cs.Println(vc[0], "and", vc[1])
			}
		}

	}
compile:
	ccs, err := cs.toR1CS(curveID)
	if err != nil {
		panic(fmt.Sprintf("compiling (curve %s) failed: %v", curveID.String(), err))
	}
	return ccs, len(cs.assertions)
}

func (cs *ConstraintSystem) shuffleVariables(seed int64, withConstant bool) []interface{} {
	var v []interface{}
	n := len(cs.public.variables) + len(cs.secret.variables) + len(cs.internal.variables)
	if withConstant {
		v = make([]interface{}, n*2+4*3)
	} else {
		v = make([]interface{}, n)
	}

	offset := 0
	for i := 0; i < len(cs.public.variables); i++ {
		v[i+offset] = cs.public.variables[i]
	}
	offset += len(cs.public.variables)
	for i := 0; i < len(cs.secret.variables); i++ {
		v[i+offset] = cs.secret.variables[i]
	}
	offset += len(cs.secret.variables)
	for i := 0; i < len(cs.internal.variables); i++ {
		v[i+offset] = cs.internal.variables[i]
	}
	offset += len(cs.internal.variables)

	if withConstant {
		// let's add some constants to the mix.
		for i := 0; i < n; i++ {
			v[i+offset] = i
		}
		offset += n
		v[offset] = frbls377.Modulus()
		v[offset+1] = frbls381.Modulus()
		v[offset+2] = frbn256.Modulus()
		v[offset+3] = frbw761.Modulus()
		v[offset+4] = new(big.Int).Sub(frbls377.Modulus(), new(big.Int).SetUint64(1))
		v[offset+5] = new(big.Int).Sub(frbls381.Modulus(), new(big.Int).SetUint64(1))
		v[offset+6] = new(big.Int).Sub(frbn256.Modulus(), new(big.Int).SetUint64(1))
		v[offset+7] = new(big.Int).Sub(frbw761.Modulus(), new(big.Int).SetUint64(1))
		v[offset+8] = new(big.Int).Add(frbls377.Modulus(), new(big.Int).SetUint64(1))
		v[offset+9] = new(big.Int).Add(frbls381.Modulus(), new(big.Int).SetUint64(1))
		v[offset+10] = new(big.Int).Add(frbn256.Modulus(), new(big.Int).SetUint64(1))
		v[offset+11] = new(big.Int).Add(frbw761.Modulus(), new(big.Int).SetUint64(1))
	}

	rand.Seed(seed)
	rand.Shuffle(len(v), func(i, j int) { v[i], v[j] = v[j], v[i] })

	return v
}
