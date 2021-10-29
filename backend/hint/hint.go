package hint

import (
	"errors"
	"hash/fnv"
	"math/big"
	"reflect"
	"runtime"

	"github.com/consensys/gnark-crypto/ecc"
)

type ID uint32

type Function func(curveID ecc.ID, inputs []*big.Int, result *big.Int) error

// UUID returns a unique ID for a hint function name
func UUID(f Function) ID {
	name := runtime.FuncForPC(reflect.ValueOf(f).Pointer()).Name()
	h := fnv.New32a()
	_, _ = h.Write([]byte(name))
	return ID(h.Sum32())
}

// IthBit expects len(inputs) == 2
// inputs[0] == a
// inputs[1] == n
// returns bit number n of a
func IthBit(_ ecc.ID, inputs []*big.Int, result *big.Int) error {
	if len(inputs) != 2 {
		return errors.New("ithBit expects 2 inputs; inputs[0] == value, inputs[1] == bit position")
	}
	if !inputs[1].IsUint64() {
		result.SetUint64(0)
		return nil
	}

	result.SetUint64(uint64(inputs[0].Bit(int(inputs[1].Uint64()))))
	return nil
}

// IsZero expects len(inputs) == 1
// inputs[0] == a
// returns m = 1 - a^(modulus-1)
func IsZero(curveID ecc.ID, inputs []*big.Int, result *big.Int) error {
	if len(inputs) != 1 {
		return errors.New("IsZero expects one input")
	}

	// get fr modulus
	q := curveID.Info().Fr.Modulus()

	// save input
	result.Set(inputs[0])

	// reuse input to compute q - 1
	qMinusOne := inputs[0].SetUint64(1)
	qMinusOne.Sub(q, qMinusOne)

	// result = input**(q-1) - 1
	result.Exp(result, qMinusOne, q)
	inputs[0].SetUint64(1)
	result.Sub(inputs[0], result).Mod(result, q)

	return nil
}
