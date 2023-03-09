package lazy

import (
	"github.com/consensys/gnark/constraint"
	"strconv"
)

func init() {
	err := RegisterPoseidonFactory()
	if err != nil {
		panic(err)
	}
}

func GetLazyPoseidonKey(params int) string {
	return "poseidon-params-" + strconv.Itoa(params)
}

func RegisterPoseidonFactory() error {
	for i := 3; i <= 13; i++ {
		key := GetLazyPoseidonKey(i)
		constraint.Register(key, createGeneralLazyInputsFunc(key))
	}
	return nil
}
