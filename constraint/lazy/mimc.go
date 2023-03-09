package lazy

import (
	"github.com/consensys/gnark/constraint"
	"strconv"
)

func init() {
	err := RegisterMimcPermutationFactory()
	if err != nil {
		panic(err)
	}
}

func GetLazyMimcPermutationKey(params int) string {
	return "mimc-params-" + strconv.Itoa(params)
}

func RegisterMimcPermutationFactory() error {
	for i := 3; i <= 13; i++ {
		key := GetLazyMimcPermutationKey(i)
		constraint.Register(key, createGeneralLazyInputsFunc(key))
	}
	return nil
}
