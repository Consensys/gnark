package sw_kb8

import (
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/std/algebra/native/fields_kb8"
)

func GetHints() []solver.Hint {
	return fields_kb8.GetHints()
}
