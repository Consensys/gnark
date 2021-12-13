package tower

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/tower/fp12"
	"github.com/consensys/gnark/std/algebra/tower/fp2"
	"github.com/consensys/gnark/std/algebra/tower/fp24"
)

type Basis interface {
	fp2.E2 | fp24.E4
}

type BasisPt[T Basis] interface {
	*T
	Neg(T) *T
	Sub(T, T) *T
	Inverse(T) *T
	Square(T) *T
	Mul(T, T) *T
	MulByFp(T, interface{}) *T
	MustBeEqual(T)
	Double(T) *T
	Add(T, T) *T
	Set(T)
	SetAPI(frontend.API) // make zero
}

type Tower interface {
	fp12.E12 | fp24.E24
}

type TowerPt[T Tower, B Basis] interface {
	*T
	Add(e1 T, e2 T) *T
	Conjugate(e1 T) *T
	CyclotomicSquare(x T) *T
	CyclotomicSquareCompressed(x T) *T
	Decompress(x T) *T
	Expt(e1 T, exponent uint64) *T
	FinalExponentiation(e1 T, genT uint64) *T
	Frobenius(e1 T) *T
	//FrobeniusCube(e1 T) *T
	//FrobeniusSquare(e1 T) *T
	Inverse(e1 T) *T
	Mul(e1, e2 T) *T
	MulBy034(c3, c4 B) *T
	MustBeEqual(other T)
	Neg(e1 T) *T
	//Select(b frontend.Variable, r1, r2 T) *T
	SetOne() *T
	Square(x T) *T
	Sub(e1, e2 T) *T
	SetAPI(api frontend.API) // make zero
	Set(T)
}
