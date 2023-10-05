package fields_bw6761

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fp"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

type e6Add struct {
	A, B, C E6
}

func (circuit *e6Add) Define(api frontend.API) error {
	var expected E6
	nfield, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		panic(err)
	}
	e := NewExt6(nfield)
	expected = *e.Add(&circuit.A, &circuit.B)
	e.AssertIsEqual(&expected, &circuit.C)
	return nil
}

func TestAddFp6(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b, c bw6761.E6
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Add(&a, &b)

	witness := e6Add{
		A: FromE6(&a),
		B: FromE6(&b),
		C: FromE6(&c),
	}

	err := test.IsSolved(&e6Add{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e6Sub struct {
	A, B, C E6
}

func (circuit *e6Sub) Define(api frontend.API) error {
	var expected E6
	nfield, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		panic(err)
	}
	e := NewExt6(nfield)
	expected = *e.Sub(&circuit.A, &circuit.B)
	e.AssertIsEqual(&expected, &circuit.C)
	return nil
}

func TestSubFp6(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b, c bw6761.E6
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Sub(&a, &b)

	witness := e6Sub{
		A: FromE6(&a),
		B: FromE6(&b),
		C: FromE6(&c),
	}

	err := test.IsSolved(&e6Sub{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e6Double struct {
	A, B E6
}

func (circuit *e6Double) Define(api frontend.API) error {
	var expected E6
	nfield, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		panic(err)
	}
	e := NewExt6(nfield)
	expected = *e.Double(&circuit.A)
	e.AssertIsEqual(&expected, &circuit.B)
	return nil
}

func TestDoubleFp6(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b bw6761.E6
	_, _ = a.SetRandom()
	b.Double(&a)

	witness := e6Double{
		A: FromE6(&a),
		B: FromE6(&b),
	}

	err := test.IsSolved(&e6Double{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e6Mul struct {
	A, B, C E6
}

func (circuit *e6Mul) Define(api frontend.API) error {
	var expected E6
	nfield, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		panic(err)
	}
	e := NewExt6(nfield)
	expected = *e.Mul(&circuit.A, &circuit.B)
	e.AssertIsEqual(&expected, &circuit.C)
	return nil
}

func TestMulFp6(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b, c bw6761.E6
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Mul(&a, &b)

	witness := e6Mul{
		A: FromE6(&a),
		B: FromE6(&b),
		C: FromE6(&c),
	}

	// add=72955 equals=1098 fromBinary=0 mul=71442 sub=1049 toBinary=0
	// counters add=34695 equals=582 fromBinary=0 mul=32806 sub=903 toBinary=0
	err := test.IsSolved(&e6Mul{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e6Square struct {
	A, B E6
}

func (circuit *e6Square) Define(api frontend.API) error {
	var expected E6
	nfield, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		panic(err)
	}
	e := NewExt6(nfield)
	expected = *e.Square(&circuit.A)
	e.AssertIsEqual(&expected, &circuit.B)
	return nil
}

func TestSquareFp6(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b bw6761.E6
	_, _ = a.SetRandom()
	b.Square(&a)

	witness := e6Square{
		A: FromE6(&a),
		B: FromE6(&b),
	}

	// add=51966 equals=768 fromBinary=0 mul=50706 sub=780 toBinary=0
	// add=29636 equals=456 fromBinary=0 mul=28014 sub=686 toBinary=0
	err := test.IsSolved(&e6Square{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e6Inverse struct {
	A, B E6
}

func (circuit *e6Inverse) Define(api frontend.API) error {
	var expected E6
	nfield, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		panic(err)
	}
	e := NewExt6(nfield)
	expected = *e.Inverse(&circuit.A)
	e.AssertIsEqual(&expected, &circuit.B)
	return nil
}

func TestInverseFp6(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b bw6761.E6
	_, _ = a.SetRandom()
	b.Inverse(&a)

	witness := e6Inverse{
		A: FromE6(&a),
		B: FromE6(&b),
	}

	// add=136669 equals=2033 fromBinary=0 mul=134924 sub=1691 toBinary=0
	// add=114515 equals=1721 fromBinary=0 mul=112628 sub=1617 toBinary=0
	err := test.IsSolved(&e6Inverse{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e6Conjugate struct {
	A, B E6
}

func (circuit *e6Conjugate) Define(api frontend.API) error {
	var expected E6
	nfield, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		panic(err)
	}
	e := NewExt6(nfield)
	expected = *e.Conjugate(&circuit.A)
	e.AssertIsEqual(&expected, &circuit.B)
	return nil
}

func TestConjugateFp6(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b bw6761.E6
	_, _ = a.SetRandom()
	b.Conjugate(&a)

	witness := e6Conjugate{
		A: FromE6(&a),
		B: FromE6(&b),
	}

	// add=7095 equals=108 fromBinary=0 mul=6990 sub=165 toBinary=0
	err := test.IsSolved(&e6Conjugate{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e6CyclotomicSquareCompressed struct {
	A, B E6
}

func (circuit *e6CyclotomicSquareCompressed) Define(api frontend.API) error {
	nfield, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		panic(err)
	}
	e := NewExt6(nfield)
	expected := e.CyclotomicSquareCompressed(&circuit.A)
	e.AssertIsEqual(expected, &circuit.B)
	return nil
}

func TestCyclotomicSquareCompressedFp6(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b bw6761.E6
	_, _ = a.SetRandom()
	b.Set(&a)
	b.CyclotomicSquareCompressed(&a)

	witness := e6CyclotomicSquareCompressed{
		A: FromE6(&a),
		B: FromE6(&b),
	}

	// add=28975 equals=438 fromBinary=0 mul=28342 sub=401 toBinary=0
	// add=19987 equals=298 fromBinary=0 mul=19064 sub=339 toBinary=0
	err := test.IsSolved(&e6CyclotomicSquareCompressed{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e6DecompressKarabina struct {
	A, B E6
}

func (circuit *e6DecompressKarabina) Define(api frontend.API) error {
	nfield, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		panic(err)
	}
	e := NewExt6(nfield)
	expected := e.DecompressKarabina(&circuit.A)
	e.AssertIsEqual(expected, &circuit.B)
	return nil
}

func TestDecompressKarabinaFp6(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b bw6761.E6
	_, _ = a.SetRandom()
	b.Set(&a)
	a.DecompressKarabina(&a)

	witness := e6DecompressKarabina{
		A: FromE6(&b),
		B: FromE6(&a),
	}

	// add=28723 equals=438 fromBinary=0 mul=28342 sub=389 toBinary=0
	// add=17214 equals=284 fromBinary=0 mul=16709 sub=289 toBinary=0
	err := test.IsSolved(&e6DecompressKarabina{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e6CyclotomicSquare struct {
	A, B E6
}

func (circuit *e6CyclotomicSquare) Define(api frontend.API) error {
	nfield, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		panic(err)
	}
	e := NewExt6(nfield)
	expected := e.CyclotomicSquare(&circuit.A)
	e.AssertIsEqual(expected, &circuit.B)
	return nil
}

func TestCyclotomicSquareFp6(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b bw6761.E6
	_, _ = a.SetRandom()
	b.Set(&a)
	b.CyclotomicSquare(&a)

	witness := e6CyclotomicSquare{
		A: FromE6(&a),
		B: FromE6(&b),
	}

	// add=39871 equals=603 fromBinary=0 mul=39018 sub=563 toBinary=0
	// add=26229 equals=393 fromBinary=0 mul=24991 sub=495 toBinary=0
	err := test.IsSolved(&e6CyclotomicSquare{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

/*
func TestNewE6(t *testing.T) {
	a, _ := new(big.Int).SetString("83175370704474795125412693555818269399912070346366058924020987848926901443521059146219467322598189008118890021654143123310841437365188932207798122475953021372633091598654279100089387195482601214045864119525747542050698192923485116081505909964897146420", 10)
	b, _ := new(big.Int).SetString("6368022403585149186567793239866157016295592880888573809019876686976707722559034074218497709896494419772477540172749411175273320318562448286368763367020957539305330983642372720448125982288656809793421178887827471755589212191192898758939906986677524020", 10)
	aMod := new(big.Int).Mod(a, fp.Modulus())
	bMod := new(big.Int).Mod(b, fp.Modulus())
	fmt.Println(aMod.String() == bMod.String())
	fmt.Println(a.BitLen())

}

func TestKp(t *testing.T) {
	k, _ := new(big.Int).SetString("85056971769626083370706587971739925665000858406518962290778652625791906552342223597311466786558418076119513109067357166262376397813915389059478465293248265362213566556434506971085077824793753991611718645003559647894773349413422987352", 10)
	kp := new(big.Int).Mul(k, fp.Modulus())
	fmt.Println(kp.String())
}

func TestCreateLimbs(t *testing.T) {
	nbBits := 70
	input := big.NewInt(48)
	size := input.BitLen() / nbBits
	res := make([]*big.Int, size+1)
	for i := 0; i < size+1; i++ {
		res[i] = new(big.Int)
	}
	base := new(big.Int).Lsh(big.NewInt(1), uint(nbBits))
	fmt.Println("base:", base.String())
	r, _ := new(big.Int).SetString("21888242871839275222246405745257275088459989201842526013704146201830519410949", 10)
	fmt.Println(new(big.Int).Sub(ecc.BN254.ScalarField(), r).String())
	tmp := new(big.Int).Set(input)
	for i := 0; i < len(res); i++ {
		res[i].Mod(tmp, base)
		tmp.Rsh(tmp, uint(nbBits))
	}
	var buf bytes.Buffer
	for i := 0; i < size+1; i++ {
		buf.WriteString(res[i].String())
		if i != size {
			buf.WriteString("+")
		}
	}
	fmt.Println(buf.String())
}

type e6Expt struct {
	A, B E6
}

func (circuit *e6Expt) Define(api frontend.API) error {
	nfield, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		panic(err)
	}
	e := NewExt6(nfield)
	expected := e.Expt(&circuit.A)
	e.AssertIsEqual(expected, &circuit.B)
	return nil
}

func TestExptFp6(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b bw6761.E6
	_, _ = a.SetRandom()
	b.Set(&a)
	b.Expt(&a)

	witness := e6Expt{
		A: FromE6(&a),
		B: FromE6(&b),
	}

	err := test.IsSolved(&e6Expt{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e6Expc2 struct {
	A, B E6
}

func (circuit *e6Expc2) Define(api frontend.API) error {
	nfield, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		panic(err)
	}
	e := NewExt6(nfield)
	expected := e.Expc2(&circuit.A)
	e.AssertIsEqual(expected, &circuit.B)
	return nil
}

func TestExpc2Fp6(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b bw6761.E6
	_, _ = a.SetRandom()
	b.Set(&a)
	b.Expc2(&a)

	witness := e6Expc2{
		A: FromE6(&a),
		B: FromE6(&b),
	}

	// add=287618 equals=4068 fromBinary=0 mul=281540 sub=3690 toBinary=0
	// add=197836 equals=3048 fromBinary=0 mul=188488 sub=3810 toBinary=0
	err := test.IsSolved(&e6Expc2{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e6Expc1 struct {
	A, B E6
}

func (circuit *e6Expc1) Define(api frontend.API) error {
	nfield, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		panic(err)
	}
	e := NewExt6(nfield)
	expected := e.Expc1(&circuit.A)
	e.AssertIsEqual(expected, &circuit.B)
	return nil
}

func TestExpc1Fp6(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b bw6761.E6
	_, _ = a.SetRandom()
	b.Set(&a)
	b.Expc1(&a)

	witness := e6Expc1{
		A: FromE6(&a),
		B: FromE6(&b),
	}

	// add=578954 equals=8028 fromBinary=0 mul=566870 sub=7248 toBinary=0
	err := test.IsSolved(&e6Expc1{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}
*/

type e6MulBy014 struct {
	A    E6 `gnark:",public"`
	W    E6
	B, C baseEl
}

func (circuit *e6MulBy014) Define(api frontend.API) error {
	nfield, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		panic(err)
	}
	e := NewExt6(nfield)
	res := e.MulBy014(&circuit.A, &circuit.B, &circuit.C)
	e.AssertIsEqual(res, &circuit.W)
	return nil
}

func TestFp12MulBy014(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, w bw6761.E6
	_, _ = a.SetRandom()
	var one, b, c fp.Element
	one.SetOne()
	_, _ = b.SetRandom()
	_, _ = c.SetRandom()
	w.Set(&a)
	w.MulBy014(&b, &c, &one)

	witness := e6MulBy014{
		A: FromE6(&a),
		B: emulated.ValueOf[emulated.BW6761Fp](&b),
		C: emulated.ValueOf[emulated.BW6761Fp](&c),
		W: FromE6(&w),
	}

	err := test.IsSolved(&e6MulBy014{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}
