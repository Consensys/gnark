package fields_bw6761

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fp"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

type e6Add struct {
	A, B, C E6
}

func (circuit *e6Add) Define(api frontend.API) error {
	var expected E6
	e := NewExt6(api)
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
	e := NewExt6(api)
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
	e := NewExt6(api)
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

type e6MulVariants struct {
	A, B, C E6
}

func (circuit *e6MulVariants) Define(api frontend.API) error {
	e := NewExt6(api)
	expected1 := *e.mulMontgomery6(&circuit.A, &circuit.B)
	expected2 := *e.mulToomCook6(&circuit.A, &circuit.B)
	expected3 := *e.mulDirect(&circuit.A, &circuit.B)
	e.AssertIsEqual(&expected1, &circuit.C)
	e.AssertIsEqual(&expected2, &circuit.C)
	e.AssertIsEqual(&expected3, &circuit.C)
	return nil
}

func TestMulVariantsFp6(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b, c bw6761.E6
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Mul(&a, &b)

	witness := e6MulVariants{
		A: FromE6(&a),
		B: FromE6(&b),
		C: FromE6(&c),
	}

	err := test.IsSolved(&e6MulVariants{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e6DirectMul struct {
	A, B, C E6
}

func (circuit *e6DirectMul) Define(api frontend.API) error {
	e := NewExt6(api)
	expected := e.mulDirect(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestDirectMulFp6(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b, c bw6761.E6
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Mul(&a, &b)

	witness := e6DirectMul{
		A: FromE6(&a),
		B: FromE6(&b),
		C: FromE6(&c),
	}
	err := test.IsSolved(&e6DirectMul{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
	_, err = frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &e6DirectMul{})
	assert.NoError(err)
}

type e6Mul struct {
	A, B, C E6
}

func (circuit *e6Mul) Define(api frontend.API) error {
	// var expected E6
	e := NewExt6(api)
	expected := e.Mul(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)
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

	err := test.IsSolved(&e6Mul{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e6Square struct {
	A, B E6
}

func (circuit *e6Square) Define(api frontend.API) error {
	var expected E6
	e := NewExt6(api)
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

	err := test.IsSolved(&e6Square{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e6Inverse struct {
	A, B E6
}

func (circuit *e6Inverse) Define(api frontend.API) error {
	var expected E6
	e := NewExt6(api)
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

	err := test.IsSolved(&e6Inverse{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e6Div struct {
	A, B, C E6
}

func (circuit *e6Div) Define(api frontend.API) error {
	e := NewExt6(api)
	expected := e.DivUnchecked(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestDivFp6(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, b, c bw6761.E6
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Inverse(&b)
	c.Mul(&a, &c)

	witness := e6Div{
		A: FromE6(&a),
		B: FromE6(&b),
		C: FromE6(&c),
	}

	err := test.IsSolved(&e6Div{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e6Conjugate struct {
	A, B E6
}

func (circuit *e6Conjugate) Define(api frontend.API) error {
	var expected E6
	e := NewExt6(api)
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

	err := test.IsSolved(&e6Conjugate{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e6Expt struct {
	A, B E6
}

func (circuit *e6Expt) Define(api frontend.API) error {
	e := NewExt6(api)
	expected := e.ExpX0Minus1(&circuit.A)
	expected = e.Mul(expected, &circuit.A)
	e.AssertIsEqual(expected, &circuit.B)
	return nil
}

func TestExptFp6(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b bw6761.E6
	_, _ = a.SetRandom()

	// put a in the cyclotomic subgroup
	var tmp bw6761.E6
	tmp.Conjugate(&a)
	a.Inverse(&a)
	tmp.Mul(&tmp, &a)
	a.Frobenius(&tmp).Mul(&a, &tmp)

	b.Expt(&a)

	witness := e6Expt{
		A: FromE6(&a),
		B: FromE6(&b),
	}

	err := test.IsSolved(&e6Expt{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e6MulBy023 struct {
	A    E6 `gnark:",public"`
	W    E6
	B, C baseEl
}

func (circuit *e6MulBy023) Define(api frontend.API) error {
	e := NewExt6(api)
	res := e.MulBy023(&circuit.A, &circuit.B, &circuit.C)
	e.AssertIsEqual(res, &circuit.W)
	return nil
}

func TestFp6MulBy023(t *testing.T) {

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

	witness := e6MulBy023{
		A: FromE6(&a),
		B: emulated.ValueOf[emulated.BW6761Fp](&b),
		C: emulated.ValueOf[emulated.BW6761Fp](&c),
		W: FromE6(&w),
	}

	err := test.IsSolved(&e6MulBy023{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestMulWithQuo(t *testing.T) {
	in1 := make([]*big.Int, 6)
	in2 := make([]*big.Int, 6)

	in1[0], _ = new(big.Int).SetString("566085406183132089557503598725938322183146607631137194894951503971844712333908903364598453726764741395129364197718789361865548348607413224208396942770785701035038644184249117742293688903350169921147165236556080675385313401012453", 10)
	in1[1], _ = new(big.Int).SetString("2788753545139860057523322509308877283588307881046532119901533324213496227432276621571824675073230986003252007545730596413224713555894255466547970746733011358142541305765475857177633114248882057311343059278795257178544692469630281", 10)
	in1[2], _ = new(big.Int).SetString("1775806754966672346431495387222794399735489409809061739538890414984935869768610831626375384190933506223545794960775162940031726835064935742409733541635148007785675795815339997054268719953066974950169891236844458173574198541471770", 10)
	in1[3], _ = new(big.Int).SetString("5212601374858097626606100878536626321378608849050427704146851149654730757408169919693191932792579047430914767609854113743254087770010547859900903422527839536894481512249424516963063423461999885844657979961135118025539856836253354", 10)
	in1[4], _ = new(big.Int).SetString("665344901351478376215020735172079544165780542305517359021445995018356890240202432944335116305623671144614495580631611250277301858012370801222048746177483957080655576103579564715981840966287946886239117588578860293506296120018947", 10)
	in1[5], _ = new(big.Int).SetString("1410875319266774125507627943721191544240314688472999286289690377654832939229434829622750787094528385492578835550526325808293358342270622138171737596331387225515619151685055082950783510276243167226513915092887806096880817306639483", 10)

	in2[0], _ = new(big.Int).SetString("5063473459964710004570475172470591854883242626905665656682091284606164310683254846056091229451211638803942627064950205426900202067421863538821864826412684573822636157497665959671699453477987163225582917422673172808804271388412296", 10)
	in2[1], _ = new(big.Int).SetString("588420887982896009853588520003688427908670653135585074737062217996073286109498924969302507932432521128864620350558149926724893823872599150898513473602307671560865809342954960234944980588455203086007132373358363551626357432381394", 10)
	in2[2], _ = new(big.Int).SetString("6659858016531861424732037239302634334030418453698998007601700250388976859208732667349770276110137335773812572952332019315921399453946333830673501362204942257643867136151198300260033241755184207729416331366135169223179042081872857", 10)
	in2[3], _ = new(big.Int).SetString("5822617395049025035554122758309721255813445574763332843817089794314758986505421096747209728005953543652339117535642095390006877604667336403390004194036275612229499699333524046970804955338381736669887519585816181180817394024588585", 10)
	in2[4], _ = new(big.Int).SetString("2150807816068314192369308280290265709228617045282408587771028938810782163635831588332221977593750730009895617180453198932476622310174138179211369083168666538695387712730488839977153362704721337337850757856407182928781068030213872", 10)
	in2[5], _ = new(big.Int).SetString("6783396817137818694944221750178294054330346593321330734160719755618435258064499729186045023284091460313786060519868761818384814697519177278965016718897028457366792177931297532462902904157980197783367072913012238250965780862209144", 10)

	var A, B bw6761.E6
	A.SetRandom()
	B.SetRandom()

	A.B0.A0.SetBigInt(in1[0])
	A.B1.A0.SetBigInt(in1[1])
	A.B0.A1.SetBigInt(in1[2])
	A.B1.A1.SetBigInt(in1[3])
	A.B0.A2.SetBigInt(in1[4])
	A.B1.A2.SetBigInt(in1[5])

	B.B0.A0.SetBigInt(in2[0])
	B.B1.A0.SetBigInt(in2[1])
	B.B0.A1.SetBigInt(in2[2])
	B.B1.A1.SetBigInt(in2[3])
	B.B0.A2.SetBigInt(in2[4])
	B.B1.A2.SetBigInt(in2[5])

	mulWithQuotient(in1, in2)
}

type e6SquareRand struct {
	A, B E6
}

func (circuit *e6SquareRand) Define(api frontend.API) error {
	var expected E6
	e := NewExt6(api)
	expected = *e.squarePolyWithRand(&circuit.A, e.fp.One())
	e.AssertIsEqual(&expected, &circuit.B)
	return nil
}

func TestSquareRandFp6(t *testing.T) {
	assert := test.NewAssert(t)
	in1 := make([]*big.Int, 6)

	in1[0], _ = new(big.Int).SetString("566085406183132089557503598725938322183146607631137194894951503971844712333908903364598453726764741395129364197718789361865548348607413224208396942770785701035038644184249117742293688903350169921147165236556080675385313401012453", 10)
	in1[1], _ = new(big.Int).SetString("2788753545139860057523322509308877283588307881046532119901533324213496227432276621571824675073230986003252007545730596413224713555894255466547970746733011358142541305765475857177633114248882057311343059278795257178544692469630281", 10)
	in1[2], _ = new(big.Int).SetString("1775806754966672346431495387222794399735489409809061739538890414984935869768610831626375384190933506223545794960775162940031726835064935742409733541635148007785675795815339997054268719953066974950169891236844458173574198541471770", 10)
	in1[3], _ = new(big.Int).SetString("5212601374858097626606100878536626321378608849050427704146851149654730757408169919693191932792579047430914767609854113743254087770010547859900903422527839536894481512249424516963063423461999885844657979961135118025539856836253354", 10)
	in1[4], _ = new(big.Int).SetString("665344901351478376215020735172079544165780542305517359021445995018356890240202432944335116305623671144614495580631611250277301858012370801222048746177483957080655576103579564715981840966287946886239117588578860293506296120018947", 10)
	in1[5], _ = new(big.Int).SetString("1410875319266774125507627943721191544240314688472999286289690377654832939229434829622750787094528385492578835550526325808293358342270622138171737596331387225515619151685055082950783510276243167226513915092887806096880817306639483", 10)

	var A, B bw6761.E6

	A.B0.A0.SetBigInt(in1[0])
	A.B1.A0.SetBigInt(in1[1])
	A.B0.A1.SetBigInt(in1[2])
	A.B1.A1.SetBigInt(in1[3])
	A.B0.A2.SetBigInt(in1[4])
	A.B1.A2.SetBigInt(in1[5])
	B.Square(&A)

	// fmt.Println(B.B0.A0.String())
	// fmt.Println(B.B1.A0.String())
	// fmt.Println(B.B0.A1.String())
	// fmt.Println(B.B1.A1.String())
	// fmt.Println(B.B0.A2.String())
	// fmt.Println(B.B1.A2.String())
	// // witness values
	// var a, b bw6761.E6
	// _, _ = a.SetRandom()
	// b.Square(&a)

	witness := e6SquareRand{
		A: FromE6(&A),
		B: FromE6(&B),
	}

	err := test.IsSolved(&e6SquareRand{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}
