package pairing_bn254

import (
	"math/big"

	"github.com/consensys/gnark/std/math/emulated"
)

type curveF = emulated.Field[emulated.BN254Fp]
type baseEl = emulated.Element[emulated.BN254Fp]

type e2 struct {
	A0, A1 baseEl
}

type e6 struct {
	B0, B1, B2 e2
}

type e12 struct {
	C0, C1 e6
}

type ext2 struct {
	fp          *curveF
	nonResidues map[int]map[int]*e2
}

func newExt2(baseField *curveF) *ext2 {
	pwrs := map[int]map[int]struct {
		A0 string
		A1 string
	}{
		0: {
			-1: {"21087453498479301738505683583845423561061080261299122796980902361914303298513", "14681138511599513868579906292550611339979233093309515871315818100066920017952"},
			1:  {"9", "1"},
		},
		1: {
			1: {"8376118865763821496583973867626364092589906065868298776909617916018768340080", "16469823323077808223889137241176536799009286646108169935659301613961712198316"},
			2: {"21575463638280843010398324269430826099269044274347216827212613867836435027261", "10307601595873709700152284273816112264069230130616436755625194854815875713954"},
			3: {"2821565182194536844548159561693502659359617185244120367078079554186484126554", "3505843767911556378687030309984248845540243509899259641013678093033130930403"},
			4: {"2581911344467009335267311115468803099551665605076196740867805258568234346338", "19937756971775647987995932169929341994314640652964949448313374472400716661030"},
			5: {"685108087231508774477564247770172212460312782337200605669322048753928464687", "8447204650696766136447902020341177575205426561248465145919723016860428151883"},
		},
		2: {
			1: {"21888242871839275220042445260109153167277707414472061641714758635765020556617", "0"},
			2: {"21888242871839275220042445260109153167277707414472061641714758635765020556616", "0"},
			3: {"21888242871839275222246405745257275088696311157297823662689037894645226208582", "0"},
			4: {"2203960485148121921418603742825762020974279258880205651966", "0"},
			5: {"2203960485148121921418603742825762020974279258880205651967", "0"},
		},
		3: {
			1: {"11697423496358154304825782922584725312912383441159505038794027105778954184319", "303847389135065887422783454877609941456349188919719272345083954437860409601"},
			2: {"3772000881919853776433695186713858239009073593817195771773381919316419345261", "2236595495967245188281701248203181795121068902605861227855261137820944008926"},
			3: {"19066677689644738377698246183563772429336693972053703295610958340458742082029", "18382399103927718843559375435273026243156067647398564021675359801612095278180"},
			4: {"5324479202449903542726783395506214481928257762400643279780343368557297135718", "16208900380737693084919495127334387981393726419856888799917914180988844123039"},
			5: {"8941241848238582420466759817324047081148088512956452953208002715982955420483", "10338197737521362862238855242243140895517409139741313354160881284257516364953"},
		},
	}
	nonResidues := make(map[int]map[int]*e2)
	for pwr, v := range pwrs {
		for coeff, v := range v {
			el := e2{emulated.ValueOf[emulated.BN254Fp](v.A0), emulated.ValueOf[emulated.BN254Fp](v.A1)}
			if nonResidues[pwr] == nil {
				nonResidues[pwr] = make(map[int]*e2)
			}
			nonResidues[pwr][coeff] = &el
		}
	}
	return &ext2{fp: baseField, nonResidues: nonResidues}
}

type ext6 struct {
	*ext2
}

func newExt6(baseField *curveF) *ext6 {
	return &ext6{ext2: newExt2(baseField)}
}

type ext12 struct {
	*ext6
}

func newExt12(baseField *curveF) *ext12 {
	return &ext12{ext6: newExt6(baseField)}
}

// TODO: check where to use Mod and where ModMul.

func (e ext2) mulByElement(x *e2, y *baseEl) *e2 {
	// var yCopy fp.Element
	// yCopy.Set(y)
	z0 := e.fp.MulMod(&x.A0, y) // z.A0.Mul(&x.A0, &yCopy)
	z1 := e.fp.MulMod(&x.A1, y) // z.A1.Mul(&x.A1, &yCopy)
	return &e2{                 // return z
		A0: *z0,
		A1: *z1,
	}
}

func (e ext2) conjugate(x *e2) *e2 {
	z0 := x.A0            // z.A0 = x.A0
	z1 := e.fp.Neg(&x.A1) // z.A1.Neg(&x.A1)
	return &e2{           // return z
		A0: z0,
		A1: *z1,
	}
}

func (e ext2) mulByNonResidueGeneric(x *e2, power, coef int) *e2 {
	y := e.nonResidues[power][coef]
	z := e.mul(x, y)
	return z
}

func (e ext2) mulByNonResidue(x *e2) *e2 {
	/*
		// below is the direct transliteration of the gnark-crypto code. Now only,
		// for simplicity and debugging purposes, we do the non residue operations
		// without optimisations.

		nine := big.NewInt(9)
		// var a, b fp.Element
		a := e.fp.MulConst(&x.A0, nine) // a.Double(&x.A0).Double(&a).Double(&a).Add(&a, &x.A0).
		a = e.fp.Sub(a, &x.A1)          //   Sub(&a, &x.A1)
		b := e.fp.MulConst(&x.A1, nine) // b.Double(&x.A1).Double(&b).Double(&b).Add(&b, &x.A1).
		b = e.fp.Add(b, &x.A0)          //   Add(&b, &x.A0)
		return &E2{
			A0: *a, // z.A0.Set(&a)
			A1: *b, // z.A1.Set(&b)
		} // return z
	*/
	// TODO: inline non-residue multiplication
	return e.mulByNonResidueGeneric(x, 0, 1)
}

func (e ext2) mulByNonResidueInv(x *e2) *e2 {
	// TODO: to optimise with constant non-residue inverse
	/*
		// from gnark-crypto
		// z.Mul(x, &nonResInverse)
		// return z
	*/
	return e.mulByNonResidueGeneric(x, 0, -1)
}

func (e ext2) mulByNonResidue1Power1(x *e2) *e2 {
	return e.mulByNonResidueGeneric(x, 1, 1)
}

func (e ext2) mulByNonResidue1Power2(x *e2) *e2 {
	return e.mulByNonResidueGeneric(x, 1, 2)
}

func (e ext2) mulByNonResidue1Power3(x *e2) *e2 {
	return e.mulByNonResidueGeneric(x, 1, 3)
}

func (e ext2) mulByNonResidue1Power4(x *e2) *e2 {
	return e.mulByNonResidueGeneric(x, 1, 4)
}

func (e ext2) mulByNonResidue1Power5(x *e2) *e2 {
	return e.mulByNonResidueGeneric(x, 1, 5)
}

func (e ext2) mulByNonResidue2Power1(x *e2) *e2 {
	// TODO: A1 is 0, we can optimize for it
	return e.mulByNonResidueGeneric(x, 2, 1)
}
func (e ext2) mulByNonResidue2Power2(x *e2) *e2 {
	// TODO: A1 is 0, we can optimize for it
	return e.mulByNonResidueGeneric(x, 2, 2)
}

func (e ext2) mulByNonResidue2Power3(x *e2) *e2 {
	// TODO: A1 is 0, we can optimize for it
	return e.mulByNonResidueGeneric(x, 2, 3)
}

func (e ext2) mulByNonResidue2Power4(x *e2) *e2 {
	// TODO: A1 is 0, we can optimize for it
	return e.mulByNonResidueGeneric(x, 2, 4)
}

func (e ext2) mulByNonResidue2Power5(x *e2) *e2 {
	// TODO: A1 is 0, we can optimize for it
	return e.mulByNonResidueGeneric(x, 2, 5)
}

func (e ext2) mulByNonResidue3Power1(x *e2) *e2 {
	return e.mulByNonResidueGeneric(x, 3, 1)
}

func (e ext2) mulByNonResidue3Power2(x *e2) *e2 {
	return e.mulByNonResidueGeneric(x, 3, 2)
}

func (e ext2) mulByNonResidue3Power3(x *e2) *e2 {
	return e.mulByNonResidueGeneric(x, 3, 3)
}

func (e ext2) mulByNonResidue3Power4(x *e2) *e2 {
	return e.mulByNonResidueGeneric(x, 3, 4)
}

func (e ext2) mulByNonResidue3Power5(x *e2) *e2 {
	return e.mulByNonResidueGeneric(x, 3, 5)
}

func (e ext2) mul(x, y *e2) *e2 {
	// var a, b, c fp.Element
	a := e.fp.Add(&x.A0, &x.A1)    // a.Add(&x.A0, &x.A1)
	b := e.fp.Add(&y.A0, &y.A1)    // b.Add(&y.A0, &y.A1)
	a = e.fp.MulMod(a, b)          // a.Mul(&a, &b)
	b = e.fp.MulMod(&x.A0, &y.A0)  // b.Mul(&x.A0, &y.A0)
	c := e.fp.MulMod(&x.A1, &y.A1) // c.Mul(&x.A1, &y.A1)
	z1 := e.fp.Sub(a, b)           // z.A1.Sub(&a, &b).
	z1 = e.fp.Sub(z1, c)           //   Sub(&z.A1, &c)
	z0 := e.fp.Sub(b, c)           // z.A0.Sub(&b, &c)
	return &e2{
		A0: *z0,
		A1: *z1,
	}
}

func (e ext2) add(x, y *e2) *e2 {
	z0 := e.fp.Add(&x.A0, &y.A0) // z.A0.Add(&x.A0, &y.A0)
	z1 := e.fp.Add(&x.A1, &y.A1) // z.A1.Add(&x.A1, &y.A1)
	return &e2{
		A0: *z0,
		A1: *z1,
	}
}

func (e ext2) sub(x, y *e2) *e2 {
	z0 := e.fp.Sub(&x.A0, &y.A0) // z.A0.Sub(&x.A0, &y.A0)
	z1 := e.fp.Sub(&x.A1, &y.A1) // z.A1.Sub(&x.A1, &y.A1)
	return &e2{
		A0: *z0,
		A1: *z1,
	}
}

func (e ext2) neg(x *e2) *e2 {
	z0 := e.fp.Neg(&x.A0) // z.A0.Neg(&x.A0)
	z1 := e.fp.Neg(&x.A1) // z.A1.Neg(&x.A1)
	return &e2{
		A0: *z0,
		A1: *z1,
	}
}

func (e ext2) one() *e2 {
	z0 := e.fp.One()  // z.A0.SetOne()
	z1 := e.fp.Zero() // z.A1.SetZero()
	return &e2{       // return z
		A0: *z0,
		A1: *z1,
	}
}

func (e ext2) zero() *e2 {
	z0 := e.fp.Zero()
	z1 := e.fp.Zero()
	return &e2{
		A0: *z0,
		A1: *z1,
	}
}

func (e ext2) square(x *e2) *e2 {
	// var a, b fp.Element
	a := e.fp.Add(&x.A0, &x.A1)         // a.Add(&x.A0, &x.A1)
	b := e.fp.Sub(&x.A0, &x.A1)         // b.Sub(&x.A0, &x.A1)
	a = e.fp.MulMod(a, b)               // a.Mul(&a, &b)
	b = e.fp.MulMod(&x.A0, &x.A1)       // b.Mul(&x.A0, &x.A1).
	b = e.fp.MulConst(b, big.NewInt(2)) //   Double(&b)
	return &e2{
		A0: *a, // z.A0.Set(&a)
		A1: *b, // z.A1.Set(&b)
	}
}

func (e ext2) double(x *e2) *e2 {
	two := big.NewInt(2)
	z0 := e.fp.MulConst(&x.A0, two) // z.A0.Double(&x.A0)
	z1 := e.fp.MulConst(&x.A1, two) // z.A1.Double(&x.A1)
	return &e2{
		A0: *z0,
		A1: *z1,
	}
}

func (e ext2) halve(x *e2) *e2 {
	// I'm trying to avoid hard-coding modulus here in case want to make generic
	// for different curves.
	// TODO: if implemented Half in field emulation, then replace with it.
	one := e.fp.One()
	two := e.fp.MulConst(one, big.NewInt(2))
	z0 := e.fp.Div(&x.A0, two)
	z1 := e.fp.Div(&x.A1, two)
	return &e2{
		A0: *z0,
		A1: *z1,
	}
}

func (e ext2) mulBybTwistCurveCoeff(x *e2) *e2 {
	// var res E2
	res := e.mulByNonResidueInv(x) // res.MulByNonResidueInv(x)
	z := e.double(res)             // z.Double(&res).
	z = e.add(z, res)              // 	Add(&res, z)
	return z                       // return z
}

func (e ext2) inverse(x *e2) *e2 {
	// var t0, t1 fp.Element
	t0 := e.fp.MulMod(&x.A0, &x.A0) // t0.Square(&x.A0)
	t1 := e.fp.MulMod(&x.A1, &x.A1) // t1.Square(&x.A1)
	t0 = e.fp.Add(t0, t1)           // t0.Add(&t0, &t1)
	t1 = e.fp.Inverse(t0)           // t1.Inverse(&t0)
	z0 := e.fp.MulMod(&x.A0, t1)    // z.A0.Mul(&x.A0, &t1)
	z1 := e.fp.MulMod(&x.A1, t1)    // z.A1.Mul(&x.A1, &t1).
	z1 = e.fp.Neg(z1)               //   Neg(&z.A1)
	return &e2{
		A0: *z0,
		A1: *z1,
	}
}

func (e ext2) assertIsEqual(x, y *e2) {
	e.fp.AssertIsEqual(&x.A0, &y.A0)
	e.fp.AssertIsEqual(&x.A1, &y.A1)
}

func (e ext6) add(x, y *e6) *e6 {
	z0 := e.ext2.add(&x.B0, &y.B0) // z.B0.Add(&x.B0, &y.B0)
	z1 := e.ext2.add(&x.B1, &y.B1) // z.B1.Add(&x.B1, &y.B1)
	z2 := e.ext2.add(&x.B2, &y.B2) // z.B2.Add(&x.B2, &y.B2)
	return &e6{                    // return z
		B0: *z0,
		B1: *z1,
		B2: *z2,
	}
}

func (e ext6) neg(x *e6) *e6 {
	z0 := e.ext2.neg(&x.B0) // z.B0.Neg(&x.B0)
	z1 := e.ext2.neg(&x.B1) // z.B1.Neg(&x.B1)
	z2 := e.ext2.neg(&x.B2) // z.B2.Neg(&x.B2)
	return &e6{             // return z
		B0: *z0,
		B1: *z1,
		B2: *z2,
	}
}

func (e ext6) sub(x, y *e6) *e6 {
	z0 := e.ext2.sub(&x.B0, &y.B0) // z.B0.Sub(&x.B0, &y.B0)
	z1 := e.ext2.sub(&x.B1, &y.B1) // z.B1.Sub(&x.B1, &y.B1)
	z2 := e.ext2.sub(&x.B2, &y.B2) // z.B2.Sub(&x.B2, &y.B2)
	return &e6{                    // return z
		B0: *z0,
		B1: *z1,
		B2: *z2,
	}
}

func (e ext6) mul(x, y *e6) *e6 {
	// var t0, t1, t2, c0, c1, c2, tmp E2
	t0 := e.ext2.mul(&x.B0, &y.B0)   // t0.Mul(&x.B0, &y.B0)
	t1 := e.ext2.mul(&x.B1, &y.B1)   // t1.Mul(&x.B1, &y.B1)
	t2 := e.ext2.mul(&x.B2, &y.B2)   // t2.Mul(&x.B2, &y.B2)
	c0 := e.ext2.add(&x.B1, &x.B2)   // c0.Add(&x.B1, &x.B2)
	tmp := e.ext2.add(&y.B1, &y.B2)  // tmp.Add(&y.B1, &y.B2)
	c0 = e.ext2.mul(c0, tmp)         // c0.Mul(&c0, &tmp).
	c0 = e.ext2.sub(c0, t1)          // 	Sub(&c0, &t1).
	c0 = e.ext2.sub(c0, t2)          // 	Sub(&c0, &t2).
	c0 = e.ext2.mulByNonResidue(c0)  // 	MulByNonResidue(&c0).
	c0 = e.ext2.add(c0, t0)          // 	Add(&c0, &t0)
	c1 := e.ext2.add(&x.B0, &x.B1)   // c1.Add(&x.B0, &x.B1)
	tmp = e.ext2.add(&y.B0, &y.B1)   // tmp.Add(&y.B0, &y.B1)
	c1 = e.ext2.mul(c1, tmp)         // c1.Mul(&c1, &tmp).
	c1 = e.ext2.sub(c1, t0)          // 	Sub(&c1, &t0).
	c1 = e.ext2.sub(c1, t1)          // 	Sub(&c1, &t1)
	tmp = e.ext2.mulByNonResidue(t2) // tmp.MulByNonResidue(&t2)
	c1 = e.ext2.add(c1, tmp)         // c1.Add(&c1, &tmp)
	tmp = e.ext2.add(&x.B0, &x.B2)   // tmp.Add(&x.B0, &x.B2)
	c2 := e.ext2.add(&y.B0, &y.B2)   // c2.Add(&y.B0, &y.B2).
	c2 = e.ext2.mul(c2, tmp)         // 	Mul(&c2, &tmp).
	c2 = e.ext2.sub(c2, t0)          // 	Sub(&c2, &t0).
	c2 = e.ext2.sub(c2, t2)          // 	Sub(&c2, &t2).
	c2 = e.ext2.add(c2, t1)          // 	Add(&c2, &t1)
	return &e6{
		B0: *c0, // z.B0.Set(&c0)
		B1: *c1, // z.B1.Set(&c1)
		B2: *c2, // z.B2.Set(&c2)
	} // return z
}

func (e ext6) double(x *e6) *e6 {
	z0 := e.ext2.double(&x.B0) // z.B0.Double(&x.B0)
	z1 := e.ext2.double(&x.B1) // z.B1.Double(&x.B1)
	z2 := e.ext2.double(&x.B2) // z.B2.Double(&x.B2)
	return &e6{                // return z
		B0: *z0,
		B1: *z1,
		B2: *z2,
	}
}

func (e ext6) square(x *e6) *e6 {
	// var c4, c5, c1, c2, c3, c0 E2
	c4 := e.ext2.mul(&x.B0, &x.B1)   // c4.Mul(&x.B0, &x.B1).
	c4 = e.ext2.double(c4)           // 	Double(&c4)
	c5 := e.ext2.square(&x.B2)       // c5.Square(&x.B2)
	c1 := e.ext2.mulByNonResidue(c5) // c1.MulByNonResidue(&c5).
	c1 = e.ext2.add(c1, c4)          // 	Add(&c1, &c4)
	c2 := e.ext2.sub(c4, c5)         // c2.Sub(&c4, &c5)
	c3 := e.ext2.square(&x.B0)       // c3.Square(&x.B0)
	c4 = e.ext2.sub(&x.B0, &x.B1)    // c4.Sub(&x.B0, &x.B1).
	c4 = e.ext2.add(c4, &x.B2)       // 	Add(&c4, &x.B2)
	c5 = e.ext2.mul(&x.B1, &x.B2)    // c5.Mul(&x.B1, &x.B2).
	c5 = e.ext2.double(c5)           // 	Double(&c5)
	c4 = e.ext2.square(c4)           // c4.Square(&c4)
	c0 := e.ext2.mulByNonResidue(c5) // c0.MulByNonResidue(&c5).
	c0 = e.ext2.add(c0, c3)          // 	Add(&c0, &c3)
	z2 := e.ext2.add(c2, c4)         // z.B2.Add(&c2, &c4).
	z2 = e.ext2.add(z2, c5)          // 	Add(&z.B2, &c5).
	z2 = e.ext2.sub(z2, c3)          // 	Sub(&z.B2, &c3)
	z0 := c0                         // z.B0.Set(&c0)
	z1 := c1                         // z.B1.Set(&c1)
	return &e6{                      // return z
		B0: *z0,
		B1: *z1,
		B2: *z2,
	}
}

func (e ext6) inverse(x *e6) *e6 {
	// var t0, t1, t2, t3, t4, t5, t6, c0, c1, c2, d1, d2 E2
	t0 := e.ext2.square(&x.B0)       // t0.Square(&x.B0)
	t1 := e.ext2.square(&x.B1)       // t1.Square(&x.B1)
	t2 := e.ext2.square(&x.B2)       // t2.Square(&x.B2)
	t3 := e.ext2.mul(&x.B0, &x.B1)   // t3.Mul(&x.B0, &x.B1)
	t4 := e.ext2.mul(&x.B0, &x.B2)   // t4.Mul(&x.B0, &x.B2)
	t5 := e.ext2.mul(&x.B1, &x.B2)   // t5.Mul(&x.B1, &x.B2)
	c0 := e.ext2.mulByNonResidue(t5) // c0.MulByNonResidue(&t5).
	c0 = e.ext2.neg(c0)              //    Neg(&c0).
	c0 = e.ext2.add(c0, t0)          //    Add(&c0, &t0)
	c1 := e.ext2.mulByNonResidue(t2) // c1.MulByNonResidue(&t2).
	c1 = e.ext2.sub(c1, t3)          //    Sub(&c1, &t3)
	c2 := e.ext2.sub(t1, t4)         // c2.Sub(&t1, &t4)
	t6 := e.ext2.mul(&x.B0, c0)      // t6.Mul(&x.B0, &c0)
	d1 := e.ext2.mul(&x.B2, c1)      // d1.Mul(&x.B2, &c1)
	d2 := e.ext2.mul(&x.B1, c2)      // d2.Mul(&x.B1, &c2)
	d1 = e.ext2.add(d1, d2)          // d1.Add(&d1, &d2).
	d1 = e.ext2.mulByNonResidue(d1)  //    MulByNonResidue(&d1)
	t6 = e.ext2.add(t6, d1)          // t6.Add(&t6, &d1)
	t6 = e.ext2.inverse(t6)          // t6.Inverse(&t6)
	z0 := e.ext2.mul(c0, t6)         // z.B0.Mul(&c0, &t6)
	z1 := e.ext2.mul(c1, t6)         // z.B1.Mul(&c1, &t6)
	z2 := e.ext2.mul(c2, t6)         // z.B2.Mul(&c2, &t6)
	return &e6{                      // return z
		B0: *z0,
		B1: *z1,
		B2: *z2,
	}
}
func (e ext6) mulByE2(x *e6, y *e2) *e6 {
	// var yCopy E2
	// yCopy.Set(y)
	z0 := e.ext2.mul(&x.B0, y) // z.B0.Mul(&x.B0, &yCopy)
	z1 := e.ext2.mul(&x.B1, y) // z.B1.Mul(&x.B1, &yCopy)
	z2 := e.ext2.mul(&x.B2, y) // z.B2.Mul(&x.B2, &yCopy)
	return &e6{                // return z
		B0: *z0,
		B1: *z1,
		B2: *z2,
	}
}

func (e ext6) mulBy01(z *e6, c0, c1 *e2) *e6 {
	// var a, b, tmp, t0, t1, t2 E2
	a := e.ext2.mul(&z.B0, c0)      // a.Mul(&z.B0, c0)
	b := e.ext2.mul(&z.B1, c1)      // b.Mul(&z.B1, c1)
	tmp := e.ext2.add(&z.B1, &z.B2) // tmp.Add(&z.B1, &z.B2)
	t0 := e.ext2.mul(c1, tmp)       // t0.Mul(c1, &tmp)
	t0 = e.ext2.sub(t0, b)          // t0.Sub(&t0, &b)
	t0 = e.ext2.mulByNonResidue(t0) // t0.MulByNonResidue(&t0)
	t0 = e.ext2.add(t0, a)          // t0.Add(&t0, &a)
	tmp = e.ext2.add(&z.B0, &z.B2)  // tmp.Add(&z.B0, &z.B2)
	t2 := e.ext2.mul(c0, tmp)       // t2.Mul(c0, &tmp)
	t2 = e.ext2.sub(t2, a)          // t2.Sub(&t2, &a)
	t2 = e.ext2.add(t2, b)          // t2.Add(&t2, &b)
	t1 := e.ext2.add(c0, c1)        // t1.Add(c0, c1)
	tmp = e.ext2.add(&z.B0, &z.B1)  // tmp.Add(&z.B0, &z.B1)
	t1 = e.ext2.mul(t1, tmp)        // t1.Mul(&t1, &tmp)
	t1 = e.ext2.sub(t1, a)          // t1.Sub(&t1, &a)
	t1 = e.ext2.sub(t1, b)          // t1.Sub(&t1, &b)
	return &e6{
		B0: *t0, // z.B0.Set(&t0)
		B1: *t1, // z.B1.Set(&t1)
		B2: *t2, // z.B2.Set(&t2)
	} // return z
}

func (e ext6) mulByNonResidue(x *e6) *e6 {
	z2, z1, z0 := &x.B1, &x.B0, &x.B2 // z.B2, z.B1, z.B0 = x.B1, x.B0, x.B2
	z0 = e.ext2.mulByNonResidue(z0)   // z.B0.MulByNonResidue(&z.B0)
	return &e6{                       // return z
		B0: *z0,
		B1: *z1,
		B2: *z2,
	}
}

func (e ext6) assertIsEqual(x, y *e6) {
	e.ext2.assertIsEqual(&x.B0, &y.B0)
	e.ext2.assertIsEqual(&x.B1, &y.B1)
	e.ext2.assertIsEqual(&x.B2, &y.B2)
}

func (e ext12) conjugate(x *e12) *e12 {
	z1 := e.ext6.neg(&x.C1) // z.C1.Neg(&z.C1)
	return &e12{            // return z
		C0: x.C0,
		C1: *z1,
	}
}

func (e ext12) inverse(x *e12) *e12 {
	// var t0, t1, tmp E6
	t0 := e.ext6.square(&x.C0)        // t0.Square(&x.C0)
	t1 := e.ext6.square(&x.C1)        // t1.Square(&x.C1)
	tmp := e.ext6.mulByNonResidue(t1) // tmp.MulByNonResidue(&t1)
	t0 = e.ext6.sub(t0, tmp)          // t0.Sub(&t0, &tmp)
	t1 = e.ext6.inverse(t0)           // t1.Inverse(&t0)
	z0 := e.ext6.mul(&x.C0, t1)       // z.C0.Mul(&x.C0, &t1)
	z1 := e.ext6.mul(&x.C1, t1)       // z.C1.Mul(&x.C1, &t1).
	z1 = e.ext6.neg(z1)               //      Neg(&z.C1)
	return &e12{                      // return z
		C0: *z0,
		C1: *z1,
	}
}

func (e ext12) mul(x, y *e12) *e12 {
	// var a, b, c E6
	a := e.ext6.add(&x.C0, &x.C1)   // a.Add(&x.C0, &x.C1)
	b := e.ext6.add(&y.C0, &y.C1)   // b.Add(&y.C0, &y.C1)
	a = e.ext6.mul(a, b)            // a.Mul(&a, &b)
	b = e.ext6.mul(&x.C0, &y.C0)    // b.Mul(&x.C0, &y.C0)
	c := e.ext6.mul(&x.C1, &y.C1)   // c.Mul(&x.C1, &y.C1)
	z1 := e.ext6.sub(a, b)          // z.C1.Sub(&a, &b).
	z1 = e.ext6.sub(z1, c)          //      Sub(&z.C1, &c)
	z0 := e.ext6.mulByNonResidue(c) // z.C0.MulByNonResidue(&c).
	z0 = e.ext6.add(z0, b)          //      Add(&z.C0, &b)
	return &e12{                    // return z
		C0: *z0,
		C1: *z1,
	}
}

func (e ext12) cyclotomicSquare(x *e12) *e12 {
	// var t [9]E2
	t0 := e.ext2.square(&x.C1.B1)        // t[0].Square(&x.C1.B1)
	t1 := e.ext2.square(&x.C0.B0)        // t[1].Square(&x.C0.B0)
	t6 := e.ext2.add(&x.C1.B1, &x.C0.B0) // t[6].Add(&x.C1.B1, &x.C0.B0).
	t6 = e.ext2.square(t6)               // 	Square(&t[6]).
	t6 = e.ext2.sub(t6, t0)              // 	Sub(&t[6], &t[0]).
	t6 = e.ext2.sub(t6, t1)              // 	Sub(&t[6], &t[1])
	t2 := e.ext2.square(&x.C0.B2)        // t[2].Square(&x.C0.B2)
	t3 := e.ext2.square(&x.C1.B0)        // t[3].Square(&x.C1.B0)
	t7 := e.ext2.add(&x.C0.B2, &x.C1.B0) // t[7].Add(&x.C0.B2, &x.C1.B0).
	t7 = e.ext2.square(t7)               // 	Square(&t[7]).
	t7 = e.ext2.sub(t7, t2)              // 	Sub(&t[7], &t[2]).
	t7 = e.ext2.sub(t7, t3)              // 	Sub(&t[7], &t[3])
	t4 := e.ext2.square(&x.C1.B2)        // t[4].Square(&x.C1.B2)
	t5 := e.ext2.square(&x.C0.B1)        // t[5].Square(&x.C0.B1)
	t8 := e.ext2.add(&x.C1.B2, &x.C0.B1) // t[8].Add(&x.C1.B2, &x.C0.B1).
	t8 = e.ext2.square(t8)               // 	Square(&t[8]).
	t8 = e.ext2.sub(t8, t4)              // 	Sub(&t[8], &t[4]).
	t8 = e.ext2.sub(t8, t5)              // 	Sub(&t[8], &t[5]).
	t8 = e.ext2.mulByNonResidue(t8)      // 	MulByNonResidue(&t[8])
	t0 = e.ext2.mulByNonResidue(t0)      // t[0].MulByNonResidue(&t[0]).
	t0 = e.ext2.add(t0, t1)              // 	Add(&t[0], &t[1])
	t2 = e.ext2.mulByNonResidue(t2)      // t[2].MulByNonResidue(&t[2]).
	t2 = e.ext2.add(t2, t3)              // 	Add(&t[2], &t[3])
	t4 = e.ext2.mulByNonResidue(t4)      // t[4].MulByNonResidue(&t[4]).
	t4 = e.ext2.add(t4, t5)              // 	Add(&t[4], &t[5])
	z00 := e.ext2.sub(t0, &x.C0.B0)      // z.C0.B0.Sub(&t[0], &x.C0.B0).
	z00 = e.ext2.double(z00)             // 	Double(&z.C0.B0).
	z00 = e.ext2.add(z00, t0)            // 	Add(&z.C0.B0, &t[0])
	z01 := e.ext2.sub(t2, &x.C0.B1)      // z.C0.B1.Sub(&t[2], &x.C0.B1).
	z01 = e.ext2.double(z01)             // 	Double(&z.C0.B1).
	z01 = e.ext2.add(z01, t2)            // 	Add(&z.C0.B1, &t[2])
	z02 := e.ext2.sub(t4, &x.C0.B2)      // z.C0.B2.Sub(&t[4], &x.C0.B2).
	z02 = e.ext2.double(z02)             // 	Double(&z.C0.B2).
	z02 = e.ext2.add(z02, t4)            // 	Add(&z.C0.B2, &t[4])
	z10 := e.ext2.add(t8, &x.C1.B0)      // z.C1.B0.Add(&t[8], &x.C1.B0).
	z10 = e.ext2.double(z10)             // 	Double(&z.C1.B0).
	z10 = e.ext2.add(z10, t8)            // 	Add(&z.C1.B0, &t[8])
	z11 := e.ext2.add(t6, &x.C1.B1)      // z.C1.B1.Add(&t[6], &x.C1.B1).
	z11 = e.ext2.double(z11)             // 	Double(&z.C1.B1).
	z11 = e.ext2.add(z11, t6)            // 	Add(&z.C1.B1, &t[6])
	z12 := e.ext2.add(t7, &x.C1.B2)      // z.C1.B2.Add(&t[7], &x.C1.B2).
	z12 = e.ext2.double(z12)             // 	Double(&z.C1.B2).
	z12 = e.ext2.add(z12, t7)            // 	Add(&z.C1.B2, &t[7])
	return &e12{                         // return z
		C0: e6{
			B0: *z00,
			B1: *z01,
			B2: *z02,
		},
		C1: e6{
			B0: *z10,
			B1: *z11,
			B2: *z12,
		},
	}
}

func (e ext12) frobenius(x *e12) *e12 {
	// var t [6]E2
	t0 := e.ext2.conjugate(&x.C0.B0)       // t[0].Conjugate(&x.C0.B0)
	t1 := e.ext2.conjugate(&x.C0.B1)       // t[1].Conjugate(&x.C0.B1)
	t2 := e.ext2.conjugate(&x.C0.B2)       // t[2].Conjugate(&x.C0.B2)
	t3 := e.ext2.conjugate(&x.C1.B0)       // t[3].Conjugate(&x.C1.B0)
	t4 := e.ext2.conjugate(&x.C1.B1)       // t[4].Conjugate(&x.C1.B1)
	t5 := e.ext2.conjugate(&x.C1.B2)       // t[5].Conjugate(&x.C1.B2)
	t1 = e.ext2.mulByNonResidue1Power2(t1) // t[1].MulByNonResidue1Power2(&t[1])
	t2 = e.ext2.mulByNonResidue1Power4(t2) // t[2].MulByNonResidue1Power4(&t[2])
	t3 = e.ext2.mulByNonResidue1Power1(t3) // t[3].MulByNonResidue1Power1(&t[3])
	t4 = e.ext2.mulByNonResidue1Power3(t4) // t[4].MulByNonResidue1Power3(&t[4])
	t5 = e.ext2.mulByNonResidue1Power5(t5) // t[5].MulByNonResidue1Power5(&t[5])
	return &e12{                           // return z
		C0: e6{
			B0: *t0, // z.C0.B0 = t[0]
			B1: *t1, // z.C0.B1 = t[1]
			B2: *t2, // z.C0.B2 = t[2]
		},
		C1: e6{
			B0: *t3, // z.C1.B0 = t[3]
			B1: *t4, // z.C1.B1 = t[4]
			B2: *t5, // z.C1.B2 = t[5]
		},
	}
}

func (e ext12) frobeniusSquare(x *e12) *e12 {
	z00 := &x.C0.B0                                // z.C0.B0 = x.C0.B0
	z01 := e.ext2.mulByNonResidue2Power2(&x.C0.B1) // z.C0.B1.MulByNonResidue2Power2(&x.C0.B1)
	z02 := e.ext2.mulByNonResidue2Power4(&x.C0.B2) // z.C0.B2.MulByNonResidue2Power4(&x.C0.B2)
	z10 := e.ext2.mulByNonResidue2Power1(&x.C1.B0) // z.C1.B0.MulByNonResidue2Power1(&x.C1.B0)
	z11 := e.ext2.mulByNonResidue2Power3(&x.C1.B1) // z.C1.B1.MulByNonResidue2Power3(&x.C1.B1)
	z12 := e.ext2.mulByNonResidue2Power5(&x.C1.B2) // z.C1.B2.MulByNonResidue2Power5(&x.C1.B2)
	return &e12{                                   // return z
		C0: e6{B0: *z00, B1: *z01, B2: *z02},
		C1: e6{B0: *z10, B1: *z11, B2: *z12},
	}
}

func (e ext12) frobeniusCube(x *e12) *e12 {
	// var t [6]E2
	t0 := e.ext2.conjugate(&x.C0.B0)       // t[0].Conjugate(&x.C0.B0)
	t1 := e.ext2.conjugate(&x.C0.B1)       // t[1].Conjugate(&x.C0.B1)
	t2 := e.ext2.conjugate(&x.C0.B2)       // t[2].Conjugate(&x.C0.B2)
	t3 := e.ext2.conjugate(&x.C1.B0)       // t[3].Conjugate(&x.C1.B0)
	t4 := e.ext2.conjugate(&x.C1.B1)       // t[4].Conjugate(&x.C1.B1)
	t5 := e.ext2.conjugate(&x.C1.B2)       // t[5].Conjugate(&x.C1.B2)
	t1 = e.ext2.mulByNonResidue3Power2(t1) // t[1].MulByNonResidue3Power2(&t[1])
	t2 = e.ext2.mulByNonResidue3Power4(t2) // t[2].MulByNonResidue3Power4(&t[2])
	t3 = e.ext2.mulByNonResidue3Power1(t3) // t[3].MulByNonResidue3Power1(&t[3])
	t4 = e.ext2.mulByNonResidue3Power3(t4) // t[4].MulByNonResidue3Power3(&t[4])
	t5 = e.ext2.mulByNonResidue3Power5(t5) // t[5].MulByNonResidue3Power5(&t[5])
	return &e12{                           // return z
		C0: e6{
			B0: *t0, // z.C0.B0 = t[0]
			B1: *t1, // z.C0.B1 = t[1]
			B2: *t2, // z.C0.B2 = t[2]
		},
		C1: e6{
			B0: *t3, // z.C1.B0 = t[3]
			B1: *t4, // z.C1.B1 = t[4]
			B2: *t5, // z.C1.B2 = t[5]
		},
	}
}

func (e ext12) expt(x *e12) *e12 {
	// var result, t0, t1, t2, t3, t4, t5, t6 E12
	t3 := e.cyclotomicSquare(x)      // t3.CyclotomicSquare(x)
	t5 := e.cyclotomicSquare(t3)     // t5.CyclotomicSquare(&t3)
	result := e.cyclotomicSquare(t5) // result.CyclotomicSquare(&t5)
	t0 := e.cyclotomicSquare(result) // t0.CyclotomicSquare(&result)
	t2 := e.mul(x, t0)               // t2.Mul(x, &t0)
	t0 = e.mul(t3, t2)               // t0.Mul(&t3, &t2)
	t1 := e.mul(x, t0)               // t1.Mul(x, &t0)
	t4 := e.mul(result, t2)          // t4.Mul(&result, &t2)
	t6 := e.cyclotomicSquare(t2)     // t6.CyclotomicSquare(&t2)
	t1 = e.mul(t0, t1)               // t1.Mul(&t0, &t1)
	t0 = e.mul(t3, t1)               // t0.Mul(&t3, &t1)
	t6 = e.nSquare(t6, 6)            // t6.nSquare(6)
	t5 = e.mul(t5, t6)               // t5.Mul(&t5, &t6)
	t5 = e.mul(t4, t5)               // t5.Mul(&t4, &t5)
	t5 = e.nSquare(t5, 7)            // t5.nSquare(7)
	t4 = e.mul(t4, t5)               // t4.Mul(&t4, &t5)
	t4 = e.nSquare(t4, 8)            // t4.nSquare(8)
	t4 = e.mul(t0, t4)               // t4.Mul(&t0, &t4)
	t3 = e.mul(t3, t4)               // t3.Mul(&t3, &t4)
	t3 = e.nSquare(t3, 6)            // t3.nSquare(6)
	t2 = e.mul(t2, t3)               // t2.Mul(&t2, &t3)
	t2 = e.nSquare(t2, 8)            // t2.nSquare(8)
	t2 = e.mul(t0, t2)               // t2.Mul(&t0, &t2)
	t2 = e.nSquare(t2, 6)            // t2.nSquare(6)
	t2 = e.mul(t0, t2)               // t2.Mul(&t0, &t2)
	t2 = e.nSquare(t2, 10)           // t2.nSquare(10)
	t1 = e.mul(t1, t2)               // t1.Mul(&t1, &t2)
	t1 = e.nSquare(t1, 6)            // t1.nSquare(6)
	t0 = e.mul(t0, t1)               // t0.Mul(&t0, &t1)
	z := e.mul(result, t0)           // z.Mul(&result, &t0)
	return z                         // return z
}

func (e ext12) one() *e12 {
	z000 := e.fp.One()
	zero := e.fp.Zero()
	return &e12{
		C0: e6{
			B0: e2{A0: *z000, A1: *zero},
			B1: e2{A0: *zero, A1: *zero},
			B2: e2{A0: *zero, A1: *zero},
		},
		C1: e6{
			B0: e2{A0: *zero, A1: *zero},
			B1: e2{A0: *zero, A1: *zero},
			B2: e2{A0: *zero, A1: *zero},
		},
	}
}

func (e ext12) mulBy034(z *e12, c0, c3, c4 *e2) *e12 {
	// var a, b, d E6
	a := e.ext6.mulByE2(&z.C0, c0) // a.MulByE2(&z.C0, c0)
	// b.Set(&z.C1)
	b := e.ext6.mulBy01(&z.C1, c3, c4) // b.MulBy01(c3, c4)
	c0 = e.ext2.add(c0, c3)            // c0.Add(c0, c3)
	d := e.ext6.add(&z.C0, &z.C1)      // d.Add(&z.C0, &z.C1)
	d = e.ext6.mulBy01(d, c0, c4)      // d.MulBy01(c0, c4)
	z1 := e.add(a, b)                  // z.C1.Add(&a, &b).
	z1 = e.neg(z1)                     //      Neg(&z.C1).
	z1 = e.add(z1, d)                  //      Add(&z.C1, &d)
	z0 := e.mulByNonResidue(b)         // z.C0.MulByNonResidue(&b).
	z0 = e.add(z0, a)                  //      Add(&z.C0, &a)
	return &e12{                       // return z
		C0: *z0,
		C1: *z1,
	}
}

func (e ext12) square(x *e12) *e12 {
	// var c0, c2, c3 E6
	c0 := e.ext6.sub(&x.C0, &x.C1)      // c0.Sub(&x.C0, &x.C1)
	c3 := e.ext6.mulByNonResidue(&x.C1) // c3.MulByNonResidue(&x.C1).
	c3 = e.ext6.neg(c3)                 //    Neg(&c3).
	c3 = e.ext6.add(&x.C0, c3)          //    Add(&x.C0, &c3)
	c2 := e.ext6.mul(&x.C0, &x.C1)      // c2.Mul(&x.C0, &x.C1)
	c0 = e.ext6.mul(c0, c3)             // c0.Mul(&c0, &c3).
	c0 = e.ext6.add(c0, c2)             //    Add(&c0, &c2)
	z1 := e.ext6.double(c2)             // z.C1.Double(&c2)
	c2 = e.ext6.mulByNonResidue(c2)     // c2.MulByNonResidue(&c2)
	z0 := e.ext6.add(c0, c2)            // z.C0.Add(&c0, &c2)
	return &e12{                        // return z
		C0: *z0,
		C1: *z1,
	}
}

func (e ext12) mulBy034by034(d0, d3, d4, c0, c3, c4 *e2) *e12 {
	// var tmp, x0, x3, x4, x04, x03, x34 E2
	x0 := e.ext2.mul(c0, d0)          // x0.Mul(c0, d0)
	x3 := e.ext2.mul(c3, d3)          // x3.Mul(c3, d3)
	x4 := e.ext2.mul(c4, d4)          // x4.Mul(c4, d4)
	tmp := e.ext2.add(c0, c4)         // tmp.Add(c0, c4)
	x04 := e.ext2.add(d0, d4)         // x04.Add(d0, d4).
	x04 = e.ext2.mul(x04, tmp)        // 	Mul(&x04, &tmp).
	x04 = e.ext2.sub(x04, x0)         // 	Sub(&x04, &x0).
	x04 = e.ext2.sub(x04, x4)         // 	Sub(&x04, &x4)
	tmp = e.ext2.add(c0, c3)          // tmp.Add(c0, c3)
	x03 := e.ext2.add(d0, d3)         // x03.Add(d0, d3).
	x03 = e.ext2.mul(x03, tmp)        // 	Mul(&x03, &tmp).
	x03 = e.ext2.sub(x03, x0)         // 	Sub(&x03, &x0).
	x03 = e.ext2.sub(x03, x3)         // 	Sub(&x03, &x3)
	tmp = e.ext2.add(c3, c4)          // tmp.Add(c3, c4)
	x34 := e.ext2.add(d3, d4)         // x34.Add(d3, d4).
	x34 = e.ext2.mul(x34, tmp)        // 	Mul(&x34, &tmp).
	x34 = e.ext2.sub(x34, x3)         // 	Sub(&x34, &x3).
	x34 = e.ext2.sub(x34, x4)         // 	Sub(&x34, &x4)
	z00 := e.ext2.mulByNonResidue(x4) // z.C0.B0.MulByNonResidue(&x4).
	z00 = e.ext2.add(z00, x0)         // 	Add(&z.C0.B0, &x0)
	z01 := x3                         // z.C0.B1.Set(&x3)
	z02 := x34                        // z.C0.B2.Set(&x34)
	z10 := x03                        // z.C1.B0.Set(&x03)
	z11 := x04                        // z.C1.B1.Set(&x04)
	z12 := e.ext2.zero()              // z.C1.B2.SetZero()
	return &e12{                      // return z
		C0: e6{
			B0: *z00,
			B1: *z01,
			B2: *z02,
		},
		C1: e6{
			B0: *z10,
			B1: *z11,
			B2: *z12,
		},
	}
}

func (e ext12) assertIsEqual(x, y *e12) {
	e.ext6.assertIsEqual(&x.C0, &y.C0)
	e.ext6.assertIsEqual(&x.C1, &y.C1)
}

func (e ext12) nSquare(z *e12, n int) *e12 {
	for i := 0; i < n; i++ {
		z = e.cyclotomicSquare(z)
	}
	return z
}
