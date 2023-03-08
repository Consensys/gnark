package fields_bn254

import (
	"math/big"

	"github.com/consensys/gnark/std/math/emulated"
)

type curveF = emulated.Field[emulated.BN254Fp]
type baseEl = emulated.Element[emulated.BN254Fp]

type E2 struct {
	A0, A1 baseEl
}

type Ext2 struct {
	fp          *curveF
	nonResidues map[int]map[int]*E2
}

func NewExt2(baseField *curveF) *Ext2 {
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
	nonResidues := make(map[int]map[int]*E2)
	for pwr, v := range pwrs {
		for coeff, v := range v {
			el := E2{emulated.ValueOf[emulated.BN254Fp](v.A0), emulated.ValueOf[emulated.BN254Fp](v.A1)}
			if nonResidues[pwr] == nil {
				nonResidues[pwr] = make(map[int]*E2)
			}
			nonResidues[pwr][coeff] = &el
		}
	}
	return &Ext2{fp: baseField, nonResidues: nonResidues}
}

// TODO: check where to use Mod and where ModMul.

func (e Ext2) MulByElement(x *E2, y *baseEl) *E2 {
	// var yCopy fp.Element
	// yCopy.Set(y)
	z0 := e.fp.MulMod(&x.A0, y) // z.A0.Mul(&x.A0, &yCopy)
	z1 := e.fp.MulMod(&x.A1, y) // z.A1.Mul(&x.A1, &yCopy)
	return &E2{                 // return z
		A0: *z0,
		A1: *z1,
	}
}

func (e Ext2) Conjugate(x *E2) *E2 {
	z0 := x.A0            // z.A0 = x.A0
	z1 := e.fp.Neg(&x.A1) // z.A1.Neg(&x.A1)
	return &E2{           // return z
		A0: z0,
		A1: *z1,
	}
}

func (e Ext2) MulByNonResidueGeneric(x *E2, power, coef int) *E2 {
	y := e.nonResidues[power][coef]
	z := e.Mul(x, y)
	return z
}

func (e Ext2) MulByNonResidue(x *E2) *E2 {
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
	// TODO: inline non-residue Multiplication
	return e.MulByNonResidueGeneric(x, 0, 1)
}

func (e Ext2) MulByNonResidueInv(x *E2) *E2 {
	// TODO: to optimise with constant non-residue inverse
	/*
		// from gnark-crypto
		// z.Mul(x, &nonResInverse)
		// return z
	*/
	return e.MulByNonResidueGeneric(x, 0, -1)
}

func (e Ext2) MulByNonResidue1Power1(x *E2) *E2 {
	return e.MulByNonResidueGeneric(x, 1, 1)
}

func (e Ext2) MulByNonResidue1Power2(x *E2) *E2 {
	return e.MulByNonResidueGeneric(x, 1, 2)
}

func (e Ext2) MulByNonResidue1Power3(x *E2) *E2 {
	return e.MulByNonResidueGeneric(x, 1, 3)
}

func (e Ext2) MulByNonResidue1Power4(x *E2) *E2 {
	return e.MulByNonResidueGeneric(x, 1, 4)
}

func (e Ext2) MulByNonResidue1Power5(x *E2) *E2 {
	return e.MulByNonResidueGeneric(x, 1, 5)
}

func (e Ext2) MulByNonResidue2Power1(x *E2) *E2 {
	// TODO: A1 is 0, we can optimize for it
	return e.MulByNonResidueGeneric(x, 2, 1)
}
func (e Ext2) MulByNonResidue2Power2(x *E2) *E2 {
	// TODO: A1 is 0, we can optimize for it
	return e.MulByNonResidueGeneric(x, 2, 2)
}

func (e Ext2) MulByNonResidue2Power3(x *E2) *E2 {
	// TODO: A1 is 0, we can optimize for it
	return e.MulByNonResidueGeneric(x, 2, 3)
}

func (e Ext2) MulByNonResidue2Power4(x *E2) *E2 {
	// TODO: A1 is 0, we can optimize for it
	return e.MulByNonResidueGeneric(x, 2, 4)
}

func (e Ext2) MulByNonResidue2Power5(x *E2) *E2 {
	// TODO: A1 is 0, we can optimize for it
	return e.MulByNonResidueGeneric(x, 2, 5)
}

func (e Ext2) MulByNonResidue3Power1(x *E2) *E2 {
	return e.MulByNonResidueGeneric(x, 3, 1)
}

func (e Ext2) MulByNonResidue3Power2(x *E2) *E2 {
	return e.MulByNonResidueGeneric(x, 3, 2)
}

func (e Ext2) MulByNonResidue3Power3(x *E2) *E2 {
	return e.MulByNonResidueGeneric(x, 3, 3)
}

func (e Ext2) MulByNonResidue3Power4(x *E2) *E2 {
	return e.MulByNonResidueGeneric(x, 3, 4)
}

func (e Ext2) MulByNonResidue3Power5(x *E2) *E2 {
	return e.MulByNonResidueGeneric(x, 3, 5)
}

func (e Ext2) Mul(x, y *E2) *E2 {
	// var a, b, c fp.Element
	a := e.fp.Add(&x.A0, &x.A1)    // a.Add(&x.A0, &x.A1)
	b := e.fp.Add(&y.A0, &y.A1)    // b.Add(&y.A0, &y.A1)
	a = e.fp.MulMod(a, b)          // a.Mul(&a, &b)
	b = e.fp.MulMod(&x.A0, &y.A0)  // b.Mul(&x.A0, &y.A0)
	c := e.fp.MulMod(&x.A1, &y.A1) // c.Mul(&x.A1, &y.A1)
	z1 := e.fp.Sub(a, b)           // z.A1.Sub(&a, &b).
	z1 = e.fp.Sub(z1, c)           //   Sub(&z.A1, &c)
	z0 := e.fp.Sub(b, c)           // z.A0.Sub(&b, &c)
	return &E2{
		A0: *z0,
		A1: *z1,
	}
}

func (e Ext2) Add(x, y *E2) *E2 {
	z0 := e.fp.Add(&x.A0, &y.A0) // z.A0.Add(&x.A0, &y.A0)
	z1 := e.fp.Add(&x.A1, &y.A1) // z.A1.Add(&x.A1, &y.A1)
	return &E2{
		A0: *z0,
		A1: *z1,
	}
}

func (e Ext2) Sub(x, y *E2) *E2 {
	z0 := e.fp.Sub(&x.A0, &y.A0) // z.A0.Sub(&x.A0, &y.A0)
	z1 := e.fp.Sub(&x.A1, &y.A1) // z.A1.Sub(&x.A1, &y.A1)
	return &E2{
		A0: *z0,
		A1: *z1,
	}
}

func (e Ext2) Neg(x *E2) *E2 {
	z0 := e.fp.Neg(&x.A0) // z.A0.Neg(&x.A0)
	z1 := e.fp.Neg(&x.A1) // z.A1.Neg(&x.A1)
	return &E2{
		A0: *z0,
		A1: *z1,
	}
}

func (e Ext2) One() *E2 {
	z0 := e.fp.One()  // z.A0.SetOne()
	z1 := e.fp.Zero() // z.A1.SetZero()
	return &E2{       // return z
		A0: *z0,
		A1: *z1,
	}
}

func (e Ext2) Zero() *E2 {
	z0 := e.fp.Zero()
	z1 := e.fp.Zero()
	return &E2{
		A0: *z0,
		A1: *z1,
	}
}

func (e Ext2) Square(x *E2) *E2 {
	// var a, b fp.Element
	a := e.fp.Add(&x.A0, &x.A1)         // a.Add(&x.A0, &x.A1)
	b := e.fp.Sub(&x.A0, &x.A1)         // b.Sub(&x.A0, &x.A1)
	a = e.fp.MulMod(a, b)               // a.Mul(&a, &b)
	b = e.fp.MulMod(&x.A0, &x.A1)       // b.Mul(&x.A0, &x.A1).
	b = e.fp.MulConst(b, big.NewInt(2)) //   Double(&b)
	return &E2{
		A0: *a, // z.A0.Set(&a)
		A1: *b, // z.A1.Set(&b)
	}
}

func (e Ext2) Double(x *E2) *E2 {
	two := big.NewInt(2)
	z0 := e.fp.MulConst(&x.A0, two) // z.A0.Double(&x.A0)
	z1 := e.fp.MulConst(&x.A1, two) // z.A1.Double(&x.A1)
	return &E2{
		A0: *z0,
		A1: *z1,
	}
}

func (e Ext2) Halve(x *E2) *E2 {
	// I'm trying to avoid hard-coding modulus here in case want to make generic
	// for different curves.
	// TODO: if implemented Half in field emulation, then replace with it.
	one := e.fp.One()
	two := e.fp.MulConst(one, big.NewInt(2))
	z0 := e.fp.Div(&x.A0, two)
	z1 := e.fp.Div(&x.A1, two)
	return &E2{
		A0: *z0,
		A1: *z1,
	}
}

func (e Ext2) MulBybTwistCurveCoeff(x *E2) *E2 {
	// var res E2
	res := e.MulByNonResidueInv(x) // res.MulByNonResidueInv(x)
	z := e.Double(res)             // z.Double(&res).
	z = e.Add(z, res)              // 	Add(&res, z)
	return z                       // return z
}

func (e Ext2) Inverse(x *E2) *E2 {
	// var t0, t1 fp.Element
	t0 := e.fp.MulMod(&x.A0, &x.A0) // t0.Square(&x.A0)
	t1 := e.fp.MulMod(&x.A1, &x.A1) // t1.Square(&x.A1)
	t0 = e.fp.Add(t0, t1)           // t0.Add(&t0, &t1)
	t1 = e.fp.Inverse(t0)           // t1.Inverse(&t0)
	z0 := e.fp.MulMod(&x.A0, t1)    // z.A0.Mul(&x.A0, &t1)
	z1 := e.fp.MulMod(&x.A1, t1)    // z.A1.Mul(&x.A1, &t1).
	z1 = e.fp.Neg(z1)               //   Neg(&z.A1)
	return &E2{
		A0: *z0,
		A1: *z1,
	}
}

func (e Ext2) AssertIsEqual(x, y *E2) {
	e.fp.AssertIsEqual(&x.A0, &y.A0)
	e.fp.AssertIsEqual(&x.A1, &y.A1)
}
