package sw_bls12381

import (
	"math/big"
	"slices"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bls12381"
	"github.com/consensys/gnark/std/hash/tofield"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/std/math/uints"
)

const (
	security_level       = 128
	len_per_base_element = 64
)

func (g2 *G2) HashToG2(api frontend.API, msg []uints.U8, dst []byte) (*G2Affine, error) {
	fp, e := emulated.NewField[emulated.BLS12381Fp](api)
	if e != nil {
		return &G2Affine{}, e
	}

	// Steps:
	// 1. u = hash_to_field(msg, 2)
	// 2. Q0 = map_to_curve(u[0])
	// 3. Q1 = map_to_curve(u[1])
	// 4. R = Q0 + Q1              # Point addition
	// 5. P = clear_cofactor(R)
	// 6. return P
	lenPerBaseElement := len_per_base_element
	lenInBytes := lenPerBaseElement * 4
	uniformBytes, e := tofield.ExpandMsgXmd(api, msg, dst, lenInBytes)
	if e != nil {
		return &G2Affine{}, e
	}

	ele1 := bytesToElement(api, fp, uniformBytes[:lenPerBaseElement])
	ele2 := bytesToElement(api, fp, uniformBytes[lenPerBaseElement:lenPerBaseElement*2])
	ele3 := bytesToElement(api, fp, uniformBytes[lenPerBaseElement*2:lenPerBaseElement*3])
	ele4 := bytesToElement(api, fp, uniformBytes[lenPerBaseElement*3:])

	// we will still do iso_map before point addition, as we do not have point addition in E' (yet)
	Q0, e := g2.MapToCurve2(&fields_bls12381.E2{A0: *ele1, A1: *ele2})
	if e != nil {
		return &G2Affine{}, e
	}
	Q1, e := g2.MapToCurve2(&fields_bls12381.E2{A0: *ele3, A1: *ele4})
	if e != nil {
		return &G2Affine{}, e
	}
	Q0 = g2.isogeny(Q0)
	Q1 = g2.isogeny(Q1)

	R := g2.AddUnified(Q0, Q1)

	return clearCofactor(g2, fp, R), nil
}

func bytesToElement(api frontend.API, fp *emulated.Field[emulated.BLS12381Fp], data []uints.U8) *emulated.Element[emulated.BLS12381Fp] {
	// data in BE, need to convert to LE
	slices.Reverse(data)

	bits := make([]frontend.Variable, len(data)*8)
	for i := 0; i < len(data); i++ {
		u8 := data[i]
		u8Bits := api.ToBinary(u8.Val, 8)
		for j := 0; j < 8; j++ {
			bits[i*8+j] = u8Bits[j]
		}
	}

	cutoff := 17
	tailBits, headBits := bits[:cutoff*8], bits[cutoff*8:]
	tail := fp.FromBits(tailBits...)
	head := fp.FromBits(headBits...)

	byteMultiplier := big.NewInt(256)
	headMultiplier := byteMultiplier.Exp(byteMultiplier, big.NewInt(int64(cutoff)), big.NewInt(0))
	head = fp.MulConst(head, headMultiplier)

	return fp.Add(head, tail)
}

type g2Polynomial []fields_bls12381.E2

type isogeny struct {
	x_numerator, x_denominator, y_numerator, y_denominator g2Polynomial
}

func newIsogeny() *isogeny {
	return &isogeny{
		x_numerator: g2Polynomial([]fields_bls12381.E2{
			*e2FromStrings(
				"889424345604814976315064405719089812568196182208668418962679585805340366775741747653930584250892369786198727235542",
				"889424345604814976315064405719089812568196182208668418962679585805340366775741747653930584250892369786198727235542"),
			*e2FromStrings(
				"0",
				"2668273036814444928945193217157269437704588546626005256888038757416021100327225242961791752752677109358596181706522"),
			*e2FromStrings(
				"2668273036814444928945193217157269437704588546626005256888038757416021100327225242961791752752677109358596181706526",
				"1334136518407222464472596608578634718852294273313002628444019378708010550163612621480895876376338554679298090853261"),
			*e2FromStrings(
				"3557697382419259905260257622876359250272784728834673675850718343221361467102966990615722337003569479144794908942033",
				"0"),
		}),
		x_denominator: g2Polynomial([]fields_bls12381.E2{
			*e2FromStrings(
				"0",
				"4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559715"),
			*e2FromStrings(
				"12",
				"4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559775"),
			*e2FromStrings(
				"1",
				"0"),
		}),
		y_numerator: g2Polynomial([]fields_bls12381.E2{
			*e2FromStrings(
				"3261222600550988246488569487636662646083386001431784202863158481286248011511053074731078808919938689216061999863558",
				"3261222600550988246488569487636662646083386001431784202863158481286248011511053074731078808919938689216061999863558"),
			*e2FromStrings(
				"0",
				"889424345604814976315064405719089812568196182208668418962679585805340366775741747653930584250892369786198727235518"),
			*e2FromStrings(
				"2668273036814444928945193217157269437704588546626005256888038757416021100327225242961791752752677109358596181706524",
				"1334136518407222464472596608578634718852294273313002628444019378708010550163612621480895876376338554679298090853263"),
			*e2FromStrings(
				"2816510427748580758331037284777117739799287910327449993381818688383577828123182200904113516794492504322962636245776",
				"0"),
		}),
		y_denominator: g2Polynomial([]fields_bls12381.E2{
			*e2FromStrings(
				"4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559355",
				"4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559355"),
			*e2FromStrings(
				"0",
				"4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559571"),
			*e2FromStrings(
				"18",
				"4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559769"),
			*e2FromStrings(
				"1",
				"0"),
		}),
	}
}

func e2FromStrings(x, y string) *fields_bls12381.E2 {
	A0, _ := new(big.Int).SetString(x, 10)
	A1, _ := new(big.Int).SetString(y, 10)

	a0 := emulated.ValueOf[emulated.BLS12381Fp](A0)
	a1 := emulated.ValueOf[emulated.BLS12381Fp](A1)

	return &fields_bls12381.E2{A0: a0, A1: a1}
}

// Follow RFC 9380 Apendix G.3 to compute efficiently.
func clearCofactor(g2 *G2, fp *emulated.Field[emparams.BLS12381Fp], p *G2Affine) *G2Affine {
	// Steps:
	// 1.  t1 = c1 * P
	// c1 = -15132376222941642752
	t1 := g2.scalarMulBySeed(p)
	// 2.  t2 = psi(P)
	t2 := g2.psi(p)
	// 3.  t3 = 2 * P
	t3 := g2.double(p)
	// 4.  t3 = psi2(t3)
	t3 = g2.psi2(t3)
	// 5.  t3 = t3 - t2
	t3 = g2.sub(t3, t2)
	// 6.  t2 = t1 + t2
	t2 = g2.AddUnified(t1, t2)
	// 7.  t2 = c1 * t2
	t2 = g2.scalarMulBySeed(t2)
	// 8.  t3 = t3 + t2
	t3 = g2.AddUnified(t3, t2)
	// 9.  t3 = t3 - t1
	t3 = g2.sub(t3, t1)
	// 10.  Q = t3 - P
	Q := g2.sub(t3, p)
	// 11. return Q
	return Q
}
