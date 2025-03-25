package sw_bls12381

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

func init() {
	solver.RegisterHint(g1SqrtRatioHint)
}

type FpApi = emulated.Field[emulated.BLS12381Fp]
type FpElement = emulated.Element[emulated.BLS12381Fp]

func g1IsogenyXNumerator(api *FpApi, x *FpElement) (*FpElement, error) {

	return g1EvalPolynomial(
		api,
		false,
		[]FpElement{
			emulated.ValueOf[emulated.BLS12381Fp]("0x11a05f2b1e833340b809101dd99815856b303e88a2d7005ff2627b56cdb4e2c85610c2d5f2e62d6eaeac1662734649b7"),
			emulated.ValueOf[emulated.BLS12381Fp]("0x17294ed3e943ab2f0588bab22147a81c7c17e75b2f6a8417f565e33c70d1e86b4838f2a6f318c356e834eef1b3cb83bb"),
			emulated.ValueOf[emulated.BLS12381Fp]("0xd54005db97678ec1d1048c5d10a9a1bce032473295983e56878e501ec68e25c958c3e3d2a09729fe0179f9dac9edcb0"),
			emulated.ValueOf[emulated.BLS12381Fp]("0x1778e7166fcc6db74e0609d307e55412d7f5e4656a8dbf25f1b33289f1b330835336e25ce3107193c5b388641d9b6861"),
			emulated.ValueOf[emulated.BLS12381Fp]("0xe99726a3199f4436642b4b3e4118e5499db995a1257fb3f086eeb65982fac18985a286f301e77c451154ce9ac8895d9"),
			emulated.ValueOf[emulated.BLS12381Fp]("0x1630c3250d7313ff01d1201bf7a74ab5db3cb17dd952799b9ed3ab9097e68f90a0870d2dcae73d19cd13c1c66f652983"),
			emulated.ValueOf[emulated.BLS12381Fp]("0xd6ed6553fe44d296a3726c38ae652bfb11586264f0f8ce19008e218f9c86b2a8da25128c1052ecaddd7f225a139ed84"),
			emulated.ValueOf[emulated.BLS12381Fp]("0x17b81e7701abdbe2e8743884d1117e53356de5ab275b4db1a682c62ef0f2753339b7c8f8c8f475af9ccb5618e3f0c88e"),
			emulated.ValueOf[emulated.BLS12381Fp]("0x80d3cf1f9a78fc47b90b33563be990dc43b756ce79f5574a2c596c928c5d1de4fa295f296b74e956d71986a8497e317"),
			emulated.ValueOf[emulated.BLS12381Fp]("0x169b1f8e1bcfa7c42e0c37515d138f22dd2ecb803a0c5c99676314baf4bb1b7fa3190b2edc0327797f241067be390c9e"),
			emulated.ValueOf[emulated.BLS12381Fp]("0x10321da079ce07e272d8ec09d2565b0dfa7dccdde6787f96d50af36003b14866f69b771f8c285decca67df3f1605fb7b"),
			emulated.ValueOf[emulated.BLS12381Fp]("0x6e08c248e260e70bd1e962381edee3d31d79d7e22c837bc23c0bf1bc24c6b68c24b1b80b64d391fa9c8ba2e8ba2d229"),
		},
		x)
}

func g1IsogenyXDenominator(api *FpApi, x *FpElement) (*FpElement, error) {

	return g1EvalPolynomial(
		api,
		true,
		[]FpElement{
			emulated.ValueOf[emulated.BLS12381Fp]("0x8ca8d548cff19ae18b2e62f4bd3fa6f01d5ef4ba35b48ba9c9588617fc8ac62b558d681be343df8993cf9fa40d21b1c"),
			emulated.ValueOf[emulated.BLS12381Fp]("0x12561a5deb559c4348b4711298e536367041e8ca0cf0800c0126c2588c48bf5713daa8846cb026e9e5c8276ec82b3bff"),
			emulated.ValueOf[emulated.BLS12381Fp]("0xb2962fe57a3225e8137e629bff2991f6f89416f5a718cd1fca64e00b11aceacd6a3d0967c94fedcfcc239ba5cb83e19"),
			emulated.ValueOf[emulated.BLS12381Fp]("0x3425581a58ae2fec83aafef7c40eb545b08243f16b1655154cca8abc28d6fd04976d5243eecf5c4130de8938dc62cd8"),
			emulated.ValueOf[emulated.BLS12381Fp]("0x13a8e162022914a80a6f1d5f43e7a07dffdfc759a12062bb8d6b44e833b306da9bd29ba81f35781d539d395b3532a21e"),
			emulated.ValueOf[emulated.BLS12381Fp]("0xe7355f8e4e667b955390f7f0506c6e9395735e9ce9cad4d0a43bcef24b8982f7400d24bc4228f11c02df9a29f6304a5"),
			emulated.ValueOf[emulated.BLS12381Fp]("0x772caacf16936190f3e0c63e0596721570f5799af53a1894e2e073062aede9cea73b3538f0de06cec2574496ee84a3a"),
			emulated.ValueOf[emulated.BLS12381Fp]("0x14a7ac2a9d64a8b230b3f5b074cf01996e7f63c21bca68a81996e1cdf9822c580fa5b9489d11e2d311f7d99bbdcc5a5e"),
			emulated.ValueOf[emulated.BLS12381Fp]("0xa10ecf6ada54f825e920b3dafc7a3cce07f8d1d7161366b74100da67f39883503826692abba43704776ec3a79a1d641"),
			emulated.ValueOf[emulated.BLS12381Fp]("0x95fc13ab9e92ad4476d6e3eb3a56680f682b4ee96f7d03776df533978f31c1593174e4b4b7865002d6384d168ecdd0a"),
		},
		x)
}

func g1IsogenyYNumerator(api *FpApi, x, y *FpElement) (*FpElement, error) {

	ix, err := g1EvalPolynomial(
		api,
		false,
		[]FpElement{
			emulated.ValueOf[emulated.BLS12381Fp]("0x90d97c81ba24ee0259d1f094980dcfa11ad138e48a869522b52af6c956543d3cd0c7aee9b3ba3c2be9845719707bb33"),
			emulated.ValueOf[emulated.BLS12381Fp]("0x134996a104ee5811d51036d776fb46831223e96c254f383d0f906343eb67ad34d6c56711962fa8bfe097e75a2e41c696"),
			emulated.ValueOf[emulated.BLS12381Fp]("0xcc786baa966e66f4a384c86a3b49942552e2d658a31ce2c344be4b91400da7d26d521628b00523b8dfe240c72de1f6"),
			emulated.ValueOf[emulated.BLS12381Fp]("0x1f86376e8981c217898751ad8746757d42aa7b90eeb791c09e4a3ec03251cf9de405aba9ec61deca6355c77b0e5f4cb"),
			emulated.ValueOf[emulated.BLS12381Fp]("0x8cc03fdefe0ff135caf4fe2a21529c4195536fbe3ce50b879833fd221351adc2ee7f8dc099040a841b6daecf2e8fedb"),
			emulated.ValueOf[emulated.BLS12381Fp]("0x16603fca40634b6a2211e11db8f0a6a074a7d0d4afadb7bd76505c3d3ad5544e203f6326c95a807299b23ab13633a5f0"),
			emulated.ValueOf[emulated.BLS12381Fp]("0x4ab0b9bcfac1bbcb2c977d027796b3ce75bb8ca2be184cb5231413c4d634f3747a87ac2460f415ec961f8855fe9d6f2"),
			emulated.ValueOf[emulated.BLS12381Fp]("0x987c8d5333ab86fde9926bd2ca6c674170a05bfe3bdd81ffd038da6c26c842642f64550fedfe935a15e4ca31870fb29"),
			emulated.ValueOf[emulated.BLS12381Fp]("0x9fc4018bd96684be88c9e221e4da1bb8f3abd16679dc26c1e8b6e6a1f20cabe69d65201c78607a360370e577bdba587"),
			emulated.ValueOf[emulated.BLS12381Fp]("0xe1bba7a1186bdb5223abde7ada14a23c42a0ca7915af6fe06985e7ed1e4d43b9b3f7055dd4eba6f2bafaaebca731c30"),
			emulated.ValueOf[emulated.BLS12381Fp]("0x19713e47937cd1be0dfd0b8f1d43fb93cd2fcbcb6caf493fd1183e416389e61031bf3a5cce3fbafce813711ad011c132"),
			emulated.ValueOf[emulated.BLS12381Fp]("0x18b46a908f36f6deb918c143fed2edcc523559b8aaf0c2462e6bfe7f911f643249d9cdf41b44d606ce07c8a4d0074d8e"),
			emulated.ValueOf[emulated.BLS12381Fp]("0xb182cac101b9399d155096004f53f447aa7b12a3426b08ec02710e807b4633f06c851c1919211f20d4c04f00b971ef8"),
			emulated.ValueOf[emulated.BLS12381Fp]("0x245a394ad1eca9b72fc00ae7be315dc757b3b080d4c158013e6632d3c40659cc6cf90ad1c232a6442d9d3f5db980133"),
			emulated.ValueOf[emulated.BLS12381Fp]("0x5c129645e44cf1102a159f748c4a3fc5e673d81d7e86568d9ab0f5d396a7ce46ba1049b6579afb7866b1e715475224b"),
			emulated.ValueOf[emulated.BLS12381Fp]("0x15e6be4e990f03ce4ea50b3b42df2eb5cb181d8f84965a3957add4fa95af01b2b665027efec01c7704b456be69c8b604"),
		},
		x)
	if err != nil {
		return ix, err
	}

	ix = api.Mul(ix, y)
	return ix, nil
}

func g1IsogenyYDenominator(api *FpApi, x *FpElement) (*FpElement, error) {

	return g1EvalPolynomial(
		api,
		true,
		[]FpElement{
			emulated.ValueOf[emulated.BLS12381Fp]("0x16112c4c3a9c98b252181140fad0eae9601a6de578980be6eec3232b5be72e7a07f3688ef60c206d01479253b03663c1"),
			emulated.ValueOf[emulated.BLS12381Fp]("0x1962d75c2381201e1a0cbd6c43c348b885c84ff731c4d59ca4a10356f453e01f78a4260763529e3532f6102c2e49a03d"),
			emulated.ValueOf[emulated.BLS12381Fp]("0x58df3306640da276faaae7d6e8eb15778c4855551ae7f310c35a5dd279cd2eca6757cd636f96f891e2538b53dbf67f2"),
			emulated.ValueOf[emulated.BLS12381Fp]("0x16b7d288798e5395f20d23bf89edb4d1d115c5dbddbcd30e123da489e726af41727364f2c28297ada8d26d98445f5416"),
			emulated.ValueOf[emulated.BLS12381Fp]("0xbe0e079545f43e4b00cc912f8228ddcc6d19c9f0f69bbb0542eda0fc9dec916a20b15dc0fd2ededda39142311a5001d"),
			emulated.ValueOf[emulated.BLS12381Fp]("0x8d9e5297186db2d9fb266eaac783182b70152c65550d881c5ecd87b6f0f5a6449f38db9dfa9cce202c6477faaf9b7ac"),
			emulated.ValueOf[emulated.BLS12381Fp]("0x166007c08a99db2fc3ba8734ace9824b5eecfdfa8d0cf8ef5dd365bc400a0051d5fa9c01a58b1fb93d1a1399126a775c"),
			emulated.ValueOf[emulated.BLS12381Fp]("0x16a3ef08be3ea7ea03bcddfabba6ff6ee5a4375efa1f4fd7feb34fd206357132b920f5b00801dee460ee415a15812ed9"),
			emulated.ValueOf[emulated.BLS12381Fp]("0x1866c8ed336c61231a1be54fd1d74cc4f9fb0ce4c6af5920abc5750c4bf39b4852cfe2f7bb9248836b233d9d55535d4a"),
			emulated.ValueOf[emulated.BLS12381Fp]("0x167a55cda70a6e1cea820597d94a84903216f763e13d87bb5308592e7ea7d4fbc7385ea3d529b35e346ef48bb8913f55"),
			emulated.ValueOf[emulated.BLS12381Fp]("0x4d2f259eea405bd48f010a01ad2911d9c6dd039bb61a6290e591b36e636a5c871a5c29f4f83060400f8b49cba8f6aa8"),
			emulated.ValueOf[emulated.BLS12381Fp]("0xaccbb67481d033ff5852c1e48c50c477f94ff8aefce42d28c0f9a88cea7913516f968986f7ebbea9684b529e2561092"),
			emulated.ValueOf[emulated.BLS12381Fp]("0xad6b9514c767fe3c3613144b45f1496543346d98adf02267d5ceef9a00d9b8693000763e3b90ac11e99b138573345cc"),
			emulated.ValueOf[emulated.BLS12381Fp]("0x2660400eb2e4f3b628bdd0d53cd76f2bf565b94e72927c1cb748df27942480e420517bd8714cc80d1fadc1326ed06f7"),
			emulated.ValueOf[emulated.BLS12381Fp]("0xe0fa1d816ddc03e6b24255e0d7819c171c40f65e273b853324efcd6356caa205ca2f570f13497804415473a1d634b8f"),
		},
		x)
}

func g1EvalPolynomial(api *FpApi, monic bool, coefficients []FpElement, x *FpElement) (*FpElement, error) {

	var res *FpElement
	if monic {
		res = api.Add(&coefficients[len(coefficients)-1], x)
	} else {
		res = &coefficients[len(coefficients)-1]
	}

	for i := len(coefficients) - 2; i >= 0; i-- {
		res = api.Mul(res, x)
		res = api.Add(res, &coefficients[i])
	}
	return res, nil

}

func g1Isogeny(fpApi *FpApi, p *G1Affine) (*G1Affine, error) {

	den := make([]*FpElement, 2)
	var err error

	den[1], err = g1IsogenyYDenominator(fpApi, &p.X)
	if err != nil {
		return nil, err
	}
	den[0], err = g1IsogenyXDenominator(fpApi, &p.X)
	if err != nil {
		return nil, err
	}

	y, err := g1IsogenyYNumerator(fpApi, &p.X, &p.Y)
	if err != nil {
		return nil, err
	}
	x, err := g1IsogenyXNumerator(fpApi, &p.X)
	if err != nil {
		return nil, err
	}

	x = fpApi.Div(x, den[0])
	y = fpApi.Div(y, den[1])

	return &G1Affine{X: *x, Y: *y}, nil

}

// g1SqrtRatio computes the square root of u/v and returns 0 iff u/v was indeed a quadratic residue
// if not, we get sqrt(Z * u / v). Recall that Z is non-residue
// If v = 0, u/v is meaningless and the output is unspecified, without raising an error.
// The main idea is that since the computation of the square root involves taking large powers of u/v, the inversion of v can be avoided.
//
// nativeInputs[0] = u, nativeInputs[1]=v
// nativeOutput[1] = 1 if u/v is a QR, 0 otherwise, nativeOutput[1]=sqrt(u/v) or sqrt(Z u/v)
func g1SqrtRatioHint(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
	return emulated.UnwrapHint(nativeInputs, nativeOutputs,
		func(mod *big.Int, inputs, outputs []*big.Int) error {

			var z, u, v fp.Element

			u.SetBigInt(inputs[0])
			v.SetBigInt(inputs[1])

			// https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-16.html#name-optimized-sqrt_ratio-for-q- (3 mod 4)
			var tv1 fp.Element
			tv1.Square(&v) // 1. tv1 = v²

			var tv2 fp.Element
			tv2.Mul(&u, &v)     // 2. tv2 = u * v
			tv1.Mul(&tv1, &tv2) // 3. tv1 = tv1 * tv2

			var y1 fp.Element
			{
				var c1 big.Int
				// c1 = 1000602388805416848354447456433976039139220704984751971333014534031007912622709466110671907282253916009473568139946
				c1.SetBytes([]byte{6, 128, 68, 122, 142, 95, 249, 166, 146, 198, 233, 237, 144, 210, 235, 53, 217, 29, 210, 225, 60, 225, 68, 175, 217, 204, 52, 168, 61, 172, 61, 137, 7, 170, 255, 255, 172, 84, 255, 255, 238, 127, 191, 255, 255, 255, 234, 170}) // c1 = (q - 3) / 4     # Integer arithmetic

				y1.Exp(tv1, &c1) // 4. y1 = tv1ᶜ¹
			}

			y1.Mul(&y1, &tv2) // 5. y1 = y1 * tv2

			var y2 fp.Element
			// c2 = sqrt(-Z)
			tv3 := fp.Element{17544630987809824292, 17306709551153317753, 8299808889594647786, 5930295261504720397, 675038575008112577, 167386374569371918}
			y2.Mul(&y1, &tv3)              // 6. y2 = y1 * c2
			tv3.Square(&y1)                // 7. tv3 = y1²
			tv3.Mul(&tv3, &v)              // 8. tv3 = tv3 * v
			isQNr := tv3.NotEqual(&u)      // 9. isQR = tv3 == u
			z.Select(int(isQNr), &y1, &y2) // 10. y = CMOV(y2, y1, isQR)

			if isQNr != 0 {
				isQNr = 1
			}
			z.BigInt(outputs[0])
			outputs[1] = big.NewInt(int64(isQNr))

			return nil
		})
}

// g1Sgn0 returns the parity of a
func g1Sgn0(api *FpApi, a *FpElement) frontend.Variable {
	aReduced := api.Reduce(a)
	ab := api.ToBits(aReduced)
	return ab[0]
}

func ClearCofactor(g *G1, q *G1Affine) (*G1Affine, error) {

	// cf https://eprint.iacr.org/2019/403.pdf, 5

	// mulBySeed
	z := g.double(q)
	z = g.add(z, q)
	z = g.double(z)
	z = g.doubleAndAdd(z, q)
	z = g.doubleN(z, 2)
	z = g.doubleAndAdd(z, q)
	z = g.doubleN(z, 8)
	z = g.doubleAndAdd(z, q)
	z = g.doubleN(z, 31)
	z = g.doubleAndAdd(z, q)
	z = g.doubleN(z, 16)

	// Add assign
	z = g.add(z, q)

	return z, nil

}

// https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-16.html#name-simplified-swu-method
// MapToCurve1 implements the SSWU map
// No cofactor clearing or isogeny
func MapToCurve1(api frontend.API, u *FpElement) (*G1Affine, error) {
	one := emulated.ValueOf[emulated.BLS12381Fp]("1")
	eleven := emulated.ValueOf[emulated.BLS12381Fp]("11")

	fpApi, err := emulated.NewField[emulated.BLS12381Fp](api)
	if err != nil {
		return nil, err
	}

	sswuIsoCurveCoeffA := emulated.ValueOf[emulated.BLS12381Fp]("0x144698a3b8e9433d693a02c96d4982b0ea985383ee66a8d8e8981aefd881ac98936f8da0e0f97f5cf428082d584c1d")
	sswuIsoCurveCoeffB := emulated.ValueOf[emulated.BLS12381Fp]("0x12e2908d11688030018b12e8753eee3b2016c1f0f24f4070a0b9c14fcef35ef55a23215a316ceaa5d1cc48e98e172be0")

	tv1 := fpApi.Mul(u, u) // 1.  tv1 = u²

	//mul tv1 by Z ( g1MulByZ)
	tv1 = fpApi.Mul(&eleven, tv1)

	// var tv2 fp.Element
	tv2 := fpApi.Mul(tv1, tv1) // 3.  tv2 = tv1²
	tv2 = fpApi.Add(tv2, tv1)  // 4.  tv2 = tv2 + tv1

	// var tv3 fp.Element
	// var tv4 fp.Element
	tv3 := fpApi.Add(tv2, &one)               // 5.  tv3 = tv2 + 1
	tv3 = fpApi.Mul(tv3, &sswuIsoCurveCoeffB) // 6.  tv3 = B * tv3

	// tv2NZero := g1NotZero(&tv2)
	tv2IsZero := fpApi.IsZero(tv2)

	// tv4 = Z

	tv2 = fpApi.Neg(tv2)                         // tv2.Neg(&tv2)
	tv4 := fpApi.Select(tv2IsZero, &eleven, tv2) // 7.  tv4 = CMOV(Z, -tv2, tv2 != 0)
	tv4 = fpApi.Mul(tv4, &sswuIsoCurveCoeffA)    // 8.  tv4 = A * tv4

	tv2 = fpApi.Mul(tv3, tv3) // 9.  tv2 = tv3²

	tv6 := fpApi.Mul(tv4, tv4) // 10. tv6 = tv4²

	tv5 := fpApi.Mul(tv6, &sswuIsoCurveCoeffA) // 11. tv5 = A * tv6

	tv2 = fpApi.Add(tv2, tv5) // 12. tv2 = tv2 + tv5
	tv2 = fpApi.Mul(tv2, tv3) // 13. tv2 = tv2 * tv3
	tv6 = fpApi.Mul(tv6, tv4) // 14. tv6 = tv6 * tv4

	tv5 = fpApi.Mul(tv6, &sswuIsoCurveCoeffB) // 15. tv5 = B * tv6
	tv2 = fpApi.Add(tv2, tv5)                 // 16. tv2 = tv2 + tv5

	// var x fp.Element
	x := fpApi.Mul(tv1, tv3) // 17.   x = tv1 * tv3

	hint, err := fpApi.NewHint(g1SqrtRatioHint, 2, tv2, tv6)
	if err != nil {
		return nil, err
	}

	// TODO constrain gx1NSquare and y1
	// (gx1NSquare==1 AND (u/v) QNR ) OR (gx1NSquare==0 AND (u/v) QR )
	gx1NSquare := hint[1].Limbs[0]
	y1 := hint[0] // 18. (is_gx1_square, y1) = sqrt_ratio(tv2, tv6)

	// var y fp.Element
	y := fpApi.Mul(tv1, u) // 19.  	 y = tv1 * u

	y = fpApi.Mul(y, y1) // 20.   y = y * y1

	x = fpApi.Select(gx1NSquare, x, tv3) // 21.   x = CMOV(x, tv3, is_gx1_square)
	y = fpApi.Select(gx1NSquare, y, y1)  // 22.   y = CMOV(y, y1, is_gx1_square)

	y1 = fpApi.Neg(y)
	y1 = fpApi.Reduce(y1)
	sel := api.IsZero(api.Sub(g1Sgn0(fpApi, u), g1Sgn0(fpApi, y)))
	y = fpApi.Select(sel, y, y1)

	// // 23.  e1 = sgn0(u) == sgn0(y)
	// // 24.   y = CMOV(-y, y, e1)

	x = fpApi.Div(x, tv4) // 25.   x = x / tv4

	return &G1Affine{X: *x, Y: *y}, nil

}

// MapToG1 invokes the SSWU map, and guarantees that the result is in g1
func MapToG1(api frontend.API, u *FpElement) (*G1Affine, error) {

	res, err := MapToCurve1(api, u)
	if err != nil {
		return nil, err
	}

	//this is in an isogenous curve
	fpApi, err := emulated.NewField[emulated.BLS12381Fp](api)
	if err != nil {
		return nil, err
	}
	z, err := g1Isogeny(fpApi, res)
	if err != nil {
		return nil, err
	}

	g1, err := NewG1(api)
	if err != nil {
		return nil, err
	}

	z, err = ClearCofactor(g1, z)
	if err != nil {
		return nil, err
	}

	return z, nil
}
