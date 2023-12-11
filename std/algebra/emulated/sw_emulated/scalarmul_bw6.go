package sw_emulated

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/std/algebra/algopts"
	"github.com/consensys/gnark/std/math/emulated"
)

func DecomposeScalarG1(mod *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	return UnwrapHint(inputs, outputs, func(field *big.Int, inputs, outputs []*big.Int) error {
		if len(inputs) != 1 {
			return fmt.Errorf("expecting a single input")
		}
		if len(outputs) != 5 {
			return fmt.Errorf("expecting five outputs")
		}
		lambda := new(big.Int)
		lambda.SetString("80949648264912719408558363140637477264845294720710499478137287262712535938301461879813459410945", 10) // (x⁵-3x⁴+3x³-x+1)
		glvBasis := new(ecc.Lattice)
		ecc.PrecomputeLattice(ecc.BW6_761.ScalarField(), lambda, glvBasis)
		sp := ecc.SplitScalar(inputs[0], glvBasis)
		outputs[0].Set(&(sp[0]))
		outputs[1].Set(&(sp[1]))
		// figure out how many times we have overflowed
		outputs[1].Set(&(sp[1]))
		outputs[2].Mul(outputs[1], lambda).Add(outputs[2], outputs[0])
		outputs[2].Sub(outputs[2], inputs[0])
		outputs[2].Div(outputs[2], ecc.BW6_761.ScalarField())

		outputs[3].Set(outputs[0])
		if outputs[0].Sign() == -1 {
			outputs[3].Neg(outputs[0])
		}
		outputs[4].Set(outputs[1])
		if outputs[1].Sign() == -1 {
			outputs[4].Neg(outputs[1])
		}

		return nil
	})
}

func init() {
	solver.RegisterHint(DecomposeScalarG1)
}

// ScalarMulGLV computes s * p using an efficient endomorphism and returns it. It doesn't modify p nor s.
// dirty quick hack that works only for BW6-761
func (c *Curve[B, S]) ScalarMulGLV(Q *AffinePoint[B], s *emulated.Element[S], opts ...algopts.AlgebraOption) *AffinePoint[B] {
	lambda := emulated.ValueOf[S]("80949648264912719408558363140637477264845294720710499478137287262712535938301461879813459410945")
	frModulus := emulated.ValueOf[S]("258664426012969094010652733694893533536393512754914660539884262666720468348340822774968888139573360124440321458177")
	sd, err := c.scalarApi.NewHint(DecomposeScalarG1, 5, s)
	if err != nil {
		panic(fmt.Sprintf("compute GLV decomposition: %v", err))
	}
	s1, s2 := sd[0], sd[1]
	c.scalarApi.AssertIsEqual(
		c.scalarApi.Add(s1, c.scalarApi.Mul(s2, &lambda)),
		c.scalarApi.Add(s, c.scalarApi.Mul(&frModulus, sd[2])),
	)
	var Acc, B1 AffinePoint[B]
	// precompute -Q, -Φ(Q), Φ(Q)
	var tableQ, tablePhiQ [2]AffinePoint[B]
	tableQ[1].X = Q.X
	tableQ[1].Y = *c.baseApi.Select(c.scalarApi.IsZero(c.scalarApi.Sub(sd[3], s1)), &Q.Y, c.baseApi.Neg(&Q.Y))
	tableQ[0] = *c.Neg(&tableQ[1])
	thirdRootOne1 := emulated.ValueOf[B]("1968985824090209297278610739700577151397666382303825728450741611566800370218827257750865013421937292370006175842381275743914023380727582819905021229583192207421122272650305267822868639090213645505120388400344940985710520836292650")
	tablePhiQ[1].X = *c.baseApi.Mul(&Q.X, &thirdRootOne1)
	tablePhiQ[1].Y = *c.baseApi.Select(c.scalarApi.IsZero(c.scalarApi.Sub(sd[4], s2)), &Q.Y, c.baseApi.Neg(&Q.Y))
	tablePhiQ[0] = *c.Neg(&tablePhiQ[1])

	// Acc = Q + Φ(Q)
	Acc = tableQ[1]
	Acc = *c.Add(&tableQ[1], &tablePhiQ[1])

	s1 = c.scalarApi.Select(c.scalarApi.IsZero(c.scalarApi.Sub(sd[3], s1)), s1, sd[3])
	s2 = c.scalarApi.Select(c.scalarApi.IsZero(c.scalarApi.Sub(sd[4], s2)), s2, sd[4])

	s1bits := c.scalarApi.ToBits(s1)
	s2bits := c.scalarApi.ToBits(s2)

	nbits := 190

	for i := nbits - 1; i > 0; i-- {
		B1.X = tableQ[0].X
		B1.Y = *c.baseApi.Select(s1bits[i], &tableQ[1].Y, &tableQ[0].Y)
		Acc = *c.doubleAndAdd(&Acc, &B1)
		B1.X = tablePhiQ[0].X
		B1.Y = *c.baseApi.Select(s2bits[i], &tablePhiQ[1].Y, &tablePhiQ[0].Y)
		Acc = *c.Add(&Acc, &B1)

	}

	tableQ[0] = *c.Add(&tableQ[0], &Acc)
	Acc = *c.Select(s1bits[0], &Acc, &tableQ[0])
	tablePhiQ[0] = *c.Add(&tablePhiQ[0], &Acc)
	Acc = *c.Select(s2bits[0], &Acc, &tablePhiQ[0])

	return &Acc
}

// P = [s]Q + [t]R using Shamir's trick
func (c *Curve[B, S]) jointScalarMulGLV(Q, R *AffinePoint[B], s, t *emulated.Element[S], opts ...algopts.AlgebraOption) *AffinePoint[B] {

	lambda := emulated.ValueOf[S]("80949648264912719408558363140637477264845294720710499478137287262712535938301461879813459410945")
	frModulus := emulated.ValueOf[S]("258664426012969094010652733694893533536393512754914660539884262666720468348340822774968888139573360124440321458177")
	sd, err := c.scalarApi.NewHint(DecomposeScalarG1, 5, s)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}
	s1, s2 := sd[0], sd[1]

	td, err := c.scalarApi.NewHint(DecomposeScalarG1, 5, t)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}
	t1, t2 := td[0], td[1]

	c.scalarApi.AssertIsEqual(
		c.scalarApi.Add(s1, c.scalarApi.Mul(s2, &lambda)),
		c.scalarApi.Add(s, c.scalarApi.Mul(&frModulus, sd[2])),
	)
	c.scalarApi.AssertIsEqual(
		c.scalarApi.Add(t1, c.scalarApi.Mul(t2, &lambda)),
		c.scalarApi.Add(t, c.scalarApi.Mul(&frModulus, td[2])),
	)

	// precompute -Q, -Φ(Q), Φ(Q)
	var tableQ, tablePhiQ [2]AffinePoint[B]
	tableQ[1].X = Q.X
	tableQ[1].Y = *c.baseApi.Select(c.scalarApi.IsZero(c.scalarApi.Sub(sd[3], s1)), &Q.Y, c.baseApi.Neg(&Q.Y))
	tableQ[0] = *c.Neg(&tableQ[1])
	thirdRootOne1 := emulated.ValueOf[B]("1968985824090209297278610739700577151397666382303825728450741611566800370218827257750865013421937292370006175842381275743914023380727582819905021229583192207421122272650305267822868639090213645505120388400344940985710520836292650")
	tablePhiQ[1].X = *c.baseApi.Mul(&Q.X, &thirdRootOne1)
	tablePhiQ[1].Y = *c.baseApi.Select(c.scalarApi.IsZero(c.scalarApi.Sub(sd[4], s2)), &Q.Y, c.baseApi.Neg(&Q.Y))
	tablePhiQ[0] = *c.Neg(&tablePhiQ[1])
	// precompute -R, -Φ(R), Φ(R)
	var tableR, tablePhiR [2]AffinePoint[B]
	tableR[1].X = R.X
	tableR[1].Y = *c.baseApi.Select(c.scalarApi.IsZero(c.scalarApi.Sub(td[3], t1)), &R.Y, c.baseApi.Neg(&R.Y))
	tableR[0] = *c.Neg(&tableR[1])
	tablePhiR[1].X = *c.baseApi.Mul(&R.X, &thirdRootOne1)
	tablePhiR[1].Y = *c.baseApi.Select(c.scalarApi.IsZero(c.scalarApi.Sub(td[4], t2)), &R.Y, c.baseApi.Neg(&R.Y))
	tablePhiR[0] = *c.Neg(&tablePhiR[1])
	// precompute Q+R, -Q-R, Q-R, -Q+R, Φ(Q)+Φ(R), -Φ(Q)-Φ(R), Φ(Q)-Φ(R), -Φ(Q)+Φ(R)
	var tableS, tablePhiS [4]AffinePoint[B]
	tableS[0] = tableQ[0]
	tableS[0] = *c.Add(&tableS[0], &tableR[0])
	tableS[1] = *c.Neg(&tableS[0])
	tableS[2] = tableQ[1]
	tableS[2] = *c.Add(&tableS[2], &tableR[0])
	tableS[3] = *c.Neg(&tableS[2])
	tablePhiS[0] = *c.Add(&tablePhiQ[0], &tablePhiR[0])
	tablePhiS[1] = *c.Add(&tablePhiQ[1], &tablePhiR[1])
	tablePhiS[2] = *c.Add(&tablePhiQ[1], &tablePhiR[0])
	tablePhiS[3] = *c.Add(&tablePhiQ[0], &tablePhiR[1])

	// suppose first bit is 1 and set:
	// Acc = Q + R + Φ(Q) + Φ(R)
	var Acc AffinePoint[B]
	Acc = tableS[1]
	Acc = *c.Add(&Acc, &tablePhiS[1])

	s1 = c.scalarApi.Select(c.scalarApi.IsZero(c.scalarApi.Sub(sd[3], s1)), s1, sd[3])
	s2 = c.scalarApi.Select(c.scalarApi.IsZero(c.scalarApi.Sub(sd[4], s2)), s2, sd[4])
	t1 = c.scalarApi.Select(c.scalarApi.IsZero(c.scalarApi.Sub(td[3], t1)), t1, td[3])
	t2 = c.scalarApi.Select(c.scalarApi.IsZero(c.scalarApi.Sub(td[4], t2)), t2, td[4])

	s1bits := c.scalarApi.ToBits(s1)
	s2bits := c.scalarApi.ToBits(s2)
	t1bits := c.scalarApi.ToBits(t1)
	t2bits := c.scalarApi.ToBits(t2)

	nbits := 190

	// Acc = [2]Acc ± Q ± R ± Φ(Q) ± Φ(R)
	var B1 AffinePoint[B]
	for i := nbits - 1; i > 0; i-- {
		B1.X = *c.baseApi.Select(
			c.api.Xor(s1bits[i], t1bits[i]),
			&tableS[2].X, &tableS[0].X,
		)
		B1.Y = *c.baseApi.Lookup2(
			s1bits[i], t1bits[i],
			&tableS[0].Y, &tableS[2].Y, &tableS[3].Y, &tableS[1].Y,
		)
		Acc = *c.doubleAndAdd(&Acc, &B1)
		B1.X = *c.baseApi.Select(
			c.api.Xor(s2bits[i], t2bits[i]),
			&tablePhiS[2].X, &tablePhiS[0].X,
		)
		B1.Y = *c.baseApi.Lookup2(
			s2bits[i], t2bits[i],
			&tablePhiS[0].Y, &tablePhiS[2].Y, &tablePhiS[3].Y, &tablePhiS[1].Y,
		)
		Acc = *c.Add(&Acc, &B1)
	}

	// i = 0
	// subtract the initial point from the accumulator when first bit was 0
	tableQ[0] = *c.Add(&tableQ[0], &Acc)
	Acc = *c.Select(s1bits[0], &Acc, &tableQ[0])
	tablePhiQ[0] = *c.Add(&tablePhiQ[0], &Acc)
	Acc = *c.Select(s2bits[0], &Acc, &tablePhiQ[0])
	tableR[0] = *c.Add(&tableR[0], &Acc)
	Acc = *c.Select(t1bits[0], &Acc, &tableR[0])
	tablePhiR[0] = *c.Add(&tablePhiR[0], &Acc)
	Acc = *c.Select(t2bits[0], &Acc, &tablePhiR[0])

	return &Acc
}

// UnwrapHint unwraps the native inputs into nonnative inputs. Then it calls
// nonnativeHint function with nonnative inputs. After nonnativeHint returns, it
// decomposes the outputs into limbs.
func UnwrapHint(nativeInputs, nativeOutputs []*big.Int, nonnativeHint solver.Hint) error {
	if len(nativeInputs) < 2 {
		return fmt.Errorf("hint wrapper header is 2 elements")
	}
	if !nativeInputs[0].IsInt64() || !nativeInputs[1].IsInt64() {
		return fmt.Errorf("header must be castable to int64")
	}
	nbBits := int(nativeInputs[0].Int64())
	nbLimbs := int(nativeInputs[1].Int64())
	if len(nativeInputs) < 2+nbLimbs {
		return fmt.Errorf("hint wrapper header is 2+nbLimbs elements")
	}
	nonnativeMod := new(big.Int)
	if err := recompose(nativeInputs[2:2+nbLimbs], uint(nbBits), nonnativeMod); err != nil {
		return fmt.Errorf("cannot recover nonnative mod: %w", err)
	}
	if !nativeInputs[2+nbLimbs].IsInt64() {
		return fmt.Errorf("number of nonnative elements must be castable to int64")
	}
	nbInputs := int(nativeInputs[2+nbLimbs].Int64())
	nonnativeInputs := make([]*big.Int, nbInputs)
	readPtr := 3 + nbLimbs
	for i := 0; i < nbInputs; i++ {
		if len(nativeInputs) < readPtr+1 {
			return fmt.Errorf("can not read %d-th native input", i)
		}
		if !nativeInputs[readPtr].IsInt64() {
			return fmt.Errorf("corrupted %d-th native input", i)
		}
		currentInputLen := int(nativeInputs[readPtr].Int64())
		if len(nativeInputs) < (readPtr + 1 + currentInputLen) {
			return fmt.Errorf("cannot read %d-th nonnative element", i)
		}
		nonnativeInputs[i] = new(big.Int)
		if err := recompose(nativeInputs[readPtr+1:readPtr+1+currentInputLen], uint(nbBits), nonnativeInputs[i]); err != nil {
			return fmt.Errorf("recompose %d-th element: %w", i, err)
		}
		readPtr += 1 + currentInputLen
	}
	if len(nativeOutputs)%nbLimbs != 0 {
		return fmt.Errorf("output count doesn't divide limb count")
	}
	nonnativeOutputs := make([]*big.Int, len(nativeOutputs)/nbLimbs)
	for i := range nonnativeOutputs {
		nonnativeOutputs[i] = new(big.Int)
	}
	if err := nonnativeHint(nonnativeMod, nonnativeInputs, nonnativeOutputs); err != nil {
		return fmt.Errorf("nonnative hint: %w", err)
	}
	for i := range nonnativeOutputs {
		nonnativeOutputs[i].Mod(nonnativeOutputs[i], nonnativeMod)
		if err := decompose(nonnativeOutputs[i], uint(nbBits), nativeOutputs[i*nbLimbs:(i+1)*nbLimbs]); err != nil {
			return fmt.Errorf("decompose %d-th element: %w", i, err)
		}
	}
	return nil
}

// recompose takes the limbs in inputs and combines them into res. It errors if
// inputs is uninitialized or zero-length and if the result is uninitialized.
//
// The following holds
//
//	res = \sum_{i=0}^{len(inputs)} inputs[i] * 2^{nbBits * i}
func recompose(inputs []*big.Int, nbBits uint, res *big.Int) error {
	if len(inputs) == 0 {
		return fmt.Errorf("zero length slice input")
	}
	if res == nil {
		return fmt.Errorf("result not initialized")
	}
	res.SetUint64(0)
	for i := range inputs {
		res.Lsh(res, nbBits)
		res.Add(res, inputs[len(inputs)-i-1])
	}
	// TODO @gbotrel mod reduce ?
	return nil
}

// decompose decomposes the input into res as integers of width nbBits. It
// errors if the decomposition does not fit into res or if res is uninitialized.
//
// The following holds
//
//	input = \sum_{i=0}^{len(res)} res[i] * 2^{nbBits * i}
func decompose(input *big.Int, nbBits uint, res []*big.Int) error {
	// limb modulus
	if input.BitLen() > len(res)*int(nbBits) {
		return fmt.Errorf("decomposed integer does not fit into res")
	}
	for _, r := range res {
		if r == nil {
			return fmt.Errorf("result slice element uninitalized")
		}
	}
	base := new(big.Int).Lsh(big.NewInt(1), nbBits)
	tmp := new(big.Int).Set(input)
	for i := 0; i < len(res); i++ {
		res[i].Mod(tmp, base)
		tmp.Rsh(tmp, nbBits)
	}
	return nil
}
