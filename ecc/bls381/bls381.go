package bls381

import (
	"math/big"
	"sync"

	"github.com/consensys/gnark/ecc"
	"github.com/consensys/gnark/ecc/bls381/fp"
)

// generate code for field tower, curve groups
// add -testpoints to generate test points using sage
// TODO g1_test.go, g2_test.go tests currently fail---just delete those files
//go:generate go run ../internal/generator.go -out . -package bls381 -t 15132376222941642752 -tNeg -p 4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787 -r 52435875175126190479447740508185965837690552500527637822603658699938581184513 -fp2 -1 -fp6 1,1

// E: y**2=x**3+4
// Etwist: y**2 = x**3+4*(u+1)

var bls381 Curve
var initOnce sync.Once

// ID bls381 ID
const ID = ecc.BLS381

// parameters for pippenger ScalarMulByGen
const sGen = 4
const bGen = sGen

type PairingResult = e12

// BLS381 returns BLS381 curve
func BLS381() *Curve {
	initOnce.Do(initBLS381)
	return &bls381
}

// Curve represents the BLS381 curve and pre-computed constants
type Curve struct {
	B fp.Element // A, B coefficients of the curve x^3 = y^2 +AX+b

	g1Gen G1Jac // generator of torsion group G1Jac
	g2Gen G2Jac // generator of torsion group G2Jac

	g1Infinity G1Jac // infinity (in Jacobian coords)
	g2Infinity G2Jac

	// TODO store this number as a MAX_SIZE constant, or with build tags
	// NAF decomposition takes 65 trits for bls381 but only 64 trits for bls377
	loopCounter [65]int8 // NAF decomposition of t-1, t is the trace of the Frobenius

	// precomputed values for ScalarMulByGen
	tGenG1 [((1 << bGen) - 1)]G1Jac
	tGenG2 [((1 << bGen) - 1)]G2Jac
}

func initBLS381() {

	// A, B coeffs of the curve in Mont form
	bls381.B.SetUint64(4)

	// Setting G1Jac
	bls381.g1Gen.X.SetString("2407661716269791519325591009883849385849641130669941829988413640673772478386903154468379397813974815295049686961384")
	bls381.g1Gen.Y.SetString("821462058248938975967615814494474302717441302457255475448080663619194518120412959273482223614332657512049995916067")
	bls381.g1Gen.Z.SetString("1")

	// Setting G2Jac
	bls381.g2Gen.X.SetString("3914881020997020027725320596272602335133880006033342744016315347583472833929664105802124952724390025419912690116411",
		"277275454976865553761595788585036366131740173742845697399904006633521909118147462773311856983264184840438626176168")
	bls381.g2Gen.Y.SetString("253800087101532902362860387055050889666401414686580130872654083467859828854605749525591159464755920666929166876282",
		"1710145663789443622734372402738721070158916073226464929008132596760920130516982819361355832232719175024697380252309")
	bls381.g2Gen.Z.SetString("1",
		"0")

	// Setting the loop counter for Miller loop in NAF form
	// we can take |T|, see section C https://eprint.iacr.org/2008/096.pdf
	T, _ := new(big.Int).SetString("15132376222941642752", 10)
	ecc.NafDecomposition(T, bls381.loopCounter[:])

	// infinity point G1
	bls381.g1Infinity.X.SetOne()
	bls381.g1Infinity.Y.SetOne()

	// infinity point G2
	bls381.g2Infinity.X.SetOne()
	bls381.g2Infinity.Y.SetOne()

	// precomputed values for ScalarMulByGen
	bls381.tGenG1[0].Set(&bls381.g1Gen)
	for j := 1; j < len(bls381.tGenG1)-1; j = j + 2 {
		bls381.tGenG1[j].Set(&bls381.tGenG1[j/2]).Double()
		bls381.tGenG1[j+1].Set(&bls381.tGenG1[(j+1)/2]).Add(&bls381, &bls381.tGenG1[j/2])
	}
	bls381.tGenG2[0].Set(&bls381.g2Gen)
	for j := 1; j < len(bls381.tGenG2)-1; j = j + 2 {
		bls381.tGenG2[j].Set(&bls381.tGenG2[j/2]).Double()
		bls381.tGenG2[j+1].Set(&bls381.tGenG2[(j+1)/2]).Add(&bls381, &bls381.tGenG2[j/2])
	}
}
