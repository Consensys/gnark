package bls377

import (
	"math/big"
	"sync"

	"github.com/consensys/gnark/ecc"
	"github.com/consensys/gnark/ecc/bls377/fp"
)

// generate code for field tower, curve groups
// add -testpoints to generate test points using sage
//go:generate go run ../internal/generator.go -out . -package bls377 -t 9586122913090633729 -p 258664426012969094010652733694893533536393512754914660539884262666720468348340822774968888139573360124440321458177 -r 8444461749428370424248824938781546531375899335154063827935233455917409239041 -fp2 5 -fp6 0,1

// E: y**2=x**3+1
// Etwist: y**2 = x**3+u**-1

var bls377 Curve
var initOnce sync.Once

// ID bls377 ID
const ID = ecc.BLS377

// parameters for pippenger ScalarMulByGen
const sGen = 4
const bGen = sGen

type PairingResult = e12

// BLS377 returns BLS377 curve
func BLS377() *Curve {
	initOnce.Do(initBLS377)
	return &bls377
}

// Curve represents the BLS377 curve and pre-computed constants
type Curve struct {
	B fp.Element // A, B coefficients of the curve x^3 = y^2 +AX+b

	g1Gen G1Jac // generator of torsion group G1Jac
	g2Gen G2Jac // generator of torsion group G2Jac

	g1Infinity G1Jac // infinity (in Jacobian coords)
	g2Infinity G2Jac

	// TODO store this number as a MAX_SIZE constant, or with build tags
	loopCounter [64]int8 // NAF decomposition of t-1, t is the trace of the Frobenius restricted on the r torsion group

	// precomputed values for ScalarMulByGen
	tGenG1 [((1 << bGen) - 1)]G1Jac
	tGenG2 [((1 << bGen) - 1)]G2Jac
}

func initBLS377() {

	// A, B coeffs of the curve in Mont form
	bls377.B.SetUint64(4)

	// Setting G1Jac
	bls377.g1Gen.X.SetString("68333130937826953018162399284085925021577172705782285525244777453303237942212457240213897533859360921141590695983")
	bls377.g1Gen.Y.SetString("243386584320553125968203959498080829207604143167922579970841210259134422887279629198736754149500839244552761526603")
	bls377.g1Gen.Z.SetString("1")

	// Setting G2Jac
	bls377.g2Gen.X.SetString("129200027147742761118726589615458929865665635908074731940673005072449785691019374448547048953080140429883331266310",
		"218164455698855406745723400799886985937129266327098023241324696183914328661520330195732120783615155502387891913936")
	bls377.g2Gen.Y.SetString("178797786102020318006939402153521323286173305074858025240458924050651930669327663166574060567346617543016897467207",
		"246194676937700783734853490842104812127151341609821057456393698060154678349106147660301543343243364716364400889778")
	bls377.g2Gen.Z.SetString("1",
		"0")

	// Setting the loop counter for Miller loop in NAF form
	T, _ := new(big.Int).SetString("9586122913090633729", 10)
	ecc.NafDecomposition(T, bls377.loopCounter[:])

	// infinity point G1
	bls377.g1Infinity.X.SetOne()
	bls377.g1Infinity.Y.SetOne()

	// infinity point G2
	bls377.g2Infinity.X.SetOne()
	bls377.g2Infinity.Y.SetOne()

	// precomputed values for ScalarMulByGen
	bls377.tGenG1[0].Set(&bls377.g1Gen)
	for j := 1; j < len(bls377.tGenG1)-1; j = j + 2 {
		bls377.tGenG1[j].Set(&bls377.tGenG1[j/2]).Double()
		bls377.tGenG1[j+1].Set(&bls377.tGenG1[(j+1)/2]).Add(&bls377, &bls377.tGenG1[j/2])
	}
	bls377.tGenG2[0].Set(&bls377.g2Gen)
	for j := 1; j < len(bls377.tGenG2)-1; j = j + 2 {
		bls377.tGenG2[j].Set(&bls377.tGenG2[j/2]).Double()
		bls377.tGenG2[j+1].Set(&bls377.tGenG2[(j+1)/2]).Add(&bls377, &bls377.tGenG2[j/2])
	}
}
