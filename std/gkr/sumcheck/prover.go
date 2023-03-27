package sumcheck

import (
	"github.com/consensys/gnark/std/gkr/circuit"
	"github.com/consensys/gnark/std/gkr/common"
	"github.com/consensys/gnark/std/gkr/polynomial"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// Proof is the object produced by the prover
type Proof struct {
	PolyCoeffs [][]fr.Element
}

// SingleThreadedProver computes the
type SingleThreadedProver struct {
	// Contains the values of the previous layer
	vL polynomial.BookKeepingTable
	vR polynomial.BookKeepingTable
	// Contains the static tables defining the circuit structure
	eq           polynomial.BookKeepingTable
	gates        []circuit.Gate
	staticTables []polynomial.BookKeepingTable
	// Degrees for the differents variables
	degreeHL     int
	degreeHR     int
	degreeHPrime int
}

// NewSingleThreadedProver constructs a new prover
func NewSingleThreadedProver(
	vL polynomial.BookKeepingTable,
	vR polynomial.BookKeepingTable,
	eq polynomial.BookKeepingTable,
	gates []circuit.Gate,
	staticTables []polynomial.BookKeepingTable,
) SingleThreadedProver {
	// Auto-computes the degree on each variables
	degreeHL, degreeHR, degreeHPrime := 0, 0, 0
	for _, gate := range gates {
		dL, dR, dPrime := gate.Degrees()
		degreeHL = common.Max(degreeHL, dL)
		degreeHR = common.Max(degreeHR, dR)
		degreeHPrime = common.Max(degreeHPrime, dPrime)
	}
	return SingleThreadedProver{
		vL:           vL,
		vR:           vR,
		eq:           eq,
		gates:        gates,
		staticTables: staticTables,
		degreeHL:     degreeHL + 1,
		degreeHR:     degreeHR + 1,
		degreeHPrime: degreeHPrime + 1,
	}
}

// Prove runs the prover of a sumcheck
func (p *SingleThreadedProver) Prove() (proof Proof, qPrime, qL, qR, finalClaims []fr.Element) {

	// Define usefull constants
	n := len(p.eq.Table)     // Number of subcircuit. Since we haven't fold on h' yet
	g := len(p.vR.Table) / n // SubCircuit size. Since we haven't fold on hR yet
	bN := common.Log2Ceil(n)
	bG := common.Log2Ceil(g)

	// Initialized the results
	proof.PolyCoeffs = make([][]fr.Element, bN+2*bG)
	qPrime = make([]fr.Element, bN)
	qL = make([]fr.Element, bG)
	qR = make([]fr.Element, bG)
	finalClaims = make([]fr.Element, 3+len(p.staticTables))

	// Run on hL
	for i := 0; i < bG; i++ {
		evals := p.GetEvalsOnHL()
		proof.PolyCoeffs[i] = polynomial.InterpolateOnRange(evals)
		r := common.GetChallenge(proof.PolyCoeffs[i])
		p.FoldHL(r)
		qL[i] = r
	}

	// Run on hR
	for i := bG; i < 2*bG; i++ {
		evals := p.GetEvalsOnHR()
		proof.PolyCoeffs[i] = polynomial.InterpolateOnRange(evals)
		r := common.GetChallenge(proof.PolyCoeffs[i])
		p.FoldHR(r)
		qR[i-bG] = r
	}

	// Run on hPrime
	for i := 2 * bG; i < bN+2*bG; i++ {
		evals := p.GetEvalsOnHPrime()
		proof.PolyCoeffs[i] = polynomial.InterpolateOnRange(evals)
		r := common.GetChallenge(proof.PolyCoeffs[i])
		p.FoldHPrime(r)
		qPrime[i-2*bG] = r
	}

	finalClaims[0] = p.vL.Table[0]
	finalClaims[1] = p.vR.Table[0]
	finalClaims[2] = p.eq.Table[0]
	for i, bkt := range p.staticTables {
		finalClaims[3+i] = bkt.Table[0]
	}

	return proof, qPrime, qL, qR, finalClaims
}

// FoldHL folds on the first variable of hR
func (p *SingleThreadedProver) FoldHL(r fr.Element) {
	for i := range p.staticTables {
		p.staticTables[i].Fold(r)
	}
	p.vL.Fold(r)
}

// FoldHR folds on the first variable of hR
func (p *SingleThreadedProver) FoldHR(r fr.Element) {
	for i := range p.staticTables {
		p.staticTables[i].Fold(r)
	}
	p.vR.Fold(r)
}

// FoldHPrime folds on the first variable of Eq
func (p *SingleThreadedProver) FoldHPrime(r fr.Element) {
	p.vR.Fold(r)
	p.vL.Fold(r)
	p.eq.Fold(r)
}
