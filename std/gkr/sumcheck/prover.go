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
