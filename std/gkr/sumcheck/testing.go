package sumcheck

import (
	"github.com/consensys/gnark/std/gkr/circuit"
	"github.com/consensys/gnark/std/gkr/polynomial"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// InitializeMultiThreadedProver creates a test prover that is multithreaded
// and holds the same values as the single threaded prover
func InitializeMultiThreadedProver(bN, nChunks int) MultiThreadedProver {
	var zero, one, two fr.Element
	one.SetOne()
	two.SetUint64(2)

	// Fold for q', q = [2, 2, 2 ,2 ...] 2
	// cipher: q = 0, qL = 1, qR = 0
	// copy: q = 1, qL = 1, qR = 0
	qPrime := make([]fr.Element, bN)
	for i := range qPrime {
		qPrime[i] = two
	}

	eq := polynomial.GetChunkedEqTable(qPrime, nChunks, 1)
	cipher := polynomial.NewBookKeepingTable([]fr.Element{zero, zero, one, zero, zero, zero, zero, zero})
	copy := polynomial.NewBookKeepingTable([]fr.Element{zero, zero, zero, zero, zero, zero, one, zero})
	cipher.Fold(two)
	copy.Fold(two)

	vL := make([]polynomial.BookKeepingTable, nChunks)
	vR := make([]polynomial.BookKeepingTable, nChunks)
	for k := range vL {
		// Initialize the values of V
		v := make([]fr.Element, (1<<(bN+1))/nChunks)
		for i := range v {
			v[i].SetUint64(uint64(k + nChunks*i))
		}
		vL[k] = polynomial.NewBookKeepingTable(v)
		vR[k] = vL[k].DeepCopy()
	}

	return NewMultiThreadedProver(
		vL, vR, eq,
		[]circuit.Gate{circuit.CopyGate{}, &circuit.CipherGate{Ark: two}},
		[]polynomial.BookKeepingTable{copy, cipher},
	)
}

// InitializeProverForTests creates a test prover
func InitializeProverForTests(bN int) SingleThreadedProver {

	var zero, one, two fr.Element
	one.SetOne()
	two.SetUint64(2)

	// Fold for q', q = [2, 2, 2 ,2 ...] 2
	// cipher: q = 0, qL = 1, qR = 0
	// copy: q = 1, qL = 1, qR = 0
	qPrime := make([]fr.Element, bN)
	for i := range qPrime {
		qPrime[i] = two
	}
	eq := polynomial.GetFoldedEqTable(qPrime)
	cipher := polynomial.NewBookKeepingTable([]fr.Element{zero, zero, one, zero, zero, zero, zero, zero})
	copy := polynomial.NewBookKeepingTable([]fr.Element{zero, zero, zero, zero, zero, zero, one, zero})
	cipher.Fold(two)
	copy.Fold(two)

	// Initialize the values of V
	v := make([]fr.Element, 1<<(bN+1))
	for i := range v {
		v[i].SetUint64(uint64(i))
	}
	vL := polynomial.NewBookKeepingTable(v)
	vR := vL.DeepCopy()

	return NewSingleThreadedProver(
		vL, vR, eq,
		[]circuit.Gate{circuit.CopyGate{}, &circuit.CipherGate{Ark: two}},
		[]polynomial.BookKeepingTable{copy, cipher},
	)
}
