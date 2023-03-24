package polynomial

import (
	"github.com/consensys/gnark/std/gkr/common"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// AsChunkedBookKeepingTable interpret a double slice as a slice of bookkeeping tables
func AsChunkedBookKeepingTable(x [][]fr.Element) []BookKeepingTable {
	res := make([]BookKeepingTable, len(x))
	for i := range res {
		res[i] = NewBookKeepingTable(x[i])
	}
	return res
}

// Always starts by the last elements
func chunkedEvalRecombine(bkts []BookKeepingTable, qs []fr.Element) BookKeepingTable {
	logNChunks := common.Log2Ceil(len(bkts))
	if logNChunks != len(qs) {
		panic("q and bkts sizes are not compatible")
	}

	var inp, res []BookKeepingTable
	inp = bkts
	for _, q := range qs {
		mid := len(inp) / 2
		res = make([]BookKeepingTable, mid)
		for k := range res {
			// res[i] = inp[i+mid].DeepCopy()
			res[k].Sub(inp[k+mid], inp[k], 1)
			res[k].Mul(q, res[k], 1)
			res[k].Add(res[k], inp[k])
		}
		inp = res
	}

	return res[0]
}

// EvaluateChunked evaluates a chunked bookeeping table
func EvaluateChunked(bkts []BookKeepingTable, q []fr.Element) fr.Element {
	logNChunks := common.Log2Ceil(len(bkts))
	recombined := chunkedEvalRecombine(bkts, q[len(q)-logNChunks:])
	return recombined.Evaluate(q[:len(q)-logNChunks])
}

// EvaluateMixedChunked evaluates a chunked bookeeping table
func EvaluateMixedChunked(bkts []BookKeepingTable, hPrime, hL, hR []fr.Element) (fr.Element, fr.Element) {
	logNChunks := common.Log2Ceil(len(bkts))
	if logNChunks > len(hPrime) {
		panic("We can only chunks on hPrime")
	}

	recombined := chunkedEvalRecombine(bkts, hPrime[len(hPrime)-logNChunks:])
	return recombined.EvaluateLeftAndRight(hPrime[:len(hPrime)-logNChunks], hL, hR)
}
