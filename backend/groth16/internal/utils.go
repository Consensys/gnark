package internal

import "math/big"

// DivideByThresholdOrList divides x into two sub-lists. list must be sorted, non-repeating and contain no value less than indexThreshold
func DivideByThresholdOrList(indexThreshold int, list []int, x []*big.Int) (ltOrInList, gtAndNotInList []*big.Int) {
	ltOrInList = make([]*big.Int, indexThreshold+len(list))
	gtAndNotInList = make([]*big.Int, len(x)-len(ltOrInList))

	copy(ltOrInList, x[:indexThreshold])

	j := 0
	for i := indexThreshold; i < len(x); i++ {
		if j < len(list) && i == list[j] {
			ltOrInList[indexThreshold+j] = x[i]
			j++
		} else {
			gtAndNotInList[i-indexThreshold-j] = x[i]
		}
	}

	return
}
