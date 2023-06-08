package internal

import "math/big"

// DivideByThresholdOrList divides x into two sub-lists. list must be sorted, non-repeating and contain no value less than indexThreshold
// x is modified in this process. The output lists are sub-slices of x.
func DivideByThresholdOrList(indexThreshold int, list []int, x []*big.Int) (ltOrOnList, gtAndNotOnList []*big.Int) {
	ltOrOnList = x[:indexThreshold+len(list)]
	gtAndNotOnList = x[len(ltOrOnList):]
	onList := make([]*big.Int, len(list)) // the list is small
	for i := range list {
		onList[i] = x[list[i]]
	}
	for i := len(list) - 1; i >= 0; i-- { // overwrite the element at list[i]
		sliceStart := indexThreshold
		if i > 0 {
			sliceStart = list[i-1]
		}
		displacement := len(list) - i
		copy(x[sliceStart+displacement:], x[sliceStart:list[i]])
	}
	copy(x[indexThreshold:], onList)
	return
}

func ConcatAll(slices ...[]int) []int { // copyright note: written by GitHub Copilot
	totalLen := 0
	for _, s := range slices {
		totalLen += len(s)
	}
	res := make([]int, totalLen)
	i := 0
	for _, s := range slices {
		i += copy(res[i:], s)
	}
	return res
}

func NbElements(slices [][]int) int { // copyright note: written by GitHub Copilot
	totalLen := 0
	for _, s := range slices {
		totalLen += len(s)
	}
	return totalLen
}
