package lzss_v1

import "github.com/consensys/gnark/frontend"

func Gcd(a ...int) int {
	if len(a) == 0 {
		return -1
	}

	for len(a) > 1 {
		if a[1] < a[0] {
			a[0], a[1] = a[1], a[0]
		}
		for a[0] != 0 {
			a[1], a[0] = a[0], a[1]%a[0]
		}
		a = a[1:]
	}

	return a[0]
}

func Pack(api frontend.API, words []frontend.Variable, wordLen int) []frontend.Variable {
	wordsPerElem := (api.Compiler().FieldBitLen() - 1) / wordLen
	res := make([]frontend.Variable, 1+(len(words)-1)/wordsPerElem)
	for elemI := range res {
		res[elemI] = 0
		for wordI := 0; wordI < wordsPerElem; wordI++ {
			absWordI := elemI*wordsPerElem + wordI
			if absWordI >= len(words) {
				break
			}
			res[elemI] = api.Add(res[elemI], api.Mul(words[absWordI], 1<<uint(wordLen*wordI)))
		}
	}
	return res
}
