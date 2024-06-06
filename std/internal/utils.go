package internal

// NegFactorial returns (-n)(-n+1)...(-2)(-1)
// There are more efficient algorithms, but we are talking small values here so it doesn't matter
func NegFactorial(n int) int {
	n = -n
	result := n
	for n++; n <= -1; n++ {
		result *= n
	}
	return result
}
