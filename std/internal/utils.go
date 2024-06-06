package internal

// NegFactorial returns (-n)(-n+1)...(-2)(-1) for n \geq 1, and -n otherwise.
// This is not asymptotically efficient, but works for small values.
func NegFactorial(n int) int {
	n = -n
	result := n
	for n++; n <= -1; n++ {
		result *= n
	}
	return result
}
