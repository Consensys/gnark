package common

// Min returns the minimum of two numbers
func Min(a int, b int) int {
	if a <= b {
		return a
	}
	return b
}

// Max returns the maximum of two number
func Max(a int, b int) int {
	if a >= b {
		return a
	}
	return b
}

// Log2Floor computes the floored value of Log2
func Log2Floor(a int) int {
	res := 0
	for i := a; i > 1; i = i >> 1 {
		res++
	}
	return res
}

// Log2Ceil computes the ceiled value of Log2
func Log2Ceil(a int) int {
	floor := Log2Floor(a)
	if a != 1<<floor {
		floor++
	}
	return floor
}
