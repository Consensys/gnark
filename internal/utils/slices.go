package utils

// AppendRefs returns append(s, &v[0], &v[1], ...).
func AppendRefs[T any](s []any, v []T) []any {
	for i := range v {
		s = append(s, &v[i])
	}
	return s
}

// ExtendRepeatLast extends a non-empty slice s by repeating the last element until it reaches the length n.
func ExtendRepeatLast[T any](s []T, n int) []T {
	if n <= len(s) {
		return s[:n]
	}
	res := make([]T, n)
	copy(res, s)
	for i := len(s); i < n; i++ {
		res[i] = res[i-1]
	}
	return res
}
