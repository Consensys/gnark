package utils

// AppendRefs returns append(s, &v[0], &v[1], ...).
func AppendRefs[T any](s []any, v []T) []any {
	for i := range v {
		s = append(s, &v[i])
	}
	return s
}

// References returns a slice of references to the elements of v.
func References[T any](v []T) []*T {
	res := make([]*T, len(v))
	for i := range v {
		res[i] = &v[i]
	}
	return res
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
