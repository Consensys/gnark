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

// ExtendRepeatLast extends the slice s by repeating the last element until it reaches the length n.
func ExtendRepeatLast[T any](s []T, n int) []T {
	if n <= len(s) {
		return s[:n]
	}
	s = s[:len(s):len(s)] // ensure s is a slice with a capacity equal to its length
	for len(s) < n {
		s = append(s, s[len(s)-1]) // append the last element until the length is n
	}
	return s
}
