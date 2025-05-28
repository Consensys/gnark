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
