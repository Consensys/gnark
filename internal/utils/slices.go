package utils

// AppendRefs returns append(s, &v[0], &v[1], ...).
func AppendRefs[T any](s []any, v []T) []any {
	for i := range v {
		s = append(s, &v[i])
	}
	return s
}
