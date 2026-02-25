package utils

// AppendRefs returns append(s, &v[0], &v[1], ...).
func AppendRefs[T any](s []any, v []T) []any {
	for i := range v {
		s = append(s, &v[i])
	}
	return s
}

// Exclude returns a copy of s with the element at index excluded.
// If index is negative or out of bounds, returns s unchanged.
func Exclude[T any](s []T, index int) []T {
	if index < 0 || index >= len(s) {
		return s
	}
	res := make([]T, 0, len(s)-1)
	for i := range s {
		if i != index {
			res = append(res, s[i])
		}
	}
	return res
}

// CloneExcludeF returns [f(s[i])]ᵢ for all i ≠ index in range.
// If index is negative or out of bounds, returns s unchanged.
func CloneExcludeF[T, S any](s []T, index int, f func(*T) S) []S {
	res := make([]S, 0, len(s))
	for i := range s {
		if i != index {
			res = append(res, f(&s[i]))
		}
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
