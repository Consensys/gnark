package solver

import "testing"

func TestRegexpRename(t *testing.T) {
	for i, v := range []struct{ input, expected string }{
		// conversion from new to old style
		{"github.com/consensys/gnark/internal/regression_tests/issue1045.init.func1", "github.com/consensys/gnark/internal/regression_tests/issue1045.glob..func1"},
		// conversion from old to old same
		{"github.com/consensys/gnark/internal/regression_tests/issue1045.glob..func1", "github.com/consensys/gnark/internal/regression_tests/issue1045.glob..func1"},
		// conversion from explicit to explit same
		{"github.com/consensys/gnark/internal/regression_tests/issue1045.ExplicitHint", "github.com/consensys/gnark/internal/regression_tests/issue1045.ExplicitHint"},
	} {
		if got := newToOldStyle(v.input); got != v.expected {
			t.Errorf("test %d: expected %s, got %s", i, v.expected, got)
		}
	}

}
