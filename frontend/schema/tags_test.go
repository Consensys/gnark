package schema

import (
	"errors"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStructTags(t *testing.T) {

	testParseTags := func(t *testing.T, input interface{}, expected map[string]Visibility) {
		assert := require.New(t)
		collected := make(map[string]Visibility)
		collectHandler := func(f LeafInfo, _ reflect.Value) error {
			n := f.FullName()
			if _, ok := collected[n]; ok {
				return errors.New("duplicate name collected")
			}
			collected[n] = f.Visibility
			return nil
		}

		_, err := Walk(input, tVariable, collectHandler)
		assert.NoError(err)

		for k, v := range expected {
			if v2, ok := collected[k]; !ok {
				t.Fatal("failed to collect", k)
			} else if v2 != v {
				t.Fatal("collected", k, "but visibility is wrong got", v2, "expected", v)
			}
			delete(collected, k)
		}
		if len(collected) != 0 {
			t.Fatal("collected more variable than expected")
		}

	}

	{
		s := struct {
			A, B variable
		}{}
		expected := make(map[string]Visibility)
		expected["A"] = Secret
		expected["B"] = Secret
		t.Run("simple_no_tag", func(t *testing.T) { testParseTags(t, &s, expected) })
	}

	{
		s := struct {
			A variable `gnark:"a, public"`
			B variable
		}{}
		expected := make(map[string]Visibility)
		expected["a"] = Public
		expected["B"] = Secret
		t.Run("simple_tag_name", func(t *testing.T) { testParseTags(t, &s, expected) })
	}

	{
		s := struct {
			A variable `gnark:",public"`
			B variable
		}{}
		expected := make(map[string]Visibility)
		expected["A"] = Public
		expected["B"] = Secret
		t.Run("simple_tag_visibility", func(t *testing.T) { testParseTags(t, &s, expected) })
	}

	{
		s := struct {
			A variable `gnark:"-"`
			B variable
		}{}
		expected := make(map[string]Visibility)
		expected["B"] = Secret
		t.Run("simple_tag_omit", func(t *testing.T) { testParseTags(t, &s, expected) })
	}

	{
		s := struct {
			A variable `gnark:",public"`
			B variable
			C struct {
				D variable
			}
		}{}
		expected := make(map[string]Visibility)
		expected["A"] = Public
		expected["B"] = Secret
		expected["C_D"] = Secret
		t.Run("one_layer", func(t *testing.T) { testParseTags(t, &s, expected) })
	}

	// hierarchy of structs
	{
		type grandchild struct {
			D variable `gnark:"grandchild"` // parent visibility is unset, this will be secret
		}
		type child struct {
			D variable `gnark:",public"` // parent visibility is unset, this will be public
			G grandchild
		}
		s := struct {
			A variable `gnark:",public"`
			B variable
			C child
		}{}
		expected := make(map[string]Visibility)
		expected["A"] = Public
		expected["B"] = Secret
		expected["C_D"] = Public
		expected["C_G_grandchild"] = Secret
		t.Run("two_layers", func(t *testing.T) { testParseTags(t, &s, expected) })
	}

	//  embedded structs
	{
		type embedded struct {
			D variable
		}
		type child struct {
			embedded
		}

		s := struct {
			C child
			A variable `gnark:",public"`
			B variable
		}{}
		expected := make(map[string]Visibility)
		expected["A"] = Public
		expected["B"] = Secret
		expected["C_D"] = Secret
		t.Run("embedded_structs", func(t *testing.T) { testParseTags(t, &s, expected) })
	}

	// array
	{
		s := struct {
			A [2]variable `gnark:",public"`
		}{}
		expected := make(map[string]Visibility)
		expected["A_0"] = Public
		expected["A_1"] = Public
		t.Run("array", func(t *testing.T) { testParseTags(t, &s, expected) })
	}

	// slice
	{
		s := struct {
			A []variable `gnark:",public"`
		}{A: make([]variable, 2)}
		expected := make(map[string]Visibility)
		expected["A_0"] = Public
		expected["A_1"] = Public
		t.Run("slice", func(t *testing.T) { testParseTags(t, &s, expected) })
	}

}
