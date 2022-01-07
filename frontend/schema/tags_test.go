package schema_test

import (
	"errors"
	"reflect"
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/schema"
	"github.com/consensys/gnark/internal/backend/compiled"
	"github.com/stretchr/testify/require"
)

func TestStructTags(t *testing.T) {

	testParseTags := func(t *testing.T, input interface{}, expected map[string]compiled.Visibility) {
		assert := require.New(t)
		collected := make(map[string]compiled.Visibility)
		var collectHandler schema.LeafHandler = func(visibility compiled.Visibility, name string, _ reflect.Value) error {
			if _, ok := collected[name]; ok {
				return errors.New("duplicate name collected")
			}
			collected[name] = visibility
			return nil
		}

		_, err := schema.Parse(input, tVariable, collectHandler)
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
			t.Fatal("collected more frontend.Variable than expected")
		}

	}

	{
		s := struct {
			A, B frontend.Variable
		}{}
		expected := make(map[string]compiled.Visibility)
		expected["A"] = compiled.Secret
		expected["B"] = compiled.Secret
		t.Run("simple_no_tag", func(t *testing.T) { testParseTags(t, &s, expected) })
	}

	{
		s := struct {
			A frontend.Variable `gnark:"a, public"`
			B frontend.Variable
		}{}
		expected := make(map[string]compiled.Visibility)
		expected["a"] = compiled.Public
		expected["B"] = compiled.Secret
		t.Run("simple_tag_name", func(t *testing.T) { testParseTags(t, &s, expected) })
	}

	{
		s := struct {
			A frontend.Variable `gnark:",public"`
			B frontend.Variable
		}{}
		expected := make(map[string]compiled.Visibility)
		expected["A"] = compiled.Public
		expected["B"] = compiled.Secret
		t.Run("simple_tag_visibility", func(t *testing.T) { testParseTags(t, &s, expected) })
	}

	{
		s := struct {
			A frontend.Variable `gnark:"-"`
			B frontend.Variable
		}{}
		expected := make(map[string]compiled.Visibility)
		expected["B"] = compiled.Secret
		t.Run("simple_tag_omit", func(t *testing.T) { testParseTags(t, &s, expected) })
	}

	{
		s := struct {
			A frontend.Variable `gnark:",public"`
			B frontend.Variable
			C struct {
				D frontend.Variable
			}
		}{}
		expected := make(map[string]compiled.Visibility)
		expected["A"] = compiled.Public
		expected["B"] = compiled.Secret
		expected["C_D"] = compiled.Secret
		t.Run("one_layer", func(t *testing.T) { testParseTags(t, &s, expected) })
	}

	// hierarchy of structs
	{
		type grandchild struct {
			D frontend.Variable `gnark:"grandchild"` // parent visibility is unset, this will be secret
		}
		type child struct {
			D frontend.Variable `gnark:",public"` // parent visibility is unset, this will be public
			G grandchild
		}
		s := struct {
			A frontend.Variable `gnark:",public"`
			B frontend.Variable
			C child
		}{}
		expected := make(map[string]compiled.Visibility)
		expected["A"] = compiled.Public
		expected["B"] = compiled.Secret
		expected["C_D"] = compiled.Public
		expected["C_G_grandchild"] = compiled.Secret
		t.Run("two_layers", func(t *testing.T) { testParseTags(t, &s, expected) })
	}

	//  embedded structs
	{
		type embedded struct {
			D frontend.Variable
		}
		type child struct {
			embedded
		}

		s := struct {
			C child
			A frontend.Variable `gnark:",public"`
			B frontend.Variable
		}{}
		expected := make(map[string]compiled.Visibility)
		expected["A"] = compiled.Public
		expected["B"] = compiled.Secret
		expected["C_D"] = compiled.Secret
		t.Run("embedded_structs", func(t *testing.T) { testParseTags(t, &s, expected) })
	}

	// array
	{
		s := struct {
			A [2]frontend.Variable `gnark:",public"`
		}{}
		expected := make(map[string]compiled.Visibility)
		expected["A_0"] = compiled.Public
		expected["A_1"] = compiled.Public
		t.Run("array", func(t *testing.T) { testParseTags(t, &s, expected) })
	}

	// slice
	{
		s := struct {
			A []frontend.Variable `gnark:",public"`
		}{A: make([]frontend.Variable, 2)}
		expected := make(map[string]compiled.Visibility)
		expected["A_0"] = compiled.Public
		expected["A_1"] = compiled.Public
		t.Run("slice", func(t *testing.T) { testParseTags(t, &s, expected) })
	}

}
