package frontend

import (
	"errors"
	"fmt"
	"reflect"
	"runtime/debug"
	"testing"

	"github.com/consensys/gnark/internal/backend/compiled"
	"github.com/consensys/gnark/internal/parser"
)

func TestStructTags(t *testing.T) {

	testParseType := func(input interface{}, expected map[string]compiled.Visibility) {
		collected := make(map[string]compiled.Visibility)
		var collectHandler parser.LeafHandler = func(visibility compiled.Visibility, name string, tInput reflect.Value) error {
			if _, ok := collected[name]; ok {
				return errors.New("duplicate name collected")
			}
			collected[name] = visibility
			return nil
		}
		if err := parser.Visit(input, "", compiled.Unset, collectHandler, reflect.TypeOf(Variable{})); err != nil {
			t.Log(string(debug.Stack()))
			t.Fatal(err)
		}

		for k, v := range expected {
			if v2, ok := collected[k]; !ok {
				fmt.Println(collected)
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
			A, B Variable
		}{}
		expected := make(map[string]compiled.Visibility)
		expected["A"] = compiled.Secret
		expected["B"] = compiled.Secret
		testParseType(&s, expected)
	}

	{
		s := struct {
			A Variable `gnark:"a, public"`
			B Variable
		}{}
		expected := make(map[string]compiled.Visibility)
		expected["a"] = compiled.Public
		expected["B"] = compiled.Secret
		testParseType(&s, expected)
	}

	{
		s := struct {
			A Variable `gnark:",public"`
			B Variable
		}{}
		expected := make(map[string]compiled.Visibility)
		expected["A"] = compiled.Public
		expected["B"] = compiled.Secret
		testParseType(&s, expected)
	}

	{
		s := struct {
			A Variable `gnark:"-"`
			B Variable
		}{}
		expected := make(map[string]compiled.Visibility)
		expected["B"] = compiled.Secret
		testParseType(&s, expected)
	}

	{
		s := struct {
			A Variable `gnark:",public"`
			B Variable
			C struct {
				D Variable
			}
		}{}
		expected := make(map[string]compiled.Visibility)
		expected["A"] = compiled.Public
		expected["B"] = compiled.Secret
		expected["C_D"] = compiled.Secret
		testParseType(&s, expected)
	}

	// hierarchy of structs
	{
		type grandchild struct {
			D Variable `gnark:"grandchild"`
		}
		type child struct {
			D Variable `gnark:",public"` // parent visibility is secret so public here is ignored
			G grandchild
		}
		s := struct {
			A Variable `gnark:",public"`
			B Variable
			C child
		}{}
		expected := make(map[string]compiled.Visibility)
		expected["A"] = compiled.Public
		expected["B"] = compiled.Secret
		expected["C_D"] = compiled.Secret
		expected["C_G_grandchild"] = compiled.Secret
		testParseType(&s, expected)
	}

	// ignore embedded structs (not exported)
	{
		type embedded struct {
			D Variable
		}
		type child struct {
			embedded // this is not exported and ignored
		}

		s := struct {
			C child
			A Variable `gnark:",public"`
			B Variable
		}{}
		expected := make(map[string]compiled.Visibility)
		expected["A"] = compiled.Public
		expected["B"] = compiled.Secret
		testParseType(&s, expected)
	}

	// array
	{
		s := struct {
			A [2]Variable `gnark:",public"`
		}{}
		expected := make(map[string]compiled.Visibility)
		expected["A_0"] = compiled.Public
		expected["A_1"] = compiled.Public
		testParseType(&s, expected)
	}

	// slice
	{
		s := struct {
			A []Variable `gnark:",public"`
		}{A: make([]Variable, 2)}
		expected := make(map[string]compiled.Visibility)
		expected["A_0"] = compiled.Public
		expected["A_1"] = compiled.Public
		testParseType(&s, expected)
	}

}
