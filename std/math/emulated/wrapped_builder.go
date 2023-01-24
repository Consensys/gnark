package emulated

import (
	"fmt"
	"reflect"
	"strconv"

	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/schema"
)

// NewBuilder wraps the existing builder to be compatible with frontend builder
// option [frontend.WithBuilderWrapper]. The wrapper builder also wraps the API
// methods (embedded in the [frontend.Builder] definition).
//
// Using wrapped builder allows to take an existing circuit defined over a
// native field (and where all the public/private witness are defined as type
// [frontend.Variable]) and run it over non-native field.
//
// For most of the cases, this leads to sub-optimal performance as dedicated
// operations on the [Field] allow for writing more optimal circuits.
func NewBuilder[T FieldParams](native frontend.Builder) (*FieldAPI[T], error) {
	f, err := NewField[T](native)
	if err != nil {
		return nil, fmt.Errorf("new field: %w", err)
	}
	return &FieldAPI[T]{f: f, b: native}, nil
}

// builderWrapper returns a wrapper for the builder which is compatible to use
// as a frontend compile option. When using this wrapper, it is possible to
// extend existing circuits into any emulated field defined by
func builderWrapper[T FieldParams]() frontend.BuilderWrapper {
	return func(b frontend.Builder) frontend.Builder {
		b, err := NewBuilder[T](b)
		if err != nil {
			panic(err)
		}
		return b
	}
}

func (w *FieldAPI[T]) Compile() (constraint.ConstraintSystem, error) {
	return w.b.Compile()
}

func (w *FieldAPI[T]) VariableCount(_ reflect.Type) int {
	return int(w.f.fParams.NbLimbs())
}

func (w *FieldAPI[T]) addVariable(sf schema.LeafInfo, adder func(schema.LeafInfo) frontend.Variable) frontend.Variable {
	limbs := make([]frontend.Variable, w.f.fParams.NbLimbs())
	n := sf.FullName()
	for i := 0; i < len(limbs); i++ {
		li := sf
		li.FullName = func() string {
			return n + "_" + strconv.Itoa(i)
		}
		limbs[i] = adder(li)
	}
	el := w.f.PackElementLimbs(limbs)
	return el
}

func (w *FieldAPI[T]) PublicVariable(sf schema.LeafInfo) frontend.Variable {
	return w.addVariable(sf, w.b.PublicVariable)
}

func (w *FieldAPI[T]) SecretVariable(sf schema.LeafInfo) frontend.Variable {
	return w.addVariable(sf, w.b.SecretVariable)
}

func (w *FieldAPI[T]) Commit(v ...frontend.Variable) (frontend.Variable, error) {
	//TODO implement me
	panic("not implemented")
}
