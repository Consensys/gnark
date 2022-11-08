package emulated

import (
	"fmt"
	"reflect"
	"strconv"

	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/schema"
)

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

func (w *FieldAPI[T]) VariableCount(t reflect.Type) int {
	return int(w.f.fParams.NbLimbs())
}

func (w *FieldAPI[T]) addVariable(sf *schema.Field, recurseFn func(*schema.Field) frontend.Variable) frontend.Variable {
	limbs := make([]frontend.Variable, w.f.fParams.NbLimbs())
	var subfs []schema.Field
	for i := range limbs {
		subf := schema.Field{
			Name:       strconv.Itoa(i),
			Visibility: sf.Visibility,
			FullName:   fmt.Sprintf("%s_%d", sf.FullName, i),
			Type:       schema.Leaf,
			ArraySize:  1,
		}
		subfs = append(subfs, subf)
		limbs[i] = recurseFn(&subf)
	}
	sf.ArraySize = len(subfs)
	sf.Type = schema.Array
	sf.SubFields = subfs
	el := w.f.PackLimbs(limbs)
	return el
}

func (w *FieldAPI[T]) PublicVariable(sf *schema.Field) frontend.Variable {
	return w.addVariable(sf, w.b.PublicVariable)
}

func (w *FieldAPI[T]) SecretVariable(sf *schema.Field) frontend.Variable {
	return w.addVariable(sf, w.b.SecretVariable)
}

func (w *FieldAPI[T]) Commit(v ...frontend.Variable) (frontend.Variable, error) {
	//TODO implement me
	panic("not implemented")
}

// func (f *Field[T]) Reduce(i frontend.Variable) frontend.Variable {
// 	el := f.varToElement(i)
// 	res := f.reduce(el)
// 	return res
// }
