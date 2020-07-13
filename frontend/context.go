package frontend

import (
	"reflect"

	"github.com/consensys/gurvy"
)

// TODO WIP, so far, context seems to be only useful to carry the curveID. Unless we force an interface
// for user's gadgets that takes a context..

// Context represents a dictionnary of values usable by a Circuit and its components
// at a minimum, a Context holds a curveID indicating which Curve and Basefield the circuit
// is meant to use.
type Context struct {
	curveID gurvy.ID
	values  map[string]interface{}
}

// NewContext returns a new Context object with given curveID
func NewContext(curveID gurvy.ID) *Context {
	return &Context{
		curveID: curveID,
		values:  make(map[string]interface{}),
	}
}

// CurveID returns context curveID
func (ctx *Context) CurveID() gurvy.ID {
	return ctx.curveID
}

// Set ...
// TODO see golang context.Context for example doc
// ex: key definitions must be type key int to avoid key collisions.
func (ctx *Context) Set(key, value interface{}) {
	if key == nil {
		panic("nil key")
	}
	k := reflect.TypeOf(key).String()
	if _, ok := ctx.values[k]; ok {
		panic("context key already declared: key declaration must use type alias (e.g.: type key int)")
	}
	ctx.values[k] = value

}

// Value ...
// TODO
func (ctx *Context) Value(key interface{}) (interface{}, bool) {
	k := reflect.TypeOf(key).String()
	r, ok := ctx.values[k]
	return r, ok
}
