package frontend

import (
	"reflect"

	"github.com/consensys/gurvy"
)

type Context struct {
	curveID gurvy.ID
	values  map[string]interface{}
}

func NewContext(curveID gurvy.ID) *Context {
	return &Context{
		curveID: curveID,
		values:  make(map[string]interface{}),
	}
}

func (ctx *Context) CurveID() gurvy.ID {
	return ctx.curveID
}

// TODO doc similarly to golang context.Context:
// key definitions must be type key int to avoid key collisions.
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

func (ctx *Context) Value(key interface{}) (interface{}, bool) {
	k := reflect.TypeOf(key).String()
	r, ok := ctx.values[k]
	return r, ok
}
