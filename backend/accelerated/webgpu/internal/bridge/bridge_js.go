//go:build js && wasm

package bridge

import (
	"fmt"
	"syscall/js"
)

type Client struct {
	GlobalName  string
	ErrorPrefix string
}

func NewClient(globalName, errorPrefix string) Client {
	return Client{GlobalName: globalName, ErrorPrefix: errorPrefix}
}

func (c Client) getBridge() (js.Value, error) {
	bridge := js.Global().Get(c.GlobalName)
	if bridge.IsUndefined() || bridge.IsNull() {
		return js.Undefined(), fmt.Errorf("%s: %s bridge not found on global object", c.ErrorPrefix, c.GlobalName)
	}
	return bridge, nil
}

func (c Client) AwaitPromise(promise js.Value) (js.Value, error) {
	if promise.IsUndefined() || promise.IsNull() {
		return js.Undefined(), fmt.Errorf("%s: bridge returned empty promise", c.ErrorPrefix)
	}

	type result struct {
		value js.Value
		err   error
	}
	ch := make(chan result, 1)

	resolve := js.FuncOf(func(this js.Value, args []js.Value) any {
		value := js.Undefined()
		if len(args) > 0 {
			value = args[0]
		}
		ch <- result{value: value}
		return nil
	})
	reject := js.FuncOf(func(this js.Value, args []js.Value) any {
		var err error
		if len(args) > 0 {
			err = c.JSError(args[0])
		} else {
			err = fmt.Errorf("%s: bridge promise rejected", c.ErrorPrefix)
		}
		ch <- result{err: err}
		return nil
	})
	defer resolve.Release()
	defer reject.Release()

	promise.Call("then", resolve, reject)
	out := <-ch
	return out.value, out.err
}

func (c Client) JSError(v js.Value) error {
	if v.IsUndefined() || v.IsNull() {
		return fmt.Errorf("%s: unknown JS error", c.ErrorPrefix)
	}
	if message := v.Get("message"); message.Type() == js.TypeString {
		return fmt.Errorf("%s: %s", c.ErrorPrefix, message.String())
	}
	return fmt.Errorf("%s: %s", c.ErrorPrefix, v.String())
}

func (c Client) CallPromise(method string, args ...any) (js.Value, error) {
	bridge, err := c.getBridge()
	if err != nil {
		return js.Undefined(), err
	}
	fn := bridge.Get(method)
	if fn.Type() != js.TypeFunction {
		return js.Undefined(), fmt.Errorf("%s: bridge method %q is not available", c.ErrorPrefix, method)
	}
	return c.AwaitPromise(fn.Invoke(args...))
}

func JSUint8Array(src []byte) js.Value {
	out := js.Global().Get("Uint8Array").New(len(src))
	if len(src) > 0 {
		js.CopyBytesToJS(out, src)
	}
	return out
}

func GoBytes(prefix string, src js.Value) ([]byte, error) {
	if src.IsUndefined() || src.IsNull() {
		return nil, fmt.Errorf("%s: expected Uint8Array result, got empty value", prefix)
	}
	n := src.Get("byteLength")
	if n.Type() != js.TypeNumber {
		return nil, fmt.Errorf("%s: JS result does not expose byteLength", prefix)
	}
	out := make([]byte, n.Int())
	if len(out) > 0 {
		js.CopyBytesToGo(out, src)
	}
	return out, nil
}

func JSObject() js.Value {
	return js.Global().Get("Object").New()
}

func (c Client) Init(curve string) error {
	_, err := c.CallPromise("init", curve)
	return err
}

func (c Client) PrepareKey(curve string, payload js.Value) (string, error) {
	value, err := c.CallPromise("prepareKey", curve, payload)
	if err != nil {
		return "", err
	}
	handle := value.Get("handle")
	if handle.Type() != js.TypeString || handle.String() == "" {
		return "", fmt.Errorf("%s: bridge returned invalid key handle", c.ErrorPrefix)
	}
	return handle.String(), nil
}
