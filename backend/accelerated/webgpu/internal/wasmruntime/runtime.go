//go:build js && wasm

package wasmruntime

import (
	"bytes"
	"fmt"
	"io"
	"syscall/js"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
)

type ProveFunc[PK, Proof any] func(constraint.ConstraintSystem, PK, witness.Witness) (Proof, error)
type PrepareFunc[PK any] func(PK) error
type PrepareWithCSFunc[PK any] func(constraint.ConstraintSystem, PK) error
type VerifyFunc[VK, Proof any] func(Proof, VK, witness.Witness) error

type Config[PK, VK, Proof any] struct {
	GlobalName string

	SupportedCurves map[string]ecc.ID
	CSFactory       func(ecc.ID) constraint.ConstraintSystem
	PKFactory       func(ecc.ID) PK
	VKFactory       func(ecc.ID) VK
	ProofFactory    func(ecc.ID) Proof

	ReadProvingKey func(PK, string, []byte) error
	Prepare        PrepareFunc[PK]
	PrepareWithCS  PrepareWithCSFunc[PK]
	Prove          ProveFunc[PK, Proof]
	Verify         VerifyFunc[VK, Proof]
}

type Runtime[PK, VK, Proof any] struct {
	cfg     Config[PK, VK, Proof]
	next    uint64
	funcs   []js.Func
	ccs     map[string]ccsEntry
	pks     map[string]pkEntry[PK]
	vks     map[string]vkEntry[VK]
	handles map[string]string
}

type ccsEntry struct {
	curve ecc.ID
	value constraint.ConstraintSystem
}

type pkEntry[PK any] struct {
	curve    ecc.ID
	value    PK
	prepared bool
}

type vkEntry[VK any] struct {
	curve ecc.ID
	value VK
}

func Install[PK, VK, Proof any](cfg Config[PK, VK, Proof]) error {
	if cfg.GlobalName == "" {
		return fmt.Errorf("missing global name")
	}
	if cfg.CSFactory == nil {
		return fmt.Errorf("missing constraint system factory")
	}
	if cfg.PKFactory == nil {
		return fmt.Errorf("missing proving key factory")
	}
	if cfg.VKFactory == nil {
		return fmt.Errorf("missing verification key factory")
	}
	if cfg.ProofFactory == nil {
		return fmt.Errorf("missing proof factory")
	}
	if cfg.Prove == nil {
		return fmt.Errorf("missing prove function")
	}
	if cfg.Verify == nil {
		return fmt.Errorf("missing verify function")
	}

	r := &Runtime[PK, VK, Proof]{
		cfg:     cfg,
		ccs:     make(map[string]ccsEntry),
		pks:     make(map[string]pkEntry[PK]),
		vks:     make(map[string]vkEntry[VK]),
		handles: make(map[string]string),
	}
	js.Global().Set(cfg.GlobalName, r.object())
	select {}
}

func (r *Runtime[PK, VK, Proof]) object() js.Value {
	obj := js.Global().Get("Object").New()
	r.setMethod(obj, "readConstraintSystem", r.readConstraintSystem)
	r.setMethod(obj, "readProvingKey", r.readProvingKey)
	r.setMethod(obj, "readVerificationKey", r.readVerificationKey)
	r.setMethod(obj, "prepareProvingKey", r.prepareProvingKey)
	r.setMethod(obj, "prove", r.prove)
	r.setMethod(obj, "verify", r.verify)
	r.setMethod(obj, "release", r.release)
	return obj
}

func (r *Runtime[PK, VK, Proof]) setMethod(obj js.Value, name string, fn func([]js.Value) (js.Value, error)) {
	callback := js.FuncOf(func(this js.Value, args []js.Value) any {
		return promise(func() (js.Value, error) {
			return fn(args)
		})
	})
	r.funcs = append(r.funcs, callback)
	obj.Set(name, callback)
}

func promise(fn func() (js.Value, error)) js.Value {
	executor := js.FuncOf(func(this js.Value, args []js.Value) any {
		resolve := args[0]
		reject := args[1]
		go func() {
			value, err := fn()
			if err != nil {
				reject.Invoke(js.Global().Get("Error").New(err.Error()))
				return
			}
			resolve.Invoke(value)
		}()
		return nil
	})
	p := js.Global().Get("Promise").New(executor)
	executor.Release()
	return p
}

func (r *Runtime[PK, VK, Proof]) readConstraintSystem(args []js.Value) (js.Value, error) {
	curveID, err := r.curveIDFromArg(args, 0)
	if err != nil {
		return js.Undefined(), err
	}
	data, err := bytesFromArg(args, 1)
	if err != nil {
		return js.Undefined(), err
	}
	ccs := r.cfg.CSFactory(curveID)
	if _, err := ccs.ReadFrom(bytes.NewReader(data)); err != nil {
		return js.Undefined(), fmt.Errorf("read ccs: %w", err)
	}
	handle := r.store("ccs")
	r.ccs[handle] = ccsEntry{curve: curveID, value: ccs}

	out := js.Global().Get("Object").New()
	out.Set("handle", handle)
	out.Set("constraints", ccs.GetNbConstraints())
	return out, nil
}

func (r *Runtime[PK, VK, Proof]) readProvingKey(args []js.Value) (js.Value, error) {
	curveID, err := r.curveIDFromArg(args, 0)
	if err != nil {
		return js.Undefined(), err
	}
	data, err := bytesFromArg(args, 1)
	if err != nil {
		return js.Undefined(), err
	}
	format := "serialized"
	if len(args) > 2 && args[2].Type() == js.TypeString {
		format = args[2].String()
	}
	pk := r.cfg.PKFactory(curveID)
	if r.cfg.ReadProvingKey != nil {
		if err := r.cfg.ReadProvingKey(pk, format, data); err != nil {
			return js.Undefined(), err
		}
	} else if format != "serialized" {
		return js.Undefined(), fmt.Errorf("unsupported proving key format %q", format)
	} else if err := readFromBytes(pk, "pk", data); err != nil {
		return js.Undefined(), err
	}
	handle := r.store("pk")
	r.pks[handle] = pkEntry[PK]{curve: curveID, value: pk}
	return handleObject(handle), nil
}

func (r *Runtime[PK, VK, Proof]) readVerificationKey(args []js.Value) (js.Value, error) {
	curveID, err := r.curveIDFromArg(args, 0)
	if err != nil {
		return js.Undefined(), err
	}
	data, err := bytesFromArg(args, 1)
	if err != nil {
		return js.Undefined(), err
	}
	vk := r.cfg.VKFactory(curveID)
	if err := readFromBytes(vk, "vk", data); err != nil {
		return js.Undefined(), err
	}
	handle := r.store("vk")
	r.vks[handle] = vkEntry[VK]{curve: curveID, value: vk}
	return handleObject(handle), nil
}

func (r *Runtime[PK, VK, Proof]) prepareProvingKey(args []js.Value) (js.Value, error) {
	handle, pk, err := r.pkFromArg(args, 0)
	if err != nil {
		return js.Undefined(), err
	}
	var ccs *ccsEntry
	if len(args) > 1 && args[1].Type() == js.TypeString {
		entry, err := r.ccsFromArg(args, 1)
		if err != nil {
			return js.Undefined(), err
		}
		if entry.curve != pk.curve {
			return js.Undefined(), fmt.Errorf("ccs and proving key curves do not match")
		}
		ccs = &entry
	}
	if err := r.ensurePrepared(handle, pk, ccs); err != nil {
		return js.Undefined(), err
	}
	return js.Undefined(), nil
}

func (r *Runtime[PK, VK, Proof]) prove(args []js.Value) (js.Value, error) {
	ccs, err := r.ccsFromArg(args, 0)
	if err != nil {
		return js.Undefined(), err
	}
	pkHandle, pk, err := r.pkFromArg(args, 1)
	if err != nil {
		return js.Undefined(), err
	}
	if ccs.curve != pk.curve {
		return js.Undefined(), fmt.Errorf("ccs and proving key curves do not match")
	}
	witnessBytes, err := bytesFromArg(args, 2)
	if err != nil {
		return js.Undefined(), err
	}
	fullWitness, err := readWitness(ccs.curve, witnessBytes)
	if err != nil {
		return js.Undefined(), fmt.Errorf("read witness: %w", err)
	}
	if err := r.ensurePrepared(pkHandle, pk, &ccs); err != nil {
		return js.Undefined(), err
	}
	proof, err := r.cfg.Prove(ccs.value, pk.value, fullWitness)
	if err != nil {
		return js.Undefined(), fmt.Errorf("prove: %w", err)
	}
	proofBytes, err := writeToBytes(proof)
	if err != nil {
		return js.Undefined(), fmt.Errorf("serialize proof: %w", err)
	}
	return jsBytes(proofBytes), nil
}

func (r *Runtime[PK, VK, Proof]) verify(args []js.Value) (js.Value, error) {
	proofBytes, err := bytesFromArg(args, 0)
	if err != nil {
		return js.Undefined(), err
	}
	vk, err := r.vkFromArg(args, 1)
	if err != nil {
		return js.Undefined(), err
	}
	publicWitnessBytes, err := bytesFromArg(args, 2)
	if err != nil {
		return js.Undefined(), err
	}
	proof := r.cfg.ProofFactory(vk.curve)
	if err := readFromBytes(proof, "proof", proofBytes); err != nil {
		return js.Undefined(), err
	}
	publicWitness, err := readWitness(vk.curve, publicWitnessBytes)
	if err != nil {
		return js.Undefined(), fmt.Errorf("read public witness: %w", err)
	}
	if err := r.cfg.Verify(proof, vk.value, publicWitness); err != nil {
		return js.ValueOf(false), nil
	}
	return js.ValueOf(true), nil
}

func (r *Runtime[PK, VK, Proof]) release(args []js.Value) (js.Value, error) {
	if len(args) < 1 || args[0].Type() != js.TypeString {
		return js.Undefined(), fmt.Errorf("missing handle")
	}
	handle := args[0].String()
	switch r.handles[handle] {
	case "ccs":
		delete(r.ccs, handle)
	case "pk":
		delete(r.pks, handle)
	case "vk":
		delete(r.vks, handle)
	}
	delete(r.handles, handle)
	return js.Undefined(), nil
}

func (r *Runtime[PK, VK, Proof]) ensurePrepared(handle string, pk pkEntry[PK], ccs *ccsEntry) error {
	if pk.prepared {
		return nil
	}
	if ccs != nil && r.cfg.PrepareWithCS != nil {
		if err := r.cfg.PrepareWithCS(ccs.value, pk.value); err != nil {
			return fmt.Errorf("prepare pk: %w", err)
		}
		pk.prepared = true
		r.pks[handle] = pk
		return nil
	}
	if r.cfg.Prepare != nil {
		if err := r.cfg.Prepare(pk.value); err != nil {
			return fmt.Errorf("prepare pk: %w", err)
		}
	}
	if r.cfg.PrepareWithCS == nil {
		pk.prepared = true
	}
	r.pks[handle] = pk
	return nil
}

func (r *Runtime[PK, VK, Proof]) ccsFromArg(args []js.Value, index int) (ccsEntry, error) {
	handle, err := handleFromArg(args, index)
	if err != nil {
		return ccsEntry{}, err
	}
	entry, ok := r.ccs[handle]
	if !ok {
		return ccsEntry{}, fmt.Errorf("unknown ccs handle %q", handle)
	}
	return entry, nil
}

func (r *Runtime[PK, VK, Proof]) pkFromArg(args []js.Value, index int) (string, pkEntry[PK], error) {
	handle, err := handleFromArg(args, index)
	if err != nil {
		return "", pkEntry[PK]{}, err
	}
	entry, ok := r.pks[handle]
	if !ok {
		return "", pkEntry[PK]{}, fmt.Errorf("unknown proving key handle %q", handle)
	}
	return handle, entry, nil
}

func (r *Runtime[PK, VK, Proof]) vkFromArg(args []js.Value, index int) (vkEntry[VK], error) {
	handle, err := handleFromArg(args, index)
	if err != nil {
		return vkEntry[VK]{}, err
	}
	entry, ok := r.vks[handle]
	if !ok {
		return vkEntry[VK]{}, fmt.Errorf("unknown verification key handle %q", handle)
	}
	return entry, nil
}

func (r *Runtime[PK, VK, Proof]) store(kind string) string {
	r.next++
	handle := fmt.Sprintf("%s:%d", kind, r.next)
	r.handles[handle] = kind
	return handle
}

func (r *Runtime[PK, VK, Proof]) curveIDFromArg(args []js.Value, index int) (ecc.ID, error) {
	if len(args) <= index || args[index].Type() != js.TypeString {
		return ecc.UNKNOWN, fmt.Errorf("missing curve")
	}
	name := args[index].String()
	curves := r.cfg.SupportedCurves
	if len(curves) == 0 {
		curves = defaultSupportedCurves
	}
	curveID, ok := curves[name]
	if !ok {
		return ecc.UNKNOWN, fmt.Errorf("unsupported curve %q", name)
	}
	return curveID, nil
}

var defaultSupportedCurves = map[string]ecc.ID{
	"bn254":     ecc.BN254,
	"bls12_377": ecc.BLS12_377,
	"bls12_381": ecc.BLS12_381,
}

func handleObject(handle string) js.Value {
	out := js.Global().Get("Object").New()
	out.Set("handle", handle)
	return out
}

func handleFromArg(args []js.Value, index int) (string, error) {
	if len(args) <= index || args[index].Type() != js.TypeString {
		return "", fmt.Errorf("missing handle")
	}
	return args[index].String(), nil
}

func bytesFromArg(args []js.Value, index int) ([]byte, error) {
	if len(args) <= index {
		return nil, fmt.Errorf("missing bytes argument")
	}
	src := args[index]
	n := src.Get("byteLength")
	if n.Type() != js.TypeNumber {
		return nil, fmt.Errorf("expected Uint8Array")
	}
	out := make([]byte, n.Int())
	if len(out) > 0 {
		js.CopyBytesToGo(out, src)
	}
	return out, nil
}

func jsBytes(src []byte) js.Value {
	out := js.Global().Get("Uint8Array").New(len(src))
	if len(src) > 0 {
		js.CopyBytesToJS(out, src)
	}
	return out
}

func readWitness(curveID ecc.ID, data []byte) (witness.Witness, error) {
	w, err := witness.New(curveID.ScalarField())
	if err != nil {
		return nil, err
	}
	if _, err := w.ReadFrom(bytes.NewReader(data)); err != nil {
		return nil, err
	}
	return w, nil
}

func readFromBytes(value any, label string, data []byte) error {
	reader, ok := value.(interface {
		ReadFrom(io.Reader) (int64, error)
	})
	if !ok {
		return fmt.Errorf("%s does not support ReadFrom", label)
	}
	if _, err := reader.ReadFrom(bytes.NewReader(data)); err != nil {
		return fmt.Errorf("read %s: %w", label, err)
	}
	return nil
}

func writeToBytes(value any) ([]byte, error) {
	writer, ok := value.(interface {
		WriteTo(io.Writer) (int64, error)
	})
	if !ok {
		return nil, fmt.Errorf("value does not support WriteTo")
	}
	var buf bytes.Buffer
	if _, err := writer.WriteTo(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
