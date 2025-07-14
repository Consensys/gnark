package uints

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/kvstore"
	"github.com/consensys/gnark/std/internal/logderivprecomp"
	"github.com/consensys/gnark/std/rangecheck"
)

// ctxKey is used to store the API in the key-value store. In case we
// re-initialize using [NewBytes] method, then we can reuse the existing API. This
// ensures we don't rebuild any of the tables.
type ctxKey struct{}

// Bytes implements methods for manipulating bytes in circuit. Use [NewBytes] to
// create a new instance.
type Bytes struct {
	api             frontend.API
	xorT, andT, orT *logderivprecomp.Precomputed
	rchecker        frontend.Rangechecker
	allOne          U8
}

// NewBytes creates a new [Bytes] instance which can manipulate bytes and byte
// arrays. For manipulating long integers, use [BinaryField] instead.
//
// This is a caching constructor, meaning that it will return the same instance
// if called multiple times. This is useful as internally it uses lookup tables
// for bitwise operations and it amortizes the cost of creating these lookup
// tables.
func NewBytes(api frontend.API) (*Bytes, error) {
	if kv, ok := api.(kvstore.Store); ok {
		uapi := kv.GetKeyValue(ctxKey{})
		if tuapi, ok := uapi.(*Bytes); ok {
			return tuapi, nil
		}
	}
	xorT, err := logderivprecomp.New(api, xorHint, []uint{8})
	if err != nil {
		return nil, fmt.Errorf("new xor table: %w", err)
	}
	andT, err := logderivprecomp.New(api, andHint, []uint{8})
	if err != nil {
		return nil, fmt.Errorf("new and table: %w", err)
	}
	orT, err := logderivprecomp.New(api, orHint, []uint{8})
	if err != nil {
		return nil, fmt.Errorf("new or table: %w", err)
	}
	rchecker := rangecheck.New(api)
	bf := &Bytes{
		api:      api,
		xorT:     xorT,
		andT:     andT,
		orT:      orT,
		rchecker: rchecker,
	}
	// TODO: this is const. add way to init constants
	bf.allOne = bf.ValueOf(0xff)

	// store the API in the key-value store so that can be easily reused
	if kv, ok := api.(kvstore.Store); ok {
		kv.SetKeyValue(ctxKey{}, bf)
	}
	return bf, nil
}

// ValueOf returns a constrainted [U8] variable. For a constant value, use
// [NewU8] instead.
func (bf *Bytes) ValueOf(a frontend.Variable) U8 {
	bf.rchecker.Check(a, 8)
	return U8{Val: a, internal: true}
}

func (bf *Bytes) twoArgFn(tbl *logderivprecomp.Precomputed, a ...U8) U8 {
	if len(a) == 0 {
		return NewU8(0)
	}
	if len(a) == 1 {
		return a[0]
	}
	ret := tbl.Query(a[0].Val, a[1].Val)[0]
	for i := 2; i < len(a); i++ {
		ret = tbl.Query(ret, a[i].Val)[0]
	}
	return U8{Val: ret}
}

func (bf *Bytes) Not(a U8) U8 {
	ret := bf.xorT.Query(a.Val, bf.allOne.Val)
	return U8{Val: ret[0]}
}

func (bf *Bytes) And(a ...U8) U8 { return bf.twoArgFn(bf.andT, a...) }
func (bf *Bytes) Or(a ...U8) U8  { return bf.twoArgFn(bf.orT, a...) }
func (bf *Bytes) Xor(a ...U8) U8 { return bf.twoArgFn(bf.xorT, a...) }

func (bf *Bytes) AssertIsEqual(a, b U8) {
	bf.api.AssertIsEqual(a.Val, b.Val)
}
