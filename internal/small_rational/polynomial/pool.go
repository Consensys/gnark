// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package polynomial

import (
	"github.com/consensys/gnark-crypto/internal/generator/test_vector_utils/small_rational"
)

// Do as little as possible to instantiate the interface
type Pool struct {
}

func NewPool(...int) (pool Pool) {
	return Pool{}
}

func (p *Pool) Make(n int) []small_rational.SmallRational {
	return make([]small_rational.SmallRational, n)
}

func (p *Pool) Dump(...[]small_rational.SmallRational) {
}

func (p *Pool) Clone(slice []small_rational.SmallRational) []small_rational.SmallRational {
	res := p.Make(len(slice))
	copy(res, slice)
	return res
}
