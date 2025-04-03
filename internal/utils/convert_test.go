// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package utils

import (
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func TestFromInterfaceValidFormats(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("valid input should not panic")
		}
	}()

	var a fr.Element
	_, _ = a.SetRandom()

	_, err := FromInterface(a)
	assert.NoError(t, err)

	_, err = FromInterface(&a)
	assert.NoError(t, err)

	_, err = FromInterface(12)
	assert.NoError(t, err)

	_, err = FromInterface(big.NewInt(-42))
	assert.NoError(t, err)

	_, err = FromInterface(*big.NewInt(42))
	assert.NoError(t, err)

	_, err = FromInterface("8000")
	assert.NoError(t, err)

}
