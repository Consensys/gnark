package poseidon2

import (
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	gkrFr "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/gkr"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestGkrFrGates(t *testing.T) {

	const (
		rF  = 4
		rP  = 2
		d   = 3
		in0 = 0
		in1 = 0
	)
	roundKeys := make([][]fr.Element, rF+rP)
	k := int64(1)
	for i := range roundKeys {
		roundKeys[i] = make([]fr.Element, 2)
		for j := range roundKeys[i] {
			roundKeys[i][j].SetInt64(k)
			k++
		}
	}

	// compute output in the real world

	halfRf := rF / 2
	var x, y fr.Element
	_, err := x.SetInterface(in0)
	require.NoError(t, err)
	_, err = y.SetInterface(in1)
	require.NoError(t, err)

	fullRound := func(i int) {
		gate := extKeySBoxGateFr{
			d: d,
		}
		gate.roundKey = roundKeys[i][0]

		x1 := gate.Evaluate(x, y)

		gate.roundKey = roundKeys[i][1]
		x, y = x1, gate.Evaluate(y, x)

	}

	for i := range halfRf {
		fullRound(i)
	}

	var tmp fr.Element
	{ // i = halfRf: first partial round
		tmp = roundKeys[halfRf][0]
		var gate gkrFr.Gate = &extKeySBoxGateFr{
			roundKey: tmp,
			d:        d,
		}
		x1 := gate.Evaluate(x, y)

		tmp = roundKeys[halfRf][1]
		gate = &extKeyGate2Fr{
			roundKey: tmp,
			d:        d,
		}
		x, y = x1, gate.Evaluate(x, y)
	}

	for i := halfRf + 1; i < halfRf+rP; i++ {
		tmp = roundKeys[i][0]
		var gate gkrFr.Gate = &extKeySBoxGateFr{ // for x1, intKeySBox is identical to extKeySBox
			roundKey: tmp,
			d:        d,
		}
		x1 := gate.Evaluate(x, y)

		tmp = roundKeys[i][1]
		gate = &intKeyGate2Fr{
			roundKey: tmp,
			d:        d,
		}
		x, y = x1, gate.Evaluate(x, y)
	}

	{
		i := halfRf + rP
		tmp = roundKeys[i][0]
		var gate gkrFr.Gate = &extKeySBoxGateFr{
			roundKey: tmp,
			d:        d,
		}
		x1 := gate.Evaluate(x, y)

		tmp = roundKeys[i][1]
		gate = &intKeySBoxGate2Fr{
			roundKey: tmp,
			d:        d,
		}
		x, y = x1, gate.Evaluate(x, y)
	}

	for i := halfRf + rP + 1; i < rP+rF; i++ {
		fullRound(i)
	}

	y = extGateFr{}.Evaluate(y, x)

	_, err = tmp.SetString("1414568327995419415796839718524742280557393295919067110634980642502386288678")
	require.NoError(t, err)

	require.Equal(t, tmp, y)
}
