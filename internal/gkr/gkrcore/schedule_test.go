package gkrcore_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/internal/gkr/gkrcore"
	"github.com/consensys/gnark/internal/gkr/gkrtesting"
	"github.com/stretchr/testify/require"
)

var scheduleTestCache = gkrtesting.NewCache(ecc.BN254.ScalarField())

func TestDefaultProvingSchedule(t *testing.T) {
	_, c := scheduleTestCache.Compile(t, gkrtesting.SingleMulGateCircuit())
	schedule, err := gkrcore.DefaultProvingSchedule(c)
	require.NoError(t, err)

	// SingleMulGateCircuit: wires 0, 1 (inputs), 2 (mul gate with inputs 0, 1).
	// UniqueGateInputs for level 2 (wire 2) = [0, 1].
	// 3 = len(schedule) = initial challenge sentinel.
	require.Equal(t, constraint.GkrProvingSchedule{
		// Level 0: input wire 0, position 0 in mul gate's UniqueGateInputs [0, 1]
		constraint.GkrSkipLevel{Wires: []int{0}, ClaimSources: []constraint.GkrClaimSource{{Level: 2}}},
		// Level 1: input wire 1, position 1 in mul gate's UniqueGateInputs [0, 1]
		constraint.GkrSkipLevel{Wires: []int{1}, ClaimSources: []constraint.GkrClaimSource{{Level: 2}}},
		// Level 2: mul gate output, claimed by initial challenge (sentinel)
		constraint.GkrSumcheckLevel{{Wires: []int{2}, ClaimSources: []constraint.GkrClaimSource{{Level: 3}}}},
	}, schedule)
}

func TestDefaultProvingSchedulePoseidon2(t *testing.T) {
	_, c := scheduleTestCache.Compile(t, gkrtesting.Poseidon2Circuit(4, 2))
	schedule, err := gkrcore.DefaultProvingSchedule(c)
	require.NoError(t, err)

	// Wire layout for Poseidon2Circuit(4, 2) — 25 wires total:
	//   0, 1            inputs
	//   2–3             full-round 0 lin (lin0=2, lin1=3)
	//   4–5             full-round 0 sBox (sBox0=4, sBox1=5)
	//   6–7             full-round 1 lin (lin0=6, lin1=7)
	//   8–9             full-round 1 sBox (sBox0=8, sBox1=9)
	//   10–11           partial-round 0 lin (lin0=10, lin1=11)
	//   12              partial-round 0 sBox0
	//   13–14           partial-round 1 lin (lin0=13, lin1=14)
	//   15              partial-round 1 sBox0
	//   16–17           full-round 2 lin (lin0=16, lin1=17)
	//   18–19           full-round 2 sBox (sBox0=18, sBox1=19)
	//   20–21           full-round 3 lin (lin0=20, lin1=21)
	//   22–23           full-round 3 sBox (sBox0=22, sBox1=23)
	//   24              feed-forward output
	//
	// 17 = len(schedule) = initial challenge sentinel.
	require.Equal(t, constraint.GkrProvingSchedule{
		// Level 0: input wire 0 — claimed by level 2 (full-round 0 lin1+lin0 skip).
		constraint.GkrSkipLevel{Wires: []int{0}, ClaimSources: []constraint.GkrClaimSource{{Level: 2}}},

		// Level 1: input wire 1 — claimed by level 2 and level 16 (feed-forward skip).
		constraint.GkrSkipLevel{Wires: []int{1}, ClaimSources: []constraint.GkrClaimSource{{Level: 2}, {Level: 16}}},

		// Level 2: full-round 0 lin1+lin0 (skip, inputs from wires 0 and 1).
		constraint.GkrSkipLevel{Wires: []int{3, 2}, ClaimSources: []constraint.GkrClaimSource{{Level: 3}}},

		// Level 3: full-round 0 sBox1+sBox0 (sumcheck).
		constraint.GkrSumcheckLevel{{Wires: []int{5, 4}, ClaimSources: []constraint.GkrClaimSource{{Level: 4}}}},

		// Level 4: full-round 1 lin1+lin0 (skip, inputs [4, 5]).
		constraint.GkrSkipLevel{Wires: []int{7, 6}, ClaimSources: []constraint.GkrClaimSource{{Level: 5}}},

		// Level 5: full-round 1 sBox1+sBox0 (sumcheck, inputs lin1=7 and lin0=6).
		//   Feeds into level 6 (partial-round 0 lin0, M=1) and level 7 (partial-round 0 lin1, M=2).
		constraint.GkrSumcheckLevel{{Wires: []int{9, 8}, ClaimSources: []constraint.GkrClaimSource{{Level: 6}, {Level: 7}, {Level: 7, OutgoingClaimIndex: 1}}}},

		// Level 6: partial-round 0 lin0 (skip, inputs [8, 9]).
		constraint.GkrSkipLevel{Wires: []int{10}, ClaimSources: []constraint.GkrClaimSource{{Level: 8}}},

		// Level 7: partial-round 0 lin1 (skip, inputs [8, 9]). M=2 (two claim sources).
		constraint.GkrSkipLevel{Wires: []int{11}, ClaimSources: []constraint.GkrClaimSource{{Level: 9}, {Level: 10}}},

		// Level 8: partial-round 0 sBox0 (sumcheck, input lin0=10).
		constraint.GkrSumcheckLevel{{Wires: []int{12}, ClaimSources: []constraint.GkrClaimSource{{Level: 9}, {Level: 10}}}},

		// Level 9: partial-round 1 lin0 (skip, inputs [12, 11]).
		constraint.GkrSkipLevel{Wires: []int{13}, ClaimSources: []constraint.GkrClaimSource{{Level: 11}}},

		// Level 10: partial-round 1 lin1 (skip, inputs [12, 11]).
		constraint.GkrSkipLevel{Wires: []int{14}, ClaimSources: []constraint.GkrClaimSource{{Level: 12}}},

		// Level 11: partial-round 1 sBox0 (sumcheck, input lin0=13).
		constraint.GkrSumcheckLevel{{Wires: []int{15}, ClaimSources: []constraint.GkrClaimSource{{Level: 12}}}},

		// Level 12: full-round 2 lin1+lin0 (skip, inputs [15, 14]).
		constraint.GkrSkipLevel{Wires: []int{17, 16}, ClaimSources: []constraint.GkrClaimSource{{Level: 13}}},

		// Level 13: full-round 2 sBox1+sBox0 (sumcheck, inputs lin1=17 and lin0=16).
		constraint.GkrSumcheckLevel{{Wires: []int{19, 18}, ClaimSources: []constraint.GkrClaimSource{{Level: 14}}}},

		// Level 14: full-round 3 lin1+lin0 (skip, inputs [18, 19]).
		constraint.GkrSkipLevel{Wires: []int{21, 20}, ClaimSources: []constraint.GkrClaimSource{{Level: 15}}},

		// Level 15: full-round 3 sBox1+sBox0 (sumcheck, inputs lin1=21 and lin0=20).
		constraint.GkrSumcheckLevel{{Wires: []int{23, 22}, ClaimSources: []constraint.GkrClaimSource{{Level: 16}}}},

		// Level 16: feed-forward output (skip, inputs [22, 23, 1]). Claimed by initial challenge (17).
		constraint.GkrSkipLevel{Wires: []int{24}, ClaimSources: []constraint.GkrClaimSource{{Level: 17}}},
	}, schedule)
}
