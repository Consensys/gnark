package gkrcore_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/internal/gkr/gkrcore"
	"github.com/consensys/gnark/internal/gkr/gkrtesting"
	"github.com/stretchr/testify/require"
)

var scheduleTestCache = gkrtesting.NewCache(ecc.BN254.ScalarField())

func TestDefaultProvingSchedulePoseidon2(t *testing.T) {
	_, c := scheduleTestCache.Compile(t, gkrtesting.Poseidon2Circuit(4, 2))
	schedule, err := gkrcore.DefaultProvingSchedule(c)
	require.NoError(t, err)

	// Wire layout for Poseidon2Circuit(4, 2) — 25 wires total:
	//   0, 1      inputs
	//   2–5       full-round 0  (lin0, lin1, sBox0, sBox1)
	//   6–9       full-round 1  (lin0, lin1, sBox0, sBox1)
	//   10–12     partial-round 0  (lin0, lin1, sBox0)
	//   13–15     partial-round 1  (lin0, lin1, sBox0)
	//   16–19     full-round 2  (lin0, lin1, sBox0, sBox1)
	//   20–23     full-round 3  (lin0, lin1, sBox0, sBox1)
	//   24        feed-forward output
	//
	// Claim source indices refer to levels (post-reversal); 17 = len(schedule) = initial challenge.
	//
	// Linear wires (degree 1, single claim source) become SkipLevels.
	// S-box wires (degree 2) become SumcheckLevels.
	// The two s-boxes of a full round share identical claim sources and are batched together.
	// Full-round 1 s-boxes (wires 8, 9) feed three downstream sumchecks: partial-round 0 s-box
	// (level 8), partial-round 1 s-box (level 11), and full-round 2 s-boxes (level 13).
	expected := gkrcore.ProvingSchedule{

		// Level 0: input[0] — single claim source: full-round 0 s-boxes at level 3.
		gkrcore.SkipLevel{Wires: []int{0}, ClaimSources: []int{3}},
		// Level 1: input[1] — feeds full-round 0 s-boxes (level 3) and the feed-forward (level 17 = initial challenge).
		gkrcore.SkipLevel{Wires: []int{1}, ClaimSources: []int{17, 3}},

		// Level 2: full-round 0 lin1+lin0 (degree 1, batched) — claim source: full-round 0 s-boxes at level 3.
		gkrcore.SkipLevel{Wires: []int{3, 2}, ClaimSources: []int{3}},
		// Level 3: full-round 0 sBox1+sBox0 (degree 2, batched) — claim source: full-round 1 s-boxes at level 5.
		gkrcore.SumcheckLevel{{Wires: []int{5, 4}, ClaimSources: []int{5}}},

		// Level 4: full-round 1 lin1+lin0 (degree 1, batched) — claim source: full-round 1 s-boxes at level 5.
		gkrcore.SkipLevel{Wires: []int{7, 6}, ClaimSources: []int{5}},
		// Level 5: full-round 1 sBox1+sBox0 (degree 2, batched) — three downstream sumchecks.
		gkrcore.SumcheckLevel{{Wires: []int{9, 8}, ClaimSources: []int{13, 11, 8}}},

		// Level 6: partial-round 0 lin0 (degree 1) — claim source: partial-round 0 s-box at level 8.
		gkrcore.SkipLevel{Wires: []int{10}, ClaimSources: []int{8}},
		// Level 7: partial-round 0 lin1 (degree 1) — feeds partial-round 1 s-box (level 11) and full-round 2 s-boxes (level 13).
		gkrcore.SkipLevel{Wires: []int{11}, ClaimSources: []int{13, 11}},
		// Level 8: partial-round 0 sBox0 (degree 2) — feeds partial-round 1 lin0+lin1.
		gkrcore.SumcheckLevel{{Wires: []int{12}, ClaimSources: []int{13, 11}}},

		// Level 9: partial-round 1 lin0 (degree 1) — claim source: partial-round 1 s-box at level 11.
		gkrcore.SkipLevel{Wires: []int{13}, ClaimSources: []int{11}},
		// Level 10: partial-round 1 lin1 (degree 1) — claim source: full-round 2 s-boxes at level 13.
		gkrcore.SkipLevel{Wires: []int{14}, ClaimSources: []int{13}},
		// Level 11: partial-round 1 sBox0 (degree 2) — claim source: full-round 2 s-boxes at level 13.
		gkrcore.SumcheckLevel{{Wires: []int{15}, ClaimSources: []int{13}}},

		// Level 12: full-round 2 lin1+lin0 (degree 1, batched) — claim source: full-round 2 s-boxes at level 13.
		gkrcore.SkipLevel{Wires: []int{17, 16}, ClaimSources: []int{13}},
		// Level 13: full-round 2 sBox1+sBox0 (degree 2, batched) — claim source: full-round 3 s-boxes at level 15.
		gkrcore.SumcheckLevel{{Wires: []int{19, 18}, ClaimSources: []int{15}}},

		// Level 14: full-round 3 lin1+lin0 (degree 1, batched) — claim source: full-round 3 s-boxes at level 15.
		gkrcore.SkipLevel{Wires: []int{21, 20}, ClaimSources: []int{15}},
		// Level 15: full-round 3 sBox1+sBox0 (degree 2, batched) — claim source: initial challenge (17).
		gkrcore.SumcheckLevel{{Wires: []int{23, 22}, ClaimSources: []int{17}}},

		// Level 16: feed-forward output (degree 1) — claim source: initial challenge (17).
		gkrcore.SkipLevel{Wires: []int{24}, ClaimSources: []int{17}},
	}
	require.Equal(t, expected, schedule)
}

func TestBasicProvingSchedule(t *testing.T) {
	_, c := scheduleTestCache.Compile(t, gkrtesting.SingleMulGateCircuit())
	schedule, err := gkrcore.BasicProvingSchedule(c)
	require.NoError(t, err)

	// SingleMulGateCircuit has wires 0, 1 (inputs) and 2 (mul gate).
	// Claim source indices refer to levels; 3 = len(schedule) = initial challenge.
	require.Equal(t, gkrcore.ProvingSchedule{
		// Level 0: input[0] — claim source: mul gate at level 2.
		gkrcore.SkipLevel{Wires: []int{0}, ClaimSources: []int{2}},
		// Level 1: input[1] — claim source: mul gate at level 2.
		gkrcore.SkipLevel{Wires: []int{1}, ClaimSources: []int{2}},
		// Level 2: mul gate output (degree 2) — claim source: initial challenge (3).
		gkrcore.SumcheckLevel{{Wires: []int{2}, ClaimSources: []int{3}}},
	}, schedule)
}
