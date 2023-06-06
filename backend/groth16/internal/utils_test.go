package internal

import (
	"github.com/stretchr/testify/assert"
	"math/big"
	"math/rand"
	"testing"
)

type coinToss struct {
	x         uint64
	remaining byte
}

func (r *coinToss) rand() (res bool) {
	if r.remaining == 0 {
		r.x = rand.Uint64()
		r.remaining = 64
	}
	r.remaining--
	if r.x&1 == 1 {
		res = true
	}
	r.x /= 2
	return
}

func createX(size int) []*big.Int {
	x := make([]*big.Int, size)
	for i := range x {
		x[i] = big.NewInt(int64(i))
	}
	return x
}

func toInts(x []*big.Int) []int64 {
	res := make([]int64, len(x))
	for i := range x {
		res[i] = x[i].Int64()
	}
	return res
}

func TestDivideByThresholdOrList(t *testing.T) {
	x := createX(10)
	list := make([]int, 0, len(x))
	var r coinToss
	for threshold := range x {
		// reset x
		for i := range x {
			x[i].SetInt64(int64(i))
		}

		// prepare list
		list = list[:0]
		for i := threshold; i < len(x); i++ {
			if r.rand() {
				list = append(list, i)
			}
		}

		// get result from DivideByThresholdOrList
		_, _ = DivideByThresholdOrList(threshold, list, x)
		for i := 0; i < threshold; i++ {
			assert.Equal(t, int64(i), x[i].Int64())
		}
		for i := range list {
			assert.Equal(t, int64(list[i]), x[threshold+i].Int64())
		}
		prev := int64(-1)
		j := 0
		for i := threshold + len(list); i < len(x); i++ {
			cur := x[i].Int64()
			assert.Less(t, prev, cur)

			for j < len(list) && int64(list[j]) < cur {
				j++
			}
			if j < len(list) && int64(list[j]) == cur {
				t.Error("value on list present")
			}
		}
	}
}

func TestDivideByThresholdOrListLen2(t *testing.T) {
	x := createX(2)
	_, _ = DivideByThresholdOrList(0, []int{1}, x)
	xAsInts := toInts(x)
	assert.Equal(t, []int64{1, 0}, xAsInts)
}

func TestDivideByThresholdOrListLen3(t *testing.T) {
	x := createX(3)
	_, _ = DivideByThresholdOrList(1, []int{2}, x)
	xAsInts := toInts(x)
	assert.Equal(t, []int64{0, 2, 1}, xAsInts)
}

func TestDivideByThresholdOrListLen4(t *testing.T) {
	x := createX(4)
	_, _ = DivideByThresholdOrList(1, []int{1, 3}, x)
	xAsInts := toInts(x)
	assert.Equal(t, []int64{0, 1, 3, 2}, xAsInts)
}
