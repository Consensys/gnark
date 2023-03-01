/*
Package permutation implements AS-Waksman routing network.

Arbitrary size (AS) Waksman routing network is a network of layered switches
between two wires which allows to reorder the inputs in any order by defining
the switch states. The asymptotic complexity of the permutation network is `O(n
log(n))' gates for input of size `n'.

See "[On Arbitrary Waksman Networks and their Vulnerability]" by Beauquier and
Darrot for description of the construction of the network.

This is internal low-level package. For using the routing in the circuit, refer
to high-level package [github.com/consensys/gnark/std/lookup] or upcoming
RAM/rangecheck packages.

[On Arbitrary Waksman Networks and their Vulnerability]: https://hal.inria.fr/inria-00072871/document
*/
package permutation

import (
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"
)

// Permutation defines a permutation of a vector. It is an array of pairs
// mapping index to index. See [Index] and [Sorted] for creating permutations.
type Permutation [][2]int

func (p Permutation) isValid() bool {
	// all indices must exist
	a1 := make(map[int]struct{})
	a2 := make(map[int]struct{})
	for i := range p {
		if _, ok := a1[p[i][0]]; ok {
			return false
		}
		if _, ok := a2[p[i][1]]; ok {
			return false
		}
		a1[p[i][0]] = struct{}{}
		a2[p[i][1]] = struct{}{}
	}
	if len(a1) != len(p) || len(a2) != len(p) {
		return false
	}
	for i := 0; i < len(p); i++ {
		if _, ok := a1[i]; !ok {
			return false
		}
		if _, ok := a2[i]; !ok {
			return false
		}
	}
	return true
}

// Index returns an identity permutation. An identity permutation maps every
// element to the same location.
func Index(length int) Permutation {
	r := make(Permutation, length)
	for i := 0; i < length; i++ {
		r[i] = [2]int{i, i}
	}
	return r
}

// Sorted returns a permutation which sorts the input in increasing order.
func Sorted[T interface{ *big.Int | int }](in []T) Permutation {
	p := make(Permutation, len(in))
	for i := range p {
		p[i][0] = i
		p[i][1] = i
	}
	switch vv := any(in).(type) {
	case []*big.Int:
		sort.Slice(p, func(i, j int) bool {
			return vv[p[i][0]].Cmp(vv[p[j][0]]) < 0
		})
	case []int:
		sort.Slice(p, func(i, j int) bool {
			return vv[p[i][1]] < vv[p[j][1]]
		})
	default:
		panic("unknown type")
	}
	for i := range p {
		p[i][1] = i
	}
	return p
}

func permutationFromMapping(before, after []int) Permutation {
	if len(before) != len(after) {
		panic("diff lengths")
	}
	afterMap := make(map[int]int)
	for i, v := range after {
		afterMap[v] = i
	}
	p := make(Permutation, len(before))
	for i, v := range before {
		p[i] = [2]int{i, afterMap[v]}
	}
	return p
}

type vertex struct {
	vals  []int
	edges []*edge
	index int
}

func (v vertex) String() string {
	var es []string
	for _, e := range v.edges {
		es = append(es, e.String())
	}
	var vs []string
	for _, vv := range v.vals {
		vs = append(vs, strconv.Itoa(vv))
	}
	return fmt.Sprintf("V([%s], {%s})",
		strings.Join(vs, ","), strings.Join(es, ","))
}

func (v vertex) degreeUnknown() int {
	var d int
	for _, e := range v.edges {
		if e.direction == none {
			d++
		}
	}
	return d
}

type direction string

const (
	up   direction = "UP"
	down direction = "DOWN"
	none direction = "?"
)

func (d direction) other() direction {
	switch d {
	case up:
		return down
	case down:
		return up
	default:
		return none
	}
}

type edge struct {
	vertices   [2]*vertex
	permPoints [2]int
	direction
}

func (e edge) String() string {
	return fmt.Sprintf("E(%d <-> %d: direction: %s)",
		e.permPoints[0], e.permPoints[1], e.direction)
}

type bipartite struct {
	left         []*vertex
	right        []*vertex
	edges        []*edge
	len          int
	isColored    bool
	isOdd        bool
	preSwitches  []SwitchState
	postSwitches []SwitchState
}

// newBipartite constructs a new bipartite graph from the given permutation. For
// both sides we construct vertices from the two consecutive indices in the
// permutation. The method errs if the permutation is not valid.
func newBipartite(p Permutation) (*bipartite, error) {
	if !p.isValid() {
		return nil, fmt.Errorf("invalid permuation")
	}
	bp := bipartite{
		left:         make([]*vertex, (len(p)+1)/2),
		right:        make([]*vertex, (len(p)+1)/2),
		len:          len(p),
		isOdd:        len(p)%2 == 1,
		isColored:    false,
		preSwitches:  nil,
		postSwitches: nil,
	}
	// we first create the vertices for both sides.
	for i := 0; i < len(p)/2; i++ {
		bp.left[i] = &vertex{
			vals:  make([]int, 2),
			index: i,
		}
		bp.right[i] = &vertex{
			vals:  make([]int, 2),
			index: i,
		}
	}
	// special case if the length of the permutation is not even. The last
	// vertex has only a single adjacent edge.
	if bp.isOdd {
		bp.left[len(p)/2] = &vertex{
			vals:  make([]int, 1),
			index: len(p) / 2,
		}
		bp.right[len(p)/2] = &vertex{
			vals:  make([]int, 1),
			index: len(p) / 2,
		}
	}
	// now, we initialise the edges. The edges are not colored yet, we have the
	// [bipartite.color] for the coloring.
	for _, pp := range p {
		bp.left[pp[0]/2].vals[pp[0]%2] = pp[0]
		bp.right[pp[1]/2].vals[pp[1]%2] = pp[0]
		edge := &edge{
			vertices: [2]*vertex{
				bp.left[pp[0]/2],
				bp.right[pp[1]/2],
			},
			permPoints: [2]int{pp[0], pp[1]},
			direction:  none,
		}
		edge.vertices[0].edges = append(edge.vertices[0].edges, edge)
		edge.vertices[1].edges = append(edge.vertices[1].edges, edge)
		bp.edges = append(bp.edges, edge)
	}
	return &bp, nil
}

func (bp bipartite) String() string {
	var ls, rs []string
	for _, l := range bp.left {
		ls = append(ls, l.String())
	}
	for _, r := range bp.right {
		rs = append(rs, r.String())
	}
	return fmt.Sprintf("left %s\nright %s",
		strings.Join(ls, "\n"), strings.Join(rs, "\n"))
}

// hasUnknown returns a boolean indicating if there are any uncolored edges left.
func (bp bipartite) hasUnknown() bool {
	// TODO: actually, a better approach would be to keep track of the least
	// indices of the vertices on both sides which we know for sure are
	// uncolored. if the indices are larger than the lengths of the vertices
	// slices, then return false.
	for _, l := range bp.left {
		if l.degreeUnknown() > 0 {
			return true
		}
	}
	for _, l := range bp.right {
		if l.degreeUnknown() > 0 {
			return true
		}
	}
	return false
}

// color colors the edges. In this implementation the coloring is deterministic,
// but not unique.
func (bp *bipartite) color() {
	if bp.isColored {
		return
	}
	if bp.isOdd {
		// the lower subnetwork is always larger if the subnetwork are uneven.
		bp.left[len(bp.left)-1].edges[0].direction = down
		bp.right[len(bp.right)-1].edges[0].direction = down
	} else {
		// must ensure that the lower right does not swap. set the edge
		// direction which enforces that.
		if bp.right[len(bp.right)-1].vals[0] == bp.right[len(bp.right)-1].edges[0].permPoints[0] {
			bp.right[len(bp.right)-1].edges[0].direction = up
			bp.right[len(bp.right)-1].edges[1].direction = down
		} else {
			bp.right[len(bp.right)-1].edges[0].direction = down
			bp.right[len(bp.right)-1].edges[1].direction = up
		}
	}
	// coloring function. If the uncolor degree of vertex is 1, then color the
	// other edge with other color.
	allOtherColor := func(vs []*vertex) bool {
		var colored bool
		for _, v := range vs {
			if v.degreeUnknown() == 1 {
				if v.edges[0].direction != none {
					v.edges[1].direction = v.edges[0].other()
				} else {
					v.edges[0].direction = v.edges[1].other()
				}
				colored = true
			}
		}
		return colored
	}
	// we color until everything is colored.
	for bp.hasUnknown() {
		// color once on the left side
		c1 := allOtherColor(bp.left)
		// color on the right side
		c2 := allOtherColor(bp.right)
		// if we colored anything, then restart to find any vertices of
		// uncolored degree 1
		if c1 || c2 {
			continue
		}
		// there wasn't any uncolored degree 1 vertex. We choose a first vertex
		// of uncolor degree 2 and color its adjacent edges with different
		// colors.

		// TODO: this is not most efficient approach. we could keep
		// track of the first uncolored degree 2 vertex and start from there.
		// Then we wouldn't have to iterate over same vertices all the time.
		for _, v := range bp.left {
			if v.degreeUnknown() == 2 {
				v.edges[0].direction = up
				v.edges[1].direction = down
				break
			}
		}
	}
	bp.isColored = true
}

// SwitchState defines the state of the switch. There are two valid states --
// passthrough (STRAIGHT) or swap (SWAP).
type SwitchState uint

const (
	// STRAIGHT switch should not switch inputs.
	STRAIGHT SwitchState = 0
	// SWAP switch should swap the inputs.
	SWAP SwitchState = 1
	// wire is a direct connection. It corresponds to STRAIGHT switch but we do
	// not call the routing callback.
	wire SwitchState = 2
)

func newSwitch(isSwap bool) SwitchState {
	if isSwap {
		return SWAP
	}
	return STRAIGHT
}

func (ss SwitchState) String() string {
	switch ss {
	case STRAIGHT:
		return "straight"
	case SWAP:
		return "swap"
	case wire:
		return "wire"
	}
	panic("invalid")
}

func (ss SwitchState) int() int {
	return int(ss % 2)
}

// switchStates returns the states of the switches before and after routing the
// wires to the sub-networks.
func (bp *bipartite) switchStates() (pre, post []SwitchState) {
	if bp.preSwitches != nil && bp.postSwitches != nil {
		return bp.preSwitches, bp.postSwitches
	}
	if !bp.isColored {
		bp.color()
	}
	l := len(bp.left)
	if bp.isOdd {
		l--
	}
	pre = make([]SwitchState, l)
	post = make([]SwitchState, l)
	for i := 0; i < l; i++ {
		pre[i] = newSwitch((bp.left[i].edges[0].direction == up) != (bp.left[i].vals[0] == bp.left[i].edges[0].permPoints[0]))
		post[i] = newSwitch((bp.right[i].edges[0].direction == up) != (bp.right[i].vals[0] == bp.right[i].edges[0].permPoints[0]))
	}
	if bp.isOdd {
		pre = append(pre, wire)
		post = append(post, wire)
	} else {
		// set last post switch to wire.
		if post[len(post)-1] != STRAIGHT {
			panic("last post switch should be straight")
		}
		post[len(post)-1] = wire
	}
	bp.preSwitches = pre
	bp.postSwitches = post
	return
}

// innerPermutations returns the inner partitions of the upper and lower
// networks for recursion. It also returns the actual values going into either
// network after the switches have been applied.
func innerPermutations[T any](bp *bipartite, vals []T) (upper, lower Permutation, upperVals, lowerVals []T) {
	pre, post := bp.switchStates()
	var ui, li int
	upperPre, upperPost := make([]int, bp.len/2), make([]int, bp.len/2)
	lowerPre, lowerPost := make([]int, (bp.len+1)/2), make([]int, (bp.len+1)/2)
	upperStraight, lowerStraight := make([]int, len(upperPre)), make([]int, len(lowerPre))
	for i, v := range bp.left {
		if ui >= len(upperPre) {
			ui = 1
		}
		if li >= len(upperPre) {
			li = 1
		}
		if pre[i] == wire {
			lowerPre[len(lowerPre)-1] = v.vals[0]
			lowerStraight[len(lowerStraight)-1] = v.vals[0]
		} else {
			upperPre[ui] = v.vals[pre[i].int()]
			lowerPre[li] = v.vals[1-pre[i].int()]
			upperStraight[ui] = v.vals[0]
			lowerStraight[li] = v.vals[1]
		}
		ui += 2
		li += 2
	}
	ui, li = 0, 0
	for i, v := range bp.right {
		if ui >= len(upperPost) {
			ui = 1
		}
		if li >= len(upperPost) {
			li = 1
		}
		if post[i] == wire {
			if len(v.vals) == 1 {
				lowerPost[len(lowerPost)-1] = v.vals[0]
			} else {
				upperPost[ui] = v.vals[0]
				lowerPost[li] = v.vals[1]
			}
		} else {
			upperPost[ui] = v.vals[post[i].int()]
			lowerPost[li] = v.vals[1-post[i].int()]
		}
		ui += 2
		li += 2
	}
	upper = permutationFromMapping(upperPre, upperPost)
	lower = permutationFromMapping(lowerPre, lowerPost)
	upperVals = make([]T, len(upperPre))
	for i, v := range upperStraight {
		upperVals[i] = vals[v]
	}
	lowerVals = make([]T, len(lowerPre))
	for i, v := range lowerStraight {
		lowerVals[i] = vals[v]
	}
	return upper, lower, upperVals, lowerVals
}

// merge merges the output values from the subnetworks for feeding into the
// switches in recursing network.
func merge[T any](upperVals, lowerVals []T) []T {
	l := (len(upperVals) + len(lowerVals)) / 2
	if l%2 == 1 {
		l++
	}
	res := make([]T, 2*len(lowerVals))
	for i := 0; i < len(upperVals); i++ {
		if i%2 == 0 {
			res[i] = upperVals[i]
			res[i+1] = lowerVals[i]
		} else {
			res[l+i-1] = upperVals[i]
			res[l+i] = lowerVals[i]
		}
	}
	if len(lowerVals) > len(upperVals) {
		res[len(res)-2] = lowerVals[len(lowerVals)-1]
	}
	return res
}

// buildRoutingRecursive computes the pre- and post-switches for the current
// layer, applies the callback cb on every switch, splits the switched values
// and feeds them into the subnetworks. After the subnetworks have built the
// network, merges the outputs, and applies post-switches. It finally returns
// the permuted values.
func buildRoutingRecursive[T any](p Permutation, cb RoutingCallback[T], vals []T, layer, firstGate int) ([]T, int, error) {
	// we follow the algorithm in the paper. First, we construct a bipartite
	// graph (with every vertex degree 1-2) from the permutation. Then, we color
	// the edges using color "UP" and "DOWN" which indicate into which
	// sub-network the edge goes. When coloring, we keep in mind that two edges
	// adjacent to the same vertex must be different colors. There are also a
	// few edges which have fixed coloring (the edges coming from the last
	// vertex in either part of the bi-partite graph).ß
	bp, err := newBipartite(p)
	if err != nil {
		return nil, 0, fmt.Errorf("new bipartite: %w", err)
	}
	pre, post := bp.switchStates()
	nbSwitch := firstGate
	preValsIn := make([]T, len(vals)+(len(vals)%2))
	copy(preValsIn, vals)
	preValsOut := make([]T, 2*len(pre))
	var layerLoc int
	for i := 0; i < len(pre); i++ {
		if pre[i] != wire {
			preValsOut[2*i], preValsOut[2*i+1] = cb(pre[i], preValsIn[2*i], preValsIn[2*i+1], layer, layerLoc, true, nbSwitch)
			nbSwitch++
			layerLoc++
		} else {
			preValsOut[2*i], preValsOut[2*i+1] = preValsIn[2*i], preValsIn[2*i+1]
		}
	}
	if bp.isOdd {
		preValsOut = preValsOut[:len(preValsOut)-1]
	}
	if len(p) <= 2 {
		return preValsOut, nbSwitch - firstGate, nil
	}
	upper, lower, upperValsIn, lowerValsIn := innerPermutations(bp, preValsOut)
	upperValsOut, nbSwitchUp, err := buildRoutingRecursive(upper, cb, upperValsIn, layer+1, nbSwitch)
	if err != nil {
		return nil, 0, fmt.Errorf("upper: %w", err)
	}
	nbSwitch += nbSwitchUp
	lowerValsOut, nbSwitchDown, err := buildRoutingRecursive(lower, cb, lowerValsIn, layer+1, nbSwitch)
	if err != nil {
		return nil, 0, fmt.Errorf("lower: %w", err)
	}
	nbSwitch += nbSwitchDown
	postValsIn := merge(upperValsOut, lowerValsOut)
	postValsOut := make([]T, 2*len(post))
	layerLoc = 0
	for i := 0; i < len(post); i++ {
		if post[i] != wire {
			postValsOut[2*i], postValsOut[2*i+1] = cb(post[i], postValsIn[2*i], postValsIn[2*i+1], layer, layerLoc, false, nbSwitch)
			nbSwitch++
			layerLoc++
		} else {
			postValsOut[2*i], postValsOut[2*i+1] = postValsIn[2*i], postValsIn[2*i+1]
		}
	}
	if bp.isOdd {
		postValsOut = postValsOut[:len(postValsOut)-1]
	}

	return postValsOut, nbSwitch - firstGate, nil
}

// Route constructs the routing from input vals to output permutedVals using the
// given permutation p. The routing within gates is performed using the routing
// callback cb. If the routing callback is nil, then a default routing is used
// which just outputs the conditionally switched inputs.
func Route[T any](p Permutation, cb RoutingCallback[T], vals []T) (permutedVals []T, nbSwitches int, err error) {
	if len(vals) != len(p) {
		return nil, 0, fmt.Errorf("length of values differs from permutation size")
	}
	if cb == nil {
		cb = defaultRouting[T]
	}
	return buildRoutingRecursive(p, cb, vals, 0, 0)
}

// NbSwithces returns the number of switches in the permutation network for n
// input values.
func NbSwitches(n int) int {
	if n < 2 {
		return 0
	}
	return NbSwitches((n+1)/2) + NbSwitches(n/2) + n - 1
}

// RoutingCallback defines a function which takes as input two wires and outputs
// two wires based on the switch s. It also gets as inputs the exact coordinates
// within the network (layer, layerIndex, pre) and the global index of the gate
// in the network.
type RoutingCallback[T any] func(s SwitchState, inUp, inDown T, layer, layerIndex int, pre bool, globalIndex int) (outUp, outDown T)

// defaultRouting is the most basic switching callback which swaps the values
// when state is SWAP and outputs as otherwise.
func defaultRouting[T any](s SwitchState, inUp, inDown T, layer, layerIndex int, pre bool, globalIndex int) (T, T) {
	if s%2 == 0 {
		return inUp, inDown
	}
	return inDown, inUp
}
