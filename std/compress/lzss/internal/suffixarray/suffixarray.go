// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package suffixarray implements substring search in logarithmic time using
// an in-memory suffix array.
//
// It is derived from index/suffixarray in go std; the only difference is that
// it forces use of int32 for the index and exposes a single method LookupLongest
// that returns the longest match in a given range.
package suffixarray

import (
	"bytes"
	"math"
	"sort"
)

// Can change for testing
var maxData32 int = realMaxData32

const realMaxData32 = math.MaxInt32

// Index implements a suffix array for fast substring search.
type Index struct {
	data []byte
	sa   []int32 // suffix array for data; sa.len() == len(data)
}

// New creates a new [Index] for data.
// [Index] creation time is O(N) for N = len(data).
func New(data []byte, sa []int32) *Index {
	ix := &Index{data: data}
	if len(data) > maxData32 {
		panic("suffixarray: data too large")
	}
	// reset the suffix array
	for i := range sa {
		sa[i] = 0
	}
	ix.sa = sa[:len(data)]
	text_32(data, ix.sa)

	return ix
}

// Bytes returns the data over which the index was created.
// It must not be modified.
func (x *Index) Bytes() []byte {
	return x.data
}

func (x *Index) at(i int) []byte {
	return x.data[x.sa[i]:]
}

// LookupLongest returns an index and length of the longest
// substring of s[:minEnd] / s[:maxEnd] that occurs in the indexed data.
func (x *Index) LookupLongest(s []byte, minEnd, maxEnd, rangeStart, rangeEnd int) (index, length int) {
	index, length = -1, -1

	// first search at min end to reduce the search space for next searches
	sStart, sEnd := x.lookupLongestInitial(s[:minEnd])

	if sStart == -1 {
		// no match
		return
	}

	if sStart == sEnd {
		// only one match
		offset := int(x.sa[sStart])
		if offset >= rangeStart && offset < rangeEnd {
			// valid index, we can use it.
			index = offset
			length = minEnd
		}
		return
	}

	// filter the results to be in the range [rangeStart, rangeEnd)
	for i := sStart; i < sEnd; i++ {
		offset := int(x.sa[i])
		if offset >= rangeStart && offset < rangeEnd {
			// valid index, we can use it.
			index = offset
			length = minEnd
			break
		}
	}

	if length == -1 {
		// no match
		return
	}

	// binary search between maxEnd - minEnd
	low := minEnd
	high := maxEnd

	for low <= high {
		mid := low + (high-low)/2

		if newStart, offset := x.lookupLongest(s[:mid], rangeStart, rangeEnd, sStart, sEnd); offset != -1 {
			// we found a match of length mid
			// try the next part of the binary search
			sStart = newStart
			index = offset
			length = mid
			low = mid + 1
			continue
		}
		// we didn't find a match in this half; try the lower one.
		high = mid - 1
	}
	return
}

// lookupLongest is similar to lookupAll but filters out indices that are not
// in the range [rangeStart, rangeEnd).
func (x *Index) lookupLongest(s []byte, rangeStart, rangeEnd, sStart, sEnd int) (rStart, offset int) {
	rStart = sStart
	// use sort.Search
	// find the first index where s would be the prefix
	i := sort.Search(sEnd-sStart, func(i int) bool { return bytes.Compare(x.at(i+sStart), s) >= 0 }) + sStart

	if i == sEnd || !bytes.HasPrefix(x.at(i), s) {
		return rStart, -1
	}

	rStart = i

	for i < sEnd && bytes.HasPrefix(x.at(i), s) {
		offset := int(x.sa[i])
		if offset >= rangeStart && offset < rangeEnd {
			// valid index, we can use it.
			return rStart, offset
		}
		i++
	}
	return rStart, -1
}

func (x *Index) lookupLongestInitial(s []byte) (rStart, rEnd int) {
	i := sort.Search(len(x.sa), func(i int) bool { return bytes.Compare(x.at(i), s) >= 0 })
	if i == len(x.sa) || !bytes.HasPrefix(x.at(i), s) {
		return -1, -1
	}

	j := i + sort.Search(len(x.sa)-i, func(k int) bool { return !bytes.HasPrefix(x.at(k+i), s) })
	return i, j
}
