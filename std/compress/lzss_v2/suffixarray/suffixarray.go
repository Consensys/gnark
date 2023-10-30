// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package suffixarray implements substring search in logarithmic time using
// an in-memory suffix array.
//
// Example use:
//
//	// create index for some data
//	index := suffixarray.New(data)
//
//	// lookup byte slice s
//	offsets1 := index.Lookup(s, -1) // the list of all indices where s occurs in data
//	offsets2 := index.Lookup(s, 3)  // the list of at most 3 indices where s occurs in data
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

// // lookupAll returns a slice into the matching region of the index.
// // The runtime is O(log(N)*len(s)).
// func (x *Index) lookupAll(s []byte) ints {
// 	// find matching suffix index range [i:j]
// 	// find the first index where s would be the prefix
// 	i := sort.Search(len(x.sa), func(i int) bool { return bytes.Compare(x.at(i), s) >= 0 })
// 	// starting at i, find the first index at which s is not a prefix
// 	j := i + sort.Search(len(x.sa)-i, func(k int) bool { return !bytes.HasPrefix(x.at(k+i), s) })
// 	return x.sa[i:j]
// }

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
	low := sStart
	high := sEnd
	offset = -1
	rStart = sStart
	for low <= high {
		mid := low + (high-low)/2
		r := bytes.Compare(x.at(mid), s)
		if r >= 0 {
			offset = mid
			high = mid - 1
			// continue
		} else {
			// r < 0
			// x.at(mid) is less than s
			low = mid + 1
		}
	}

	if offset == -1 {
		return rStart, -1
	}
	rStart = offset // next search should start at offset
	i := offset
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
	low := 0
	high := len(x.sa)
	rStart, rEnd = -1, -1
	for low <= high {
		mid := low + (high-low)/2
		r := bytes.Compare(x.at(mid), s)
		if r >= 0 {
			rStart = mid
			high = mid - 1
			// continue
		} else {
			// r < 0
			// x.at(mid) is less than s
			low = mid + 1
		}
	}
	i := rStart
	if i == -1 {
		return -1, -1
	}

	// starting at i, find the first index at which s is not a prefix
	j := i + sort.Search(len(x.sa)-i, func(k int) bool { return !bytes.HasPrefix(x.at(k+i), s) })
	return i, j
}
