package compress

import (
	"bytes"
	"fmt"
	"github.com/icza/bitio"
	"strconv"
)

// Streams and pipelines are inefficient data structures used for easy experimentation with compression algorithms.
// They make it easy to swap modules in and out.

type Stream struct {
	D       []int
	NbSymbs int
}

func (s *Stream) Len() int {
	return len(s.D)
}

func (s *Stream) RunLen(i int) int {
	runLen := 1
	for i+runLen < len(s.D) && s.D[i+runLen] == 0 {
		runLen++
	}
	return runLen
}

func (s *Stream) At(i int) int {
	return s.D[i]
}

func NewStreamFromBytes(in []byte) Stream {
	d := make([]int, len(in))
	for i := range in {
		d[i] = int(in[i])
	}
	return Stream{d, 256}
}

func NewStream[V any](slice []V, srcBitLen, streamBitLen int) Stream {
	if srcBitLen%streamBitLen != 0 {
		panic("not implemented")
	}
	dstPerSrc := srcBitLen / streamBitLen
	d := make([]int, dstPerSrc*len(slice))

	for i := range d {
		if intVal, err := strconv.Atoi(fmt.Sprint(slice[i])); err != nil { // not intended to be fast
			panic(err)
		} else {
			indexWithinWord := i % dstPerSrc
			d[i] = (uint(intVal) >> (streamBitLen * indexWithinWord)) & ((1 << streamBitLen) - 1)
		}
	}

	return Stream{d, 1 << streamBitLen}
}

type Pipeline []func(Stream) Stream

func (pipeline Pipeline) Run(in Stream) Stream {
	for _, f := range pipeline {
		in = f(in)
	}
	return in
}

func (s *Stream) WriteNum(r int, nbWords int) *Stream {
	for i := 0; i < nbWords; i++ {
		s.D = append(s.D, r%s.NbSymbs)
		r /= s.NbSymbs
	}
	if r != 0 {
		panic("overflow")
	}
	return s
}

func (s *Stream) ReadNum(start, nbWords int) int {
	res := 0
	for j := nbWords - 1; j >= 0; j-- {
		res *= s.NbSymbs
		res += s.D[start+j]
	}
	return res
}

func bitLen(n int) int {
	bitLen := 0
	for 1<<bitLen < n {
		bitLen++
	}
	return bitLen
}

func (s *Stream) Marshal() []byte {
	wordLen := bitLen(s.NbSymbs)

	nbBytes := (len(s.D)*wordLen + 7) / 8
	encodeLen := false
	if s.NbSymbs <= 128 {
		nbBytes++
		encodeLen = true
	}
	bb := bytes.NewBuffer(make([]byte, 0, nbBytes))

	w := bitio.NewWriter(bb)
	for i := range s.D {
		if err := w.WriteBits(uint64(s.D[i]), uint8(wordLen)); err != nil {
			panic(err)
		}
	}
	if err := w.Close(); err != nil {
		panic(err)
	}

	if encodeLen {
		nbWordsInLastByte := len(s.D) - ((nbBytes-2)*8+wordLen-1)/wordLen
		bb.WriteByte(byte(nbWordsInLastByte))
	}

	return bb.Bytes()
}

func (s *Stream) Unmarshal(b []byte) *Stream {
	wordLen := bitLen(s.NbSymbs)

	var nbWords int
	if s.NbSymbs <= 128 {
		nbWordsNotEntirelyInLastByte := ((len(b)-2)*8 + wordLen - 1) / wordLen
		nbWords = nbWordsNotEntirelyInLastByte + int(b[len(b)-1])
		b = b[:len(b)-1]
	} else {
		nbWords = (len(b) * 8) / wordLen
	}

	if cap(s.D) < nbWords {
		s.D = make([]int, nbWords)
	}
	s.D = s.D[:nbWords]

	r := bitio.NewReader(bytes.NewReader(b))
	for i := range s.D {
		if n, err := r.ReadBits(uint8(wordLen)); err != nil {
			panic(err)
		} else {
			s.D[i] = int(n)
		}
	}

	return s
}
