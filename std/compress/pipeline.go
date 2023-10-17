package compress

// Streams and pipelines are inefficient data structures used for easy experimentation with compression algorithms.
// They make it easy to swap modules in and out.

type Stream struct {
	D       []int
	NbSymbs int
}

func (s Stream) Len() int {
	return len(s.D)
}

func (s Stream) RunLen(i int) int {
	runLen := 1
	for i+runLen < len(s.D) && s.D[i+runLen] == 0 {
		runLen++
	}
	return runLen
}

func (s Stream) At(i int) int {
	return s.D[i]
}

func NewStreamFromBytes(in []byte) Stream {
	d := make([]int, len(in))
	for i := range in {
		d[i] = int(in[i])
	}
	return Stream{d, 256}
}

type Pipeline []func(Stream) Stream

func (pipeline Pipeline) Run(in Stream) Stream {
	for _, f := range pipeline {
		in = f(in)
	}
	return in
}
