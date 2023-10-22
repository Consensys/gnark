package compress

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

func (s *Stream) Read(in []byte) {
	s.D = make([]int, (len(in)-1)/int(in[0]))
	for i := range s.D {
		s.D[i] = ReadNum(in[1+i*int(in[0]) : 1+(i+1)*int(in[0])])
	}
	s.NbSymbs = s.D[0]
	s.D = s.D[1:]
}

func (s *Stream) Write() []byte {
	bytePerSymb := 0
	remainder := s.NbSymbs
	for remainder > 0 {
		bytePerSymb++
		remainder >>= 8
	}
	res := make([]byte, 1+bytePerSymb*(len(s.D)+1))
	res[0] = byte(bytePerSymb)

	WriteNum(s.NbSymbs, res[1:1+bytePerSymb])
	for i := range s.D {
		WriteNum(s.D[i], res[1+bytePerSymb*(i+1):1+bytePerSymb*(i+2)])
	}

	return res
}

func (s *Stream) ReadNum(start, length int) int {
	res := 0
	for i := 0; i < length; i++ {
		res *= s.NbSymbs
		res += s.D[start+i]
	}
	return res
}

type Pipeline []func(Stream) Stream

func (pipeline Pipeline) Run(in Stream) Stream {
	for _, f := range pipeline {
		in = f(in)
	}
	return in
}

func ReadNum(bytes []byte) int { //little endian
	var res int
	for i := len(bytes) - 1; i >= 0; i-- {
		res <<= 8
		res |= int(bytes[i])
	}
	return res
}

func WriteNum(n int, bytes []byte) {
	for i := range bytes {
		bytes[i] = byte(n)
		n >>= 8
	}
	if n != 0 {
		panic("didn't fit")
	}
}
