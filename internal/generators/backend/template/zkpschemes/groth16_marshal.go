package zkpschemes

// Groth16Marshal ...
const Groth16Marshal = `

import (
	{{ template "import_curve" . }}
	{{ template "import_backend" . }}
	{{ template "import_fft" . }}
	"io"
)

// WriteTo ...
func (p *Proof) WriteTo(w io.Writer) (n int64, err error) {
	panic("not implemented")
}

// ReadFrom ...
func (p *Proof) ReadFrom(r io.Reader) (n int64, err error) {
	// use io.LimitReader as proof size is constant. 
	panic("not implemented")
}

// WriteTo ...
func (vk *VerifyingKey) WriteTo(w io.Writer) (n int64, err error) {
	panic("not implemented")
}

// ReadFrom ...
func (vk *VerifyingKey) ReadFrom(r io.Reader) (n int64, err error) {
	panic("not implemented")
}


// WriteTo ...
func (vk *ProvingKey) WriteTo(w io.Writer) (n int64, err error) {
	panic("not implemented")
}

// ReadFrom ...
func (vk *ProvingKey) ReadFrom(r io.Reader) (n int64, err error) {
	panic("not implemented")
}

`
