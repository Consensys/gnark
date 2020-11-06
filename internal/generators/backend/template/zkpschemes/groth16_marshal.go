package zkpschemes

// Groth16Marshal ...
const Groth16Marshal = `

import (
	{{ template "import_curve" . }}
	{{ template "import_backend" . }}
	{{ template "import_fft" . }}
	"io"
)

// WriteTo writes binary encoding of the Proof elements to writer
// points are stored in compressed form Ar | Krs | Bs
// use WriteRawTo(...) to encode the proof without point compression 
func (p *Proof) WriteTo(w io.Writer) (n int64, err error) {
	var written int 

	// p.Ar
	buf := p.Ar.Bytes()
	written, err = w.Write(buf[:])
	n = int64(written)
	if err != nil {
		return
	}

	// p.Krs
	buf = p.Krs.Bytes()
	written, err = w.Write(buf[:])
	n += int64(written)
	if err != nil {
		return
	}

	// p.Bs
	bufG2 := p.Bs.Bytes()
	written, err = w.Write(bufG2[:])
	n += int64(written)

	return
}


// WriteRawTo writes binary encoding of the Proof elements to writer
// points are stored in uncompressed form Ar | Krs | Bs
// use WriteTo(...) to encode the proof with point compression 
func (p *Proof) WriteRawTo(w io.Writer) (n int64, err error) {
	var written int 

	// p.Ar
	buf := p.Ar.RawBytes()
	written, err = w.Write(buf[:])
	n = int64(written)
	if err != nil {
		return
	}

	// p.Krs
	buf = p.Krs.RawBytes()
	written, err = w.Write(buf[:])
	n += int64(written)
	if err != nil {
		return
	}

	// p.Bs
	bufG2 := p.Bs.RawBytes()
	written, err = w.Write(bufG2[:])
	n += int64(written)

	return
}

// ReadFrom attempts to decode a Proof from reader
// Proof must be encoded through WriteTo (compressed) or WriteRawTo (uncompressed) 
// note that we don't check that the points are on the curve or in the correct subgroup at this point
func (p *Proof) ReadFrom(r io.Reader) (n int64, err error) {

	var buf [curve.SizeOfG2Uncompressed]byte
	var read int
	
	// read p.Ar
	read, err = io.ReadFull(r, buf[:curve.SizeOfG1Uncompressed]) 
	n += int64(read)
	if err != nil {
		return
	}
	var consumed int 
	consumed, err = p.Ar.SetBytes(buf[:curve.SizeOfG1Uncompressed])
	if err != nil {
		return
	}

	if consumed == curve.SizeOfG1Compressed {
		// proof is compressed
		// we have to use the other half of the first buffer read
		_, err = p.Krs.SetBytes(buf[curve.SizeOfG1Compressed:])
		if err != nil {
			return
		}

		// read Bs
		read, err = io.ReadFull(r, buf[:curve.SizeOfG2Compressed]) 
		n += int64(read)
		if err != nil {
			return
		}

		_, err = p.Bs.SetBytes(buf[:])
		return
	} 

	// proof is raw
	// read p.Krs
	read, err = io.ReadFull(r, buf[:curve.SizeOfG1Uncompressed]) 
	n += int64(read)
	if err != nil {
		return
	}
	if consumed, err = p.Krs.SetBytes(buf[:curve.SizeOfG1Uncompressed]); err != nil {
		return
	}
	if consumed != curve.SizeOfG1Uncompressed {
		err = errors.New("invalid proof: p.Ar is compressed, p.Krs is not")
	}
	

	// read p.Bs
	read, err = io.ReadFull(r, buf[:]) 
	n += int64(read)
	if err != nil {
		return
	}
	consumed, err = p.Bs.SetBytes(buf[:])
	if consumed != curve.SizeOfG2Uncompressed {
		err = errors.New("invalid proof: p.Ar, p.Krs are compressed, p.Bs is not")
	}

	return
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

const Groth16MarshalTest = `
import (
	{{ template "import_curve" . }}

	"testing"
)


func TestProofSerialization(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 1000
	
	properties := gopter.NewProperties(parameters)

	properties.Property("Proof -> writer -> reader -> Proof should stay constant", prop.ForAll(
		func(ar, krs curve.G1Affine, bs curve.G2Affine) bool {
			var proof, pCompressed, pRaw Proof

			// create a random proof 
			proof.Ar = ar
			proof.Krs = krs
			proof.Bs = bs

			var bufCompressed bytes.Buffer
			written, err := proof.WriteTo(&bufCompressed)
			if err != nil {
				return false
			}

			read, err := pCompressed.ReadFrom(&bufCompressed)
			if err != nil {
				return false
			}

			if read != written {
				return false
			}

			var bufRaw bytes.Buffer
			written, err = proof.WriteTo(&bufRaw)
			if err != nil {
				return false
			}

			read, err = pRaw.ReadFrom(&bufRaw)
			if err != nil {
				return false
			}

			if read != written {
				return false
			}

			return reflect.DeepEqual(&proof, &pCompressed) && reflect.DeepEqual(&proof, &pRaw)
		},
		GenG1(),
		GenG1(),
		GenG2(),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}


func GenG1() gopter.Gen {
	_, _, g1GenAff, _ := curve.Generators()
	return func(genParams *gopter.GenParameters) *gopter.GenResult {
		var scalar big.Int
		scalar.SetUint64(genParams.NextUint64())

		var g1 curve.G1Affine
		g1.ScalarMultiplication(&g1GenAff, &scalar)


		genResult := gopter.NewGenResult(g1, gopter.NoShrinker)
		return genResult
	}
}

func GenG2() gopter.Gen {
	_, _, _, g2GenAff := curve.Generators()
	return func(genParams *gopter.GenParameters) *gopter.GenResult {
		var scalar big.Int
		scalar.SetUint64(genParams.NextUint64())

		var g2 curve.G2Affine
		g2.ScalarMultiplication(&g2GenAff, &scalar)


		genResult := gopter.NewGenResult(g2, gopter.NoShrinker)
		return genResult
	}
}

`
