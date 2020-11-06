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


// WriteTo writes binary encoding of the key elements to writer
// points are compressed
// use WriteRawTo(...) to encode the key without point compression 
func (pk *ProvingKey) WriteTo(w io.Writer) (n int64, err error) {
	n, err = pk.Domain.WriteTo(w)
	if err != nil {
		return
	}

	err = binary.Write(w, binary.BigEndian, pk.NbWires)
	if err != nil {
		return
	}
	n += 8
	err = binary.Write(w, binary.BigEndian, pk.NbPrivateWires)
	if err != nil {
		return
	}
	n += 8

	// assert private wires and wires match sizes of slices in pk
	if ((int(pk.NbWires) != len(pk.G1.A)) ||
		(int(pk.NbWires) != len(pk.G1.B)) ||
		(int(pk.NbWires) != len(pk.G2.B)) ||
		(int(pk.NbPrivateWires) != len(pk.G1.K)) ||
		(int(pk.Domain.Cardinality) != len(pk.G1.Z))) {
			panic("proving key is in inconsistent state")
	}

	// write G1 elements
	{
		var written int 

		buf := pk.G1.Alpha.Bytes()
		written, err = w.Write(buf[:])
		n += int64(written)
		if err != nil {
			return
		}

		buf = pk.G1.Beta.Bytes()
		written, err = w.Write(buf[:])
		n += int64(written)
		if err != nil {
			return
		}

		buf = pk.G1.Delta.Bytes()
		written, err = w.Write(buf[:])
		n += int64(written)
		if err != nil {
			return
		}

		var n1 int64
		n1, err = writeG1Slices(w, pk.G1.A, pk.G1.B, pk.G1.Z, pk.G1.K)
		n += n1
		if err != nil {
			return
		}
	}

	// write G2 elements
	{
		var written int 

		buf := pk.G2.Beta.Bytes()
		written, err = w.Write(buf[:])
		n += int64(written)
		if err != nil {
			return
		}

		buf = pk.G2.Delta.Bytes()
		written, err = w.Write(buf[:])
		n += int64(written)
		if err != nil {
			return
		}

		for i:=0; i<len(pk.G2.B); i++ {
			buf = pk.G2.B[i].Bytes()
			written, err = w.Write(buf[:])
			n += int64(written)
			if err != nil {
				return
			}
		}
	}

	return 
}


// WriteRawTo writes binary encoding of the key elements to writer
// points are not compressed
// use WriteTo(...) to encode the key with point compression 
func (pk *ProvingKey) WriteRawTo(w io.Writer) (n int64, err error) {
	n, err = pk.Domain.WriteTo(w)
	if err != nil {
		return
	}

	err = binary.Write(w, binary.BigEndian, pk.NbWires)
	if err != nil {
		return
	}
	n += 8
	err = binary.Write(w, binary.BigEndian, pk.NbPrivateWires)
	if err != nil {
		return
	}
	n += 8

	// assert private wires and wires match sizes of slices in pk
	if ((int(pk.NbWires) != len(pk.G1.A)) ||
		(int(pk.NbWires) != len(pk.G1.B)) ||
		(int(pk.NbWires) != len(pk.G2.B)) ||
		(int(pk.NbPrivateWires) != len(pk.G1.K)) ||
		(int(pk.Domain.Cardinality) != len(pk.G1.Z))) {
			panic("proving key is in inconsistent state")
	}

	// write G1 elements
	{
		var written int 

		buf := pk.G1.Alpha.RawBytes()
		written, err = w.Write(buf[:])
		n += int64(written)
		if err != nil {
			return
		}

		buf = pk.G1.Beta.RawBytes()
		written, err = w.Write(buf[:])
		n += int64(written)
		if err != nil {
			return
		}

		buf = pk.G1.Delta.RawBytes()
		written, err = w.Write(buf[:])
		n += int64(written)
		if err != nil {
			return
		}

		var n1 int64
		n1, err = writeG1SlicesRaw(w, pk.G1.A, pk.G1.B, pk.G1.Z, pk.G1.K)
		n += n1
		if err != nil {
			return
		}
	
	}

	// write G2 elements
	{
		var written int 

		buf := pk.G2.Beta.RawBytes()
		written, err = w.Write(buf[:])
		n += int64(written)
		if err != nil {
			return
		}

		buf = pk.G2.Delta.RawBytes()
		written, err = w.Write(buf[:])
		n += int64(written)
		if err != nil {
			return
		}

		for i:=0; i<len(pk.G2.B); i++ {
			buf = pk.G2.B[i].RawBytes()
			written, err = w.Write(buf[:])
			n += int64(written)
			if err != nil {
				return
			}
		}
	}

	return 
}

// ReadFrom attempts to decode a ProvingKey from reader
// ProvingKey must be encoded through WriteTo (compressed) or WriteRawTo (uncompressed) 
// note that we don't check that the points are on the curve or in the correct subgroup at this point
// TODO while Proof points correctness is checkd in the Verifier, here may be a good place to check key
func (pk *ProvingKey) ReadFrom(r io.Reader) (n int64, err error) {

	n, err = pk.Domain.ReadFrom(r)
	if err != nil {
		return 
	}

	// read NbWires and NbPrivateWires
	var buf [curve.SizeOfG2Uncompressed]byte
	var read int
	
	read, err = io.ReadFull(r, buf[:8]) 
	n += int64(read)
	if err != nil {
		return
	}
	pk.NbWires = binary.BigEndian.Uint64(buf[:8])

	read, err = io.ReadFull(r, buf[:8]) 
	n += int64(read)
	if err != nil {
		return
	}
	pk.NbPrivateWires = binary.BigEndian.Uint64(buf[:8])

	// allocate our slices
	pk.G1.A = make([]curve.G1Affine, pk.NbWires)
	pk.G1.B = make([]curve.G1Affine, pk.NbWires)
	pk.G1.K = make([]curve.G1Affine, pk.NbPrivateWires)
	pk.G1.Z = make([]curve.G1Affine, pk.Domain.Cardinality)
	pk.G2.B = make([]curve.G2Affine, pk.NbWires)

	// read our points
	offset := curve.SizeOfG1Uncompressed
	
	// read pk.Alpha
	read, err = io.ReadFull(r, buf[:offset]) 
	n += int64(read)
	if err != nil {
		return
	}
	var consumed int 
	consumed, err = pk.G1.Alpha.SetBytes(buf[:offset])
	if err != nil {
		return
	}
	

	if consumed == curve.SizeOfG1Compressed {
		offset = curve.SizeOfG1Compressed

		// consume the second part of our buffer that was already read from reader
		_, err = pk.G1.Beta.SetBytes(buf[curve.SizeOfG1Compressed:curve.SizeOfG1Uncompressed])
		if err != nil {
			return
		}
	} else {
		// read pk.G1.Beta
		read, err = io.ReadFull(r, buf[:offset]) 
		n += int64(read)
		if err != nil {
			return
		}
		if _, err = pk.G1.Beta.SetBytes(buf[:offset]); err != nil {
			return
		}
	}
	// read pk.G1.Delta
	read, err = io.ReadFull(r, buf[:offset]) 
	n += int64(read)
	if err != nil {
		return
	}
	if _, err = pk.G1.Delta.SetBytes(buf[:offset]); err != nil {
		return
	}

	var n1 int64
	n1, err = readG1Slices(r, offset, pk.G1.A, pk.G1.B, pk.G1.Z, pk.G1.K)
	n += n1
	if err != nil {
		return
	}
	
	
	// read G2 elements
	if offset == curve.SizeOfG1Compressed {
		offset = curve.SizeOfG2Compressed
	} else {
		offset = curve.SizeOfG2Uncompressed 
	}

	read, err = io.ReadFull(r, buf[:offset]) 
	n += int64(read)
	if err != nil {
		return
	}
	if _, err = pk.G2.Beta.SetBytes(buf[:offset]); err != nil {
		return
	}

	read, err = io.ReadFull(r, buf[:offset]) 
	n += int64(read)
	if err != nil {
		return
	}
	if _, err = pk.G2.Delta.SetBytes(buf[:offset]); err != nil {
		return
	}

	for i:=0; i < len(pk.G2.B);i++ {
		read, err = io.ReadFull(r, buf[:offset]) 
		n += int64(read)
		if err != nil {
			return
		}
		if _, err = pk.G2.B[i].SetBytes(buf[:offset]); err != nil {
			return
		}
	}

	return
}

func readG1Slices(r io.Reader, offset int, slices ...[]curve.G1Affine) (n int64, err error) {
	var buf [curve.SizeOfG1Uncompressed]byte
	var read int 
	for j := 0 ; j< len(slices);j++ {
		for i:=0; i < len(slices[j]); i++ {
			read, err = io.ReadFull(r, buf[:offset]) 
			n += int64(read)
			if err != nil {
				return
			}
			if _, err = slices[j][i].SetBytes(buf[:offset]); err != nil {
				return
			}
		}
	}
	return
}

func writeG1Slices(w io.Writer, slices ...[]curve.G1Affine) (n int64, err error) {
	var written int
	for j := 0 ; j< len(slices);j++ {
		for i:=0; i < len(slices[j]); i++ {
			buf := slices[j][i].Bytes()
			written, err = w.Write(buf[:])
			n += int64(written)
			if err != nil {
				return
			}
		}
	}
	return
}

func writeG1SlicesRaw(w io.Writer, slices ...[]curve.G1Affine) (n int64, err error) {
	var written int
	for j := 0 ; j< len(slices);j++ {
		for i:=0; i < len(slices[j]); i++ {
			buf := slices[j][i].RawBytes()
			written, err = w.Write(buf[:])
			n += int64(written)
			if err != nil {
				return
			}
		}
	}
	return
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
			written, err = proof.WriteRawTo(&bufRaw)
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


func TestProvingKeySerialization(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 10
	
	properties := gopter.NewProperties(parameters)

	properties.Property("ProvingKey -> writer -> reader -> ProvingKey should stay constant", prop.ForAll(
		func(p1 curve.G1Affine, p2 curve.G2Affine) bool {
			var pk, pkCompressed, pkRaw ProvingKey

			// create a random pk
			domain := fft.NewDomain(8)
			pk.Domain = *domain

			pk.NbWires = 6
			pk.NbPrivateWires = 4

			// allocate our slices
			pk.G1.A = make([]curve.G1Affine, pk.NbWires)
			pk.G1.B = make([]curve.G1Affine, pk.NbWires)
			pk.G1.K = make([]curve.G1Affine, pk.NbPrivateWires)
			pk.G1.Z = make([]curve.G1Affine, pk.Domain.Cardinality)
			pk.G2.B = make([]curve.G2Affine, pk.NbWires)

			pk.G1.Alpha = p1
			pk.G2.Beta = p2
			pk.G1.K[1] = p1
			pk.G1.B[0] = p1
			pk.G2.B[0] = p2

			var bufCompressed bytes.Buffer
			written, err := pk.WriteTo(&bufCompressed)
			if err != nil {
				return false
			}

			read, err := pkCompressed.ReadFrom(&bufCompressed)
			if err != nil {
				return false
			}

			if read != written {
				return false
			}

			var bufRaw bytes.Buffer
			written, err = pk.WriteRawTo(&bufRaw)
			if err != nil {
				return false
			}

			read, err = pkRaw.ReadFrom(&bufRaw)
			if err != nil {
				return false
			}

			if read != written {
				return false
			}

			return reflect.DeepEqual(&pk, &pkCompressed)  && reflect.DeepEqual(&pk, &pkRaw)
		},
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
