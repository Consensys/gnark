package zkpschemes

// Groth16Marshal ...
const Groth16Marshal = `

import (
	{{ template "import_curve" . }}
	{{ template "import_backend" . }}
	{{ template "import_fft" . }}
	"io"
	"github.com/fxamacker/cbor/v2"
)

// WriteTo writes binary encoding of the Proof elements to writer
// points are stored in compressed form Ar | Krs | Bs
// use WriteRawTo(...) to encode the proof without point compression 
func (proof *Proof) WriteTo(w io.Writer) (n int64, err error) {
	return proof.writeTo(w, false)
}

// WriteRawTo writes binary encoding of the Proof elements to writer
// points are stored in uncompressed form Ar | Krs | Bs
// use WriteTo(...) to encode the proof with point compression 
func (proof *Proof) WriteRawTo(w io.Writer) (n int64, err error) {
	return proof.writeTo(w, true)
}

func (proof *Proof) writeTo(w io.Writer, raw bool) (int64, error) {
	var enc *curve.Encoder
	if raw {
		enc = curve.NewEncoder(w, curve.RawEncoding())
	} else {
		enc = curve.NewEncoder(w)
	}

	if err := enc.Encode(&proof.Ar); err != nil {
		return enc.BytesWritten(), err
	}
	if err := enc.Encode(&proof.Bs); err != nil {
		return enc.BytesWritten(), err
	}
	if err := enc.Encode(&proof.Krs); err != nil {
		return enc.BytesWritten(), err
	}
	return enc.BytesWritten(), nil
} 


// ReadFrom attempts to decode a Proof from reader
// Proof must be encoded through WriteTo (compressed) or WriteRawTo (uncompressed) 
// note that we don't check that the points are on the curve or in the correct subgroup at this point
func (proof *Proof) ReadFrom(r io.Reader) (n int64, err error) {

	dec := curve.NewDecoder(r)

	if err := dec.Decode(&proof.Ar); err != nil {
		return dec.BytesRead(), err
	}
	if err := dec.Decode(&proof.Bs); err != nil {
		return dec.BytesRead(), err
	}
	if err := dec.Decode(&proof.Krs); err != nil {
		return dec.BytesRead(), err
	}

	return dec.BytesRead(), nil
}

// WriteTo writes binary encoding of the key elements to writer
// points are compressed
// use WriteRawTo(...) to encode the key without point compression 
func (vk *VerifyingKey) WriteTo(w io.Writer) (n int64, err error) {
	return vk.writeTo(w, false)
}

// WriteRawTo writes binary encoding of the key elements to writer
// points are not compressed
// use WriteTo(...) to encode the key with point compression 
func (vk *VerifyingKey) WriteRawTo(w io.Writer) (n int64, err error) {
	return vk.writeTo(w, true)
}

func (vk *VerifyingKey) writeTo(w io.Writer, raw bool) (n int64, err error) {
	var written int 
	
	// encode public input names
	var pBytes []byte
	pBytes, err = cbor.Marshal(vk.PublicInputs)
	if err != nil {
		return  	
	}
	err = binary.Write(w, binary.BigEndian, uint64(len(pBytes)))
	if err != nil {
		return  	
	}
	n += 8
	written, err = w.Write(pBytes)
	n += int64(written)
	if err != nil {
		return
	}

	// write vk.E
	buf := vk.E.Bytes()
	written, err = w.Write(buf[:])
	n += int64(written)
	if err != nil {
		return
	}

	var enc *curve.Encoder
	if raw {
		enc = curve.NewEncoder(w, curve.RawEncoding())
	} else {
		enc = curve.NewEncoder(w)
	}


	err = enc.Encode(&vk.G2.GammaNeg)
	n += enc.BytesWritten()
	if err != nil {
		return
	}

	err = enc.Encode(&vk.G2.DeltaNeg)
	n += enc.BytesWritten()
	if err != nil {
		return
	}

	err = enc.Encode(vk.G1.K)
	n += enc.BytesWritten()
	return
}

// ReadFrom attempts to decode a VerifyingKey from reader
// VerifyingKey must be encoded through WriteTo (compressed) or WriteRawTo (uncompressed) 
// note that we don't check that the points are on the curve or in the correct subgroup at this point
// TODO while Proof points correctness is checkd in the Verifier, here may be a good place to check key
func (vk *VerifyingKey) ReadFrom(r io.Reader) (n int64, err error) {
	
	var read int 
	var buf [curve.SizeOfGT]byte

	read, err = io.ReadFull(r, buf[:8])
	n += int64(read)
	if err != nil {
		return
	}
	lPublicInputs := binary.BigEndian.Uint64(buf[:8])

	bPublicInputs  := make([]byte, lPublicInputs)
	read, err = io.ReadFull(r, bPublicInputs)
	n += int64(read)
	if err != nil {
		return
	}
	err = cbor.Unmarshal(bPublicInputs, &vk.PublicInputs)
	if err != nil {
		return
	}


	// read vk.E

	read, err = r.Read(buf[:])
	n += int64(read)
	if err != nil {
		return
	}
	err = vk.E.SetBytes(buf[:])
	if err != nil {
		return
	}

	dec := curve.NewDecoder(r)

	err = dec.Decode(&vk.G2.GammaNeg)
	n += dec.BytesRead()
	if err != nil {
		return
	}

	err = dec.Decode(&vk.G2.DeltaNeg)
	n += dec.BytesRead()
	if err != nil {
		return
	}

	err = dec.Decode(&vk.G1.K)
	n += dec.BytesRead()
	
	return
}



// WriteTo writes binary encoding of the key elements to writer
// points are compressed
// use WriteRawTo(...) to encode the key without point compression 
func (pk *ProvingKey) WriteTo(w io.Writer) (n int64, err error) {
	return pk.writeTo(w, false)
}


// WriteRawTo writes binary encoding of the key elements to writer
// points are not compressed
// use WriteTo(...) to encode the key with point compression 
func (pk *ProvingKey) WriteRawTo(w io.Writer) (n int64, err error) {
	return pk.writeTo(w, true)
}

func (pk *ProvingKey) writeTo(w io.Writer, raw bool) (int64, error) {
	n, err := pk.Domain.WriteTo(w)
	if err != nil {
		return n, err 
	}

	var enc *curve.Encoder
	if raw {
		enc = curve.NewEncoder(w, curve.RawEncoding())
	} else {
		enc = curve.NewEncoder(w)
	}
	
	toEncode := []interface{}{
		&pk.G1.Alpha,
		&pk.G1.Beta,
		&pk.G1.Delta,
		pk.G1.A,
		pk.G1.B,
		pk.G1.Z,
		pk.G1.K,
		&pk.G2.Beta,
		&pk.G2.Delta,
		pk.G2.B,
	}

	for _, v := range toEncode {
		if err := enc.Encode(v); err != nil {
			return n + enc.BytesWritten(), err
		}
	}

	return n + enc.BytesWritten(), nil

}

// ReadFrom attempts to decode a ProvingKey from reader
// ProvingKey must be encoded through WriteTo (compressed) or WriteRawTo (uncompressed) 
// note that we don't check that the points are on the curve or in the correct subgroup at this point
// TODO while Proof points correctness is checkd in the Verifier, here may be a good place to check key
func (pk *ProvingKey) ReadFrom(r io.Reader) (int64, error) {

	n, err := pk.Domain.ReadFrom(r)
	if err != nil {
		return n, err
	}

	dec := curve.NewDecoder(r)

	toDecode := []interface{}{
		&pk.G1.Alpha,
		&pk.G1.Beta,
		&pk.G1.Delta,
		&pk.G1.A,
		&pk.G1.B,
		&pk.G1.Z,
		&pk.G1.K,
		&pk.G2.Beta,
		&pk.G2.Delta,
		&pk.G2.B,
	}

	for _, v := range toDecode {
		if err := dec.Decode(v); err != nil {
			return n + dec.BytesRead(), err
		}
	}

	return n + dec.BytesRead(), nil
}



`

// Groth16MarshalTest ...
const Groth16MarshalTest = `
import (
	{{ template "import_curve" . }}

	"bytes"
	"math/big"
	"reflect"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"

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



func TestVerifyingKeySerialization(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 10
	
	properties := gopter.NewProperties(parameters)

	properties.Property("VerifyingKey -> writer -> reader -> VerifyingKey should stay constant", prop.ForAll(
		func(p1 curve.G1Affine, p2 curve.G2Affine, rs string) bool {
			var vk, vkCompressed, vkRaw VerifyingKey

			// create a random vk
			nbWires := 6

			vk.E.SetRandom()
			vk.G2.GammaNeg = p2
			vk.G2.DeltaNeg = p2

			vk.G1.K = make([]curve.G1Affine, nbWires)
			for i:=0; i < nbWires; i++ {
				vk.G1.K[i] = p1
			}

			vk.PublicInputs = make([]string, nbWires)
			for i:=0; i < nbWires; i++ {
				vk.PublicInputs[i] = rs
			}

		
			var bufCompressed bytes.Buffer
			written, err := vk.WriteTo(&bufCompressed)
			if err != nil {
				t.Log(err)
				return false
			}

			read, err := vkCompressed.ReadFrom(&bufCompressed)
			if err != nil {
				t.Log(err)
				return false
			}

			if read != written {
				t.Log("read != written")
				return false
			}

			var bufRaw bytes.Buffer
			written, err = vk.WriteRawTo(&bufRaw)
			if err != nil {
				t.Log(err)
				return false
			}

			read, err = vkRaw.ReadFrom(&bufRaw)
			if err != nil {
				t.Log(err)
				return false
			}

			if read != written {
				t.Log("read raw != written")
				return false
			}

			return reflect.DeepEqual(&vk, &vkCompressed)  && reflect.DeepEqual(&vk, &vkRaw)
		},
		GenG1(),
		GenG2(),
		gen.AnyString(),
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

			nbWires := 6
			nbPrivateWires := 4

			// allocate our slices
			pk.G1.A = make([]curve.G1Affine, nbWires)
			pk.G1.B = make([]curve.G1Affine, nbWires)
			pk.G1.K = make([]curve.G1Affine, nbPrivateWires)
			pk.G1.Z = make([]curve.G1Affine, pk.Domain.Cardinality)
			pk.G2.B = make([]curve.G2Affine, nbWires)

			pk.G1.Alpha = p1
			pk.G2.Beta = p2
			pk.G1.K[1] = p1
			pk.G1.B[0] = p1
			pk.G2.B[0] = p2

			var bufCompressed bytes.Buffer
			written, err := pk.WriteTo(&bufCompressed)
			if err != nil {
				t.Log(err)
				return false
			}

			read, err := pkCompressed.ReadFrom(&bufCompressed)
			if err != nil {
				t.Log(err)
				return false
			}

			if read != written {
				t.Log("read != written")
				return false
			}

			var bufRaw bytes.Buffer
			written, err = pk.WriteRawTo(&bufRaw)
			if err != nil {
				t.Log(err)
				return false
			}

			read, err = pkRaw.ReadFrom(&bufRaw)
			if err != nil {
				t.Log(err)
				return false
			}

			if read != written {
				t.Log("read raw != written")
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
