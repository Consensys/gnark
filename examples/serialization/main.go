package main

import (
	"bytes"

	"github.com/fxamacker/cbor/v2"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"

	"github.com/consensys/gnark/examples/cubic"
	"github.com/consensys/gnark/frontend"
)

func main() {
	var circuit cubic.Circuit

	// compile a circuit
	_r1cs, _ := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit)

	// R1CS implements io.WriterTo and io.ReaderFrom
	var buf bytes.Buffer
	_, _ = _r1cs.WriteTo(&buf)

	// gnark objects (R1CS, ProvingKey, VerifyingKey, Proof) must be instantiated like so:
	newR1CS := groth16.NewCS(ecc.BN254)
	_, _ = newR1CS.ReadFrom(&buf)

	// setup
	pk, vk, _ := groth16.Setup(_r1cs)

	// gnark objects implements binary encoding using (or not) elliptic curve point compression
	// groth16.ProvingKey, groth16.VerifyingKey and groth16.Proof implements io.WriterTo and io.ReaderFrom
	// but also gnarkio.WriterRawTo to serialize without point compression
	buf.Reset()
	_, _ = pk.WriteRawTo(&buf)
	newPK := groth16.NewProvingKey(ecc.BN254)
	_, _ = newPK.ReadFrom(&buf)

	// library user is free to use another encoder like gob or cbor to serialize / deserialize objects
	// but will need to check reconstructed object validity (points on curve, etc)
	// TODO add example and APIs for that
	buf.Reset()
	enc := cbor.NewEncoder(&buf)
	_ = enc.Encode(vk)
	// ...
}
