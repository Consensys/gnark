package main

import (
	"fmt"
	"math/rand"
	"time"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/signature/eddsa"
	"github.com/consensys/gnark/std/hash/mimc"
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	eddsaCrypto "github.com/consensys/gnark-crypto/signature/eddsa"
)

type eddsaCircuit struct {
	curveID   tedwards.ID
	PublicKey eddsa.PublicKey           `gnark:",public"`
	Signature eddsa.Signature           `gnark:",public"`
	Message   frontend.Variable         `gnark:",public"`
}

func (circuit *eddsaCircuit) Define(api frontend.API) error {
	curve, err := twistededwards.NewEdCurve(api, circuit.curveID)
	if err != nil {
		return err
	}

	mimc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	return eddsa.Verify(curve, circuit.Signature, circuit.Message, circuit.PublicKey, &mimc)
}

func main() {
    // instantiate hash function
    hFunc := hash.MIMC_BN254.New()

    seed := time.Now().Unix()
    randomness := rand.New(rand.NewSource(seed))

    // create a eddsa key pair
    privateKey, err := eddsaCrypto.New(tedwards.BN254, randomness)
    publicKey := privateKey.Public()

    // note that the message is on 4 bytes
    msg := []byte{0xde, 0xad, 0xf0, 0x0d}

    // sign the message
    signature, err := privateKey.Sign(msg, hFunc)

    // verifies signature
    isValid, err := publicKey.Verify(signature, msg, hFunc)
    if !isValid {
        fmt.Println("1. invalid signature")
    } else {
        fmt.Println("1. valid signature")
    }

    var circuit eddsaCircuit
    r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
    if err != nil {
	    fmt.Println("error cannot be returned 1")
	   // return err[0]
    }

    pk, vk, err := groth16.Setup(r1cs)
    if err != nil {
	    fmt.Println("error cannot be returned 2")
	    //return err
    }

    // declare the witness
    var assignment eddsaCircuit

    // assign message value
    assignment.Message = msg

    // public key bytes
    _publicKey := publicKey.Bytes()

    // assign public key values
    assignment.PublicKey.Assign(tedwards.BN254, _publicKey[:32])

    // assign signature values
    assignment.Signature.Assign(tedwards.BN254, signature)

    // witness
    witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
    publicWitness, err := witness.Public()
    // generate the proof
    proof, err := groth16.Prove(r1cs, pk, witness)

    // verify the proof
    err = groth16.Verify(proof, vk, publicWitness)
    if err != nil {
        // invalid proof
    }
}
