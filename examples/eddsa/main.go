package main

import (
	"fmt"
	"math/rand"
	"time"
	"bytes"
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

const N = 2

type eddsaCircuit struct {
	curveID   tedwards.ID
	PublicKey [N]eddsa.PublicKey           `gnark:",public"`
	Signature [N]eddsa.Signature           `gnark:",public"`
	Message   [N]frontend.Variable         `gnark:",public"`
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

	for i := 0; i < N; i++ {
		ver_err := eddsa.Verify(curve, circuit.Signature[i], circuit.Message[i], circuit.PublicKey[i], &mimc)
		if ver_err != nil {
			return ver_err
		}
	}

	return nil
	//return eddsa.Verify(curve, circuit.Signature, circuit.Message, circuit.PublicKey, &mimc)
}

func main() {
    // instantiate hash function
    hFunc := hash.MIMC_BN254.New()

    seed := time.Now().Unix()
    randomness := rand.New(rand.NewSource(seed))

    // create a eddsa key pair
    //for i := 0; i < N; i++ {
	    privateKey, err := eddsaCrypto.New(tedwards.BN254, randomness)
	    fmt.Println("%T\n", privateKey)
	    publicKey := privateKey.Public()
	    fmt.Println("%T\n", publicKey)

    // note that the message is on 4 bytes
    msg := []byte{4, 138, 238, 31, 227, 139, 149, 17, 139, 42, 141, 190, 58, 89, 207, 213, 43, 102, 126, 255, 120, 144, 82, 112, 31, 116, 76, 42, 1, 122, 145, 41}
    //This message errors, not sure why: {0xde, 0xad, 0xf0, 0x0d}
    fmt.Println(msg)
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
    circuit.curveID = tedwards.BN254
    fmt.Println("Here2!")
    _r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
    if err != nil {
	    fmt.Println("error cannot be returned 1")
	   // return err[0]
    }

    var buf bytes.Buffer
    _, _ = _r1cs.WriteTo(&buf)

    newR1CS := groth16.NewCS(ecc.BN254)
    _, _ = newR1CS.ReadFrom(&buf)

    pk, vk, err := groth16.Setup(_r1cs)
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
    proof, err := groth16.Prove(_r1cs, pk, witness)

    // verify the proof
    err = groth16.Verify(proof, vk, publicWitness)
    if err != nil {
        // invalid proof
    }
}
