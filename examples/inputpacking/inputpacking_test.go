package inputpacking

import (
	"crypto/rand"
	"fmt"
	"math/big"

	fp_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fp"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	cmimc "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
)

func inCircuitComputation(api frontend.API, input1, input2 frontend.Variable, expected frontend.Variable) {
	res := api.Mul(input1, input2)
	api.AssertIsEqual(res, expected)
}

func inCircuitComputationEmulated(api frontend.API, input1, input2 emulated.Element[emulated.BN254Fp], expected emulated.Element[emulated.BN254Fp]) error {
	f, err := emulated.NewField[emulated.BN254Fp](api)
	if err != nil {
		return err
	}
	res := f.Mul(&input1, &input2)
	f.AssertIsEqual(res, &expected)
	return nil
}

// UnpackedCircuit represents a circuit where all public inputs are given as is
type UnpackedCircuit struct {
	Input1, Input2                 frontend.Variable                  `gnark:",public"`
	EmulatedInput1, EmulatedInput2 emulated.Element[emulated.BN254Fp] `gnark:",public"`
	Output                         frontend.Variable                  `gnark:",private"`
	EmulatedOutput                 emulated.Element[emulated.BN254Fp] `gnark:",private"`
}

func (circuit *UnpackedCircuit) Define(api frontend.API) error {
	inCircuitComputation(api, circuit.Input1, circuit.Input2, circuit.Output)
	return inCircuitComputationEmulated(api, circuit.EmulatedInput1, circuit.EmulatedInput2, circuit.EmulatedOutput)
}

// PackedCircuit represents a circuit where all public inputs are given as private instead and we provide a hash of them as the only public input.
type PackedCircuit struct {
	PublicHash frontend.Variable

	Input1, Input2                 frontend.Variable                  `gnark:",private"`
	EmulatedInput1, EmulatedInput2 emulated.Element[emulated.BN254Fp] `gnark:",private"`
	Output                         frontend.Variable                  `gnark:",private"`
	EmulatedOutput                 emulated.Element[emulated.BN254Fp] `gnark:",private"`
}

func (circuit *PackedCircuit) Define(api frontend.API) error {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	h.Write(circuit.Input1)
	h.Write(circuit.Input2)
	h.Write(circuit.EmulatedInput1.Limbs...)
	h.Write(circuit.EmulatedInput2.Limbs...)
	dgst := h.Sum()
	api.AssertIsEqual(dgst, circuit.PublicHash)

	inCircuitComputation(api, circuit.Input1, circuit.Input2, circuit.Output)
	return inCircuitComputationEmulated(api, circuit.EmulatedInput1, circuit.EmulatedInput2, circuit.EmulatedOutput)
}

func Example() {
	modulusNative := ecc.BN254.ScalarField()
	modulusEmulated := ecc.BN254.BaseField()

	// declare inputs
	input1, err := rand.Int(rand.Reader, modulusNative)
	if err != nil {
		panic(err)
	}
	input2, err := rand.Int(rand.Reader, modulusNative)
	if err != nil {
		panic(err)
	}
	emulatedInput1, err := rand.Int(rand.Reader, modulusEmulated)
	if err != nil {
		panic(err)
	}
	emulatedInput2, err := rand.Int(rand.Reader, modulusEmulated)
	if err != nil {
		panic(err)
	}
	output := new(big.Int).Mul(input1, input2)
	output.Mod(output, modulusNative)
	emulatedOutput := new(big.Int).Mul(emulatedInput1, emulatedInput2)
	emulatedOutput.Mod(emulatedOutput, modulusEmulated)

	// first we run the circuit where public inputs are not packed
	assignment := &UnpackedCircuit{
		Input1:         input1,
		Input2:         input2,
		EmulatedInput1: emulated.ValueOf[emparams.BN254Fp](emulatedInput1),
		EmulatedInput2: emulated.ValueOf[emparams.BN254Fp](emulatedInput2),
		Output:         output,
		EmulatedOutput: emulated.ValueOf[emparams.BN254Fp](emulatedOutput),
	}
	privWit, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	publicWit, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		panic(err)
	}

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &UnpackedCircuit{})
	if err != nil {
		panic(err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}
	proof, err := groth16.Prove(ccs, pk, privWit)
	if err != nil {
		panic(err)
	}
	err = groth16.Verify(proof, vk, publicWit)
	if err != nil {
		panic(err)
	}

	// print the number of public inputs when we provide all public inputs. Note that we also count the commitment here.
	fmt.Println("unpacked public variables:", ccs.GetNbPublicVariables())

	// then we run the circuit where public inputs are packed
	var buf [fr_bn254.Bytes]byte
	var buf2 [fp_bn254.Bytes]byte
	h := cmimc.NewMiMC()
	input1.FillBytes(buf[:])
	h.Write(buf[:])
	input2.FillBytes(buf[:])
	h.Write(buf[:])
	emulatedInput1.FillBytes(buf2[:])
	h.Write(buf2[24:32])
	h.Write(buf2[16:24])
	h.Write(buf2[8:16])
	h.Write(buf2[0:8])
	emulatedInput2.FillBytes(buf2[:])
	h.Write(buf2[24:32])
	h.Write(buf2[16:24])
	h.Write(buf2[8:16])
	h.Write(buf2[0:8])

	dgst := h.Sum(nil)
	phash := new(big.Int).SetBytes(dgst)

	assignment2 := &PackedCircuit{
		PublicHash:     phash,
		Input1:         input1,
		Input2:         input2,
		EmulatedInput1: emulated.ValueOf[emparams.BN254Fp](emulatedInput1),
		EmulatedInput2: emulated.ValueOf[emparams.BN254Fp](emulatedInput2),
		Output:         output,
		EmulatedOutput: emulated.ValueOf[emparams.BN254Fp](emulatedOutput),
	}
	privWit2, err := frontend.NewWitness(assignment2, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	publicWit2, err := frontend.NewWitness(assignment2, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		panic(err)
	}

	ccs2, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &PackedCircuit{})
	if err != nil {
		panic(err)
	}
	pk2, vk2, err := groth16.Setup(ccs2)
	if err != nil {
		panic(err)
	}
	proof2, err := groth16.Prove(ccs2, pk2, privWit2)
	if err != nil {
		panic(err)
	}
	err = groth16.Verify(proof2, vk2, publicWit2)
	if err != nil {
		panic(err)
	}
	// print the number of public inputs when we provide only the hash. Note that we also count the commitment here.
	fmt.Println("packed public variables:", ccs2.GetNbPublicVariables())
	// output: unpacked public variables: 11
	// packed public variables: 1
}
