package sudoku

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// SudokuCircuit represents a Sudoku circuit. It contains two grids: the
// challenge and solution grids (named Challenge and Solution respectively). The
// challenge grid is public, while the solution grid is private.
type SudokuCircuit struct {
	Challenge SudokuGrid `gnark:"Challenge,public"`
	Solution  SudokuGrid `gnark:"Solution,secret"`
}

// SudokuGrid represents a 9x9 Sudoku grid in-circuit.
type SudokuGrid [9][9]frontend.Variable

// Define defines the constraints of the Sudoku circuit.
func (circuit *SudokuCircuit) Define(api frontend.API) error {
	// Constraint 1: Each cell value in the CompleteGrid must be between 1 and 9
	for i := 0; i < 9; i++ {
		for j := 0; j < 9; j++ {
			api.AssertIsLessOrEqual(circuit.Solution[i][j], 9)
			api.AssertIsLessOrEqual(1, circuit.Solution[i][j])
		}
	}

	// Constraint 2: Each row in the CompleteGrid must contain unique values
	for i := 0; i < 9; i++ {
		for j := 0; j < 9; j++ {
			for k := j + 1; k < 9; k++ {
				api.AssertIsDifferent(circuit.Solution[i][j], circuit.Solution[i][k])
			}
		}
	}

	// Constraint 3: Each column in the CompleteGrid must contain unique values
	for j := 0; j < 9; j++ {
		for i := 0; i < 9; i++ {
			for k := i + 1; k < 9; k++ {
				api.AssertIsDifferent(circuit.Solution[i][j], circuit.Solution[k][j])
			}
		}
	}

	// Constraint 4: Each 3x3 sub-grid in the CompleteGrid must contain unique values
	for boxRow := 0; boxRow < 3; boxRow++ {
		for boxCol := 0; boxCol < 3; boxCol++ {
			for i := 0; i < 9; i++ {
				for j := i + 1; j < 9; j++ {
					row1 := boxRow*3 + i/3
					col1 := boxCol*3 + i%3
					row2 := boxRow*3 + j/3
					col2 := boxCol*3 + j%3
					api.AssertIsDifferent(circuit.Solution[row1][col1], circuit.Solution[row2][col2])
				}
			}
		}
	}

	// Constraint 5: The values in the IncompleteGrid must match the CompleteGrid where provided
	for i := 0; i < 9; i++ {
		for j := 0; j < 9; j++ {
			isCellGiven := api.IsZero(circuit.Challenge[i][j])
			api.AssertIsEqual(api.Select(isCellGiven, circuit.Solution[i][j], circuit.Challenge[i][j]), circuit.Solution[i][j])
		}
	}

	return nil
}

// SudokuSerialization represents a Sudoku witness out-circuit. Used for serialization.
type SudokuSerialization struct {
	Grid [9][9]int `json:"grid"`
}

// NewSudokuGrid creates a new Sudoku grid from the serialized grid.
func NewSudokuGrid(serialized SudokuSerialization) SudokuGrid {
	var grid SudokuGrid
	for i := 0; i < 9; i++ {
		for j := 0; j < 9; j++ {
			grid[i][j] = frontend.Variable(serialized.Grid[i][j])
		}
	}
	return grid
}

// setup performs the setup phase of the Sudoku circuit
func setup(ccsWriter, pkWriter, vkWriter io.Writer) error {
	// compile the circuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &SudokuCircuit{})
	if err != nil {
		return fmt.Errorf("failed to compile circuit: %v", err)
	}
	// perform the setup. NB! In practice use MPC. This is currently UNSAFE
	// approach.
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return fmt.Errorf("failed to setup circuit: %v", err)
	}
	// serialize the circuit, proving key and verifying key
	_, err = ccs.WriteTo(ccsWriter)
	if err != nil {
		return fmt.Errorf("failed to write constraint system: %v", err)
	}
	_, err = pk.WriteTo(pkWriter)
	if err != nil {
		return fmt.Errorf("failed to write proving key: %v", err)
	}
	_, err = vk.WriteTo(vkWriter)
	if err != nil {
		return fmt.Errorf("failed to write verifying key: %v", err)
	}
	return nil
}

// prover performs the prover phase of the Sudoku circuit
func prover(ccsReader, challengeReader, pkReader io.Reader, proofWriter io.Writer) error {
	// define the sudoku solution. This is private information known only to the
	// prover. We use serialization to represent it.
	serializedSolution := `{"grid":[[5,3,4,6,7,8,9,1,2],[6,7,2,1,9,5,3,4,8],[1,9,8,3,4,2,5,6,7],[8,5,9,7,6,1,4,2,3],[4,2,6,8,5,3,7,9,1],[7,1,3,9,2,4,8,5,6],[9,6,1,5,3,7,2,8,4],[2,8,7,4,1,9,6,3,5],[3,4,5,2,8,6,1,7,9]]}`
	var nativeSolution SudokuSerialization
	err := json.Unmarshal([]byte(serializedSolution), &nativeSolution)
	if err != nil {
		return fmt.Errorf("failed to unmarshal solution: %v", err)
	}
	// deserialize the circuit, challenge and proving key
	var ccs cs_bn254.R1CS
	_, err = ccs.ReadFrom(ccsReader)
	if err != nil {
		return fmt.Errorf("failed to read constraint system: %v", err)
	}
	var nativeChallenge SudokuSerialization
	err = json.NewDecoder(challengeReader).Decode(&nativeChallenge)
	if err != nil {
		return fmt.Errorf("failed to read challenge: %v", err)
	}
	var pk groth16_bn254.ProvingKey
	_, err = pk.ReadFrom(pkReader)
	if err != nil {
		return fmt.Errorf("failed to read proving key: %v", err)
	}

	// create the circuit assignments
	assignment := &SudokuCircuit{
		Challenge: NewSudokuGrid(nativeChallenge),
		Solution:  NewSudokuGrid(nativeSolution),
	}
	// create the witness
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return fmt.Errorf("failed to create witness: %v", err)
	}
	// generate the proof
	proof, err := groth16.Prove(&ccs, &pk, witness)
	if err != nil {
		return fmt.Errorf("failed to generate proof: %v", err)
	}
	// serialize the proof
	_, err = proof.WriteTo(proofWriter)
	if err != nil {
		return fmt.Errorf("failed to write proof: %v", err)
	}
	return nil
}

// verifier performs the verifier phase of the Sudoku circuit
func verifier(challengeReader, vkReader, proofReader io.Reader) error {
	// deserialize the challenge, verifying key and proof
	var nativeChallenge SudokuSerialization
	err := json.NewDecoder(challengeReader).Decode(&nativeChallenge)
	if err != nil {
		return fmt.Errorf("failed to read challenge: %v", err)
	}
	var vk groth16_bn254.VerifyingKey
	_, err = vk.ReadFrom(vkReader)
	if err != nil {
		return fmt.Errorf("failed to read verifying key: %v", err)
	}
	var proof groth16_bn254.Proof
	_, err = proof.ReadFrom(proofReader)
	if err != nil {
		return fmt.Errorf("failed to read proof: %v", err)
	}
	// create the circuit assignment
	assignment := &SudokuCircuit{
		Challenge: NewSudokuGrid(nativeChallenge),
	}
	// create the public witness
	pubWit, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return fmt.Errorf("failed to create public witness: %v", err)
	}
	// verify the proof
	err = groth16.Verify(&proof, &vk, pubWit)
	if err != nil {
		return fmt.Errorf("failed to verify proof: %v", err)
	}
	return nil
}

// This example demonstrates how to implement a Sudoku challenge verification
// circuit such that the solution stays private.
//
// This example also demonstrates how to serialize and deserialize the values
// produced during setup and proof generation.
func Example() {
	// define the sudoku challenge. This is public information. We use
	// serialization to represent it.
	serializedChallengeBytes := `{"grid":[[5,3,0,0,7,0,0,0,0],[6,0,0,1,9,5,0,0,0],[0,9,8,0,0,0,0,6,0],[8,0,0,0,6,0,0,0,3],[4,0,0,8,0,3,0,0,1],[7,0,0,0,2,0,0,0,6],[0,6,0,0,0,0,2,8,0],[0,0,0,4,1,9,0,0,5],[0,0,0,0,8,0,0,7,9]]}`

	var (
		serializedCCS bytes.Buffer

		serializedProvingKey   bytes.Buffer
		serializedVerifyingKey bytes.Buffer

		serializedProof bytes.Buffer
	)

	// full example

	// first we run the setup phase. This happens offline in a trusted or MPC setting
	if err := setup(&serializedCCS, &serializedProvingKey, &serializedVerifyingKey); err != nil {
		fmt.Println("failed to setup circuit:", err)
		return
	}

	// then we run the prover phase. This happens online
	serializedChallenge := bytes.NewBufferString(serializedChallengeBytes)
	if err := prover(&serializedCCS, serializedChallenge, &serializedProvingKey, &serializedProof); err != nil {
		fmt.Println("failed to prove circuit:", err)
		return
	}

	// finally we run the verifier phase. This happens online
	serializedChallenge = bytes.NewBufferString(serializedChallengeBytes)
	if err := verifier(serializedChallenge, &serializedVerifyingKey, &serializedProof); err != nil {
		fmt.Println("failed to verify circuit:", err)
		return
	}
	fmt.Println("proof verified successfully!")
	// Output: proof verified successfully!
}
