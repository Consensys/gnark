package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

const (
	pubInputFile = "public.json"
	priInputFile = "private.json"
	vkKeyFile    = "vk.g16vk"
	proofFile    = "proof.g16p"
)

type SudokuCircuit struct {
	IncompleteGrid [9][9]frontend.Variable `gnark:"IncompleteSudoku,public"`
	CompleteGrid   [9][9]frontend.Variable `gnark:"CompleteSudoku"`
}

type Sudoku struct {
	Grid [9][9]int `json:"grid"`
}

func (circuit *SudokuCircuit) Define(api frontend.API) error {
	// Constraint 1: Each cell value in the CompleteGrid must be between 1 and 9
	for i := 0; i < 9; i++ {
		for j := 0; j < 9; j++ {
			api.AssertIsLessOrEqual(circuit.CompleteGrid[i][j], 9)
			api.AssertIsLessOrEqual(1, circuit.CompleteGrid[i][j])
		}
	}

	// Constraint 2: Each row in the CompleteGrid must contain unique values
	for i := 0; i < 9; i++ {
		for j := 0; j < 9; j++ {
			for k := j + 1; k < 9; k++ {
				api.AssertIsDifferent(circuit.CompleteGrid[i][j], circuit.CompleteGrid[i][k])
			}
		}
	}

	// Constraint 3: Each column in the CompleteGrid must contain unique values
	for j := 0; j < 9; j++ {
		for i := 0; i < 9; i++ {
			for k := i + 1; k < 9; k++ {
				api.AssertIsDifferent(circuit.CompleteGrid[i][j], circuit.CompleteGrid[k][j])
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
					api.AssertIsDifferent(circuit.CompleteGrid[row1][col1], circuit.CompleteGrid[row2][col2])
				}
			}
		}
	}

	// Constraint 5: The values in the IncompleteGrid must match the CompleteGrid where provided
	for i := 0; i < 9; i++ {
		for j := 0; j < 9; j++ {
			isCellGiven := api.IsZero(circuit.IncompleteGrid[i][j])
			api.AssertIsEqual(api.Select(isCellGiven, circuit.CompleteGrid[i][j], circuit.IncompleteGrid[i][j]), circuit.CompleteGrid[i][j])
		}
	}

	return nil
}

func createProofAndVK() error {
	// Read the public (incomplete) and private (complete) Sudoku grids from JSON files
	incompleteFile, err := os.ReadFile(pubInputFile)
	if err != nil {
		return fmt.Errorf("failed to read %s: %v", pubInputFile, err)
	}

	completeFile, err := os.ReadFile(priInputFile)
	if err != nil {
		return fmt.Errorf("failed to read %s: %v", priInputFile, err)
	}

	var incompleteSudoku Sudoku
	err = json.Unmarshal(incompleteFile, &incompleteSudoku)
	if err != nil {
		return fmt.Errorf("failed to unmarshal incomplete Sudoku: %v", err)
	}

	var completeSudoku Sudoku
	err = json.Unmarshal(completeFile, &completeSudoku)
	if err != nil {
		return fmt.Errorf("failed to unmarshal complete Sudoku: %v", err)
	}

	// Create the circuit assignment
	assignment := &SudokuCircuit{}
	for i := 0; i < 9; i++ {
		for j := 0; j < 9; j++ {
			assignment.IncompleteGrid[i][j] = frontend.Variable(incompleteSudoku.Grid[i][j])
			assignment.CompleteGrid[i][j] = frontend.Variable(completeSudoku.Grid[i][j])
		}
	}

	// Create the circuit and witness
	var myCircuit SudokuCircuit
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return fmt.Errorf("failed to create witness: %v", err)
	}

	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &myCircuit)
	if err != nil {
		return fmt.Errorf("failed to compile circuit: %v", err)
	}

	// Groth16 setup (generate proving and verification keys)
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		return fmt.Errorf("failed to setup Groth16: %v", err)
	}

	// Generate the proof
	proof, err := groth16.Prove(cs, pk, witness)
	if err != nil {
		return fmt.Errorf("failed to create proof: %v", err)
	}

	// Write the verification key to a file
	vkF, err := os.Create(vkKeyFile)
	if err != nil {
		return fmt.Errorf("failed to create %s: %v", vkKeyFile, err)
	}
	defer vkF.Close()

	_, err = vk.WriteTo(vkF)
	if err != nil {
		return fmt.Errorf("failed to write verification key: %v", err)
	}

	// Write the proof to a file
	proofF, err := os.Create(proofFile)
	if err != nil {
		return fmt.Errorf("failed to create %s: %v", proofFile, err)
	}
	defer proofF.Close()

	_, err = proof.WriteTo(proofF)
	if err != nil {
		return fmt.Errorf("failed to write proof: %v", err)
	}

	fmt.Println("Proof and verification key files have been successfully generated.")
	return nil
}

func main() {
	// Call the function to generate the proof and vk file
	if err := createProofAndVK(); err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Println("Sudoku proof and vk generation completed.")
	}
}
