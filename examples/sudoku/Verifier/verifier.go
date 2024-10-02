package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/frontend"
)

const (
	pubInputFile = "public.json"
	vkKeyFile    = "vk.g16vk"
	proofFile    = "proof.g16p"
)

type SudokuCircuitPublic struct {
	IncompleteGrid [9][9]frontend.Variable `gnark:"IncompleteSudoku,public"`
}

// Define the circuit (required for frontend.Circuit interface)
func (circuit *SudokuCircuitPublic) Define(api frontend.API) error {
	// There are no additional constraints since this is the public part (IncompleteGrid)
	return nil
}

type Sudoku struct {
	Grid [9][9]int `json:"grid"`
}

func readProofAndVerify() error {
	// Open verification key and proof files
	vkF, err := os.Open(vkKeyFile)
	if err != nil {
		return fmt.Errorf("failed to open %s: %v", vkKeyFile, err)
	}
	defer vkF.Close()

	proofF, err := os.Open(proofFile)
	if err != nil {
		return fmt.Errorf("failed to open %s: %v", proofFile, err)
	}
	defer proofF.Close()

	// Read the public input (incomplete Sudoku) from file
	pubB, err := os.ReadFile(pubInputFile)
	if err != nil {
		return fmt.Errorf("failed to read %s: %v", pubInputFile, err)
	}

	var incompleteSudoku Sudoku
	err = json.Unmarshal(pubB, &incompleteSudoku)
	if err != nil {
		return fmt.Errorf("failed to unmarshal public Sudoku: %v", err)
	}

	// Create the public part of the witness (IncompleteGrid only)
	var sudokuCircuitAssignmentPublic SudokuCircuitPublic
	for i := 0; i < 9; i++ {
		for j := 0; j < 9; j++ {
			sudokuCircuitAssignmentPublic.IncompleteGrid[i][j] = frontend.Variable(incompleteSudoku.Grid[i][j])
		}
	}

	// Create the public witness for verification
	pubWit, err := frontend.NewWitness(&sudokuCircuitAssignmentPublic, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return fmt.Errorf("failed to create public witness: %v", err)
	}

	// Read the verification key
	var vk groth16_bn254.VerifyingKey
	_, err = vk.ReadFrom(vkF)
	if err != nil {
		return fmt.Errorf("failed to read verification key: %v", err)
	}

	// Read the proof
	var proof groth16_bn254.Proof
	_, err = proof.ReadFrom(proofF)
	if err != nil {
		return fmt.Errorf("failed to read proof: %v", err)
	}

	// Verify the proof using the public witness
	err = groth16.Verify(&proof, &vk, pubWit)
	if err != nil {
		return fmt.Errorf("proof verification failed: %v", err)
	}

	fmt.Println("Proof verified successfully!")
	return nil
}

func main() {
	// Call the function to read the proof and verify it using public inputs
	if err := readProofAndVerify(); err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Println("Sudoku proof verification completed.")
	}
}
