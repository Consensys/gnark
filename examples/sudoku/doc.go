// Package sudoku implements a Sudoku circuit using gnark.
//
// [Sudoku] is a popular puzzle to fill a 9x9 grid with digits so that each
// column, each row, and each of the nine 3x3 sub-grids that compose the grid
// contain all of the digits from 1 to 9. This package provides a circuit that
// verifies a solution to a Sudoku puzzle.
//
// See the included full example on how to define the circuit, run the setup,
// generate proof and verify the proof. This example also demonstrates how to
// serialize and deserialize the values produced during setup and proof
// generation.
//
// [Sudoku]: https://en.wikipedia.org/wiki/Sudoku
package sudoku
