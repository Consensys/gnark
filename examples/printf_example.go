package examples

import "github.com/consensys/gnark/frontend"

func PrintfExample(api frontend.API) {
    x := api.Add(10, 20)
    y := api.Mul(x, 2)
    
    // Basic usage
    api.Printf("x = %v, y = %v\n", x, y)
    
    // Different formats for constants and variables
    api.Printf("dec: %d hex: %x\n", x, x)
    
    // Debugging information
    api.Printf("coeff: %c var: %i\n", x, y)
}
