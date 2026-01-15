//go:build ignore

package main

import (
    "fmt"
    "os"

    "github.com/consensys/gnark/frontend"
    "github.com/consensys/gnark/internal/smt"
)

type DecompositionOnlyCircuit struct {
    X     frontend.Variable `gnark:",public"`
    Limb0 frontend.Variable
    Limb1 frontend.Variable
}

func (c *DecompositionOnlyCircuit) Define(api frontend.API) error {
    recomp := api.Add(c.Limb0, api.Mul(c.Limb1, 256))
    api.AssertIsEqual(recomp, c.X)
    return nil
}

func main() {
    opts := smt.DefaultCompileOptions()
    opts.TestName = "TestProfile"
    
    result, err := smt.CompileCircuit(&DecompositionOnlyCircuit{}, opts)
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }
    
    fmt.Printf("Has debug info: %v\n", result.DebugInfo != nil && result.DebugInfo.HasDebugInfo)
    if result.DebugInfo != nil {
        fmt.Printf("Constraint debug entries: %d\n", len(result.DebugInfo.ConstraintDebug))
        for idx, cdi := range result.DebugInfo.ConstraintDebug {
            fmt.Printf("  Constraint %d: %d stack frames\n", idx, len(cdi.Stack))
            for j, loc := range cdi.Stack {
                fmt.Printf("    [%d] %s:%d (%s)\n", j, loc.File, loc.Line, loc.Function)
            }
        }
    }
    
    result.WriteReport(os.Stdout, "TestProfile", smt.FormatTerminal)
}
