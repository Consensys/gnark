//go:build ignore

package main

import (
    "fmt"
    "os"

    pproflib "github.com/google/pprof/profile"
    "github.com/consensys/gnark-crypto/ecc"
    "github.com/consensys/gnark/frontend"
    "github.com/consensys/gnark/frontend/cs/scs"
    "github.com/consensys/gnark/profile"
    cs_bn254 "github.com/consensys/gnark/constraint/bn254"
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
    profilePath := "/tmp/test_debug_profile.pprof"
    
    // Start profiling
    prof := profile.Start(profile.WithPath(profilePath))
    
    // Compile
    ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &DecompositionOnlyCircuit{})
    if err != nil {
        fmt.Printf("Compile error: %v\n", err)
        return
    }
    
    // Stop profiling (writes to file)
    prof.Stop()
    
    // Check file exists
    info, err := os.Stat(profilePath)
    if err != nil {
        fmt.Printf("Stat error: %v\n", err)
        return
    }
    fmt.Printf("Profile file exists, size: %d bytes\n", info.Size())
    
    // Read the profile directly
    f, err := os.Open(profilePath)
    if err != nil {
        fmt.Printf("Open error: %v\n", err)
        return
    }
    pprofData, err := pproflib.Parse(f)
    f.Close()
    if err != nil {
        fmt.Printf("Parse error: %v\n", err)
        return
    }
    fmt.Printf("Direct read: %d samples\n", len(pprofData.Sample))
    
    // Now extract via the debug info function
    scsCS := ccs.(*cs_bn254.SparseR1CS)
    debugInfo := smt.ExtractDebugInfoWithProfile(scsCS, profilePath)
    
    fmt.Printf("\nExtracted debug info:\n")
    fmt.Printf("  HasDebugInfo: %v\n", debugInfo.HasDebugInfo)
    fmt.Printf("  Constraint entries: %d\n", len(debugInfo.ConstraintDebug))
    
    for idx, cdi := range debugInfo.ConstraintDebug {
        fmt.Printf("  Constraint %d: %d stack frames\n", idx, len(cdi.Stack))
        for j, loc := range cdi.Stack {
            fmt.Printf("    [%d] %s\n", j, loc.String())
        }
    }
    
    // Cleanup
    os.Remove(profilePath)
}
