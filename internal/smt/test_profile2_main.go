//go:build ignore

package main

import (
    "fmt"
    "os"

    pproflib "github.com/google/pprof/profile"
    "github.com/consensys/gnark/frontend"
    "github.com/consensys/gnark/frontend/cs/scs"
    "github.com/consensys/gnark/profile"
    "github.com/consensys/gnark-crypto/ecc"
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
    profilePath := "/tmp/test_profile_debug.pprof"
    
    // Start profiling
    prof := profile.Start(profile.WithPath(profilePath))
    
    // Compile
    _, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &DecompositionOnlyCircuit{})
    if err != nil {
        fmt.Printf("Compile error: %v\n", err)
        return
    }
    
    // Stop profiling
    prof.Stop()
    
    // Read the profile
    f, err := os.Open(profilePath)
    if err != nil {
        fmt.Printf("Open error: %v\n", err)
        return
    }
    defer f.Close()
    
    pprofData, err := pproflib.Parse(f)
    if err != nil {
        fmt.Printf("Parse error: %v\n", err)
        return
    }
    
    fmt.Printf("Profile samples: %d\n", len(pprofData.Sample))
    fmt.Printf("Profile locations: %d\n", len(pprofData.Location))
    fmt.Printf("Profile functions: %d\n", len(pprofData.Function))
    
    for i, sample := range pprofData.Sample {
        fmt.Printf("\nSample %d (value: %v):\n", i, sample.Value)
        for _, loc := range sample.Location {
            fmt.Printf("  Location ID=%d:\n", loc.ID)
            for _, line := range loc.Line {
                if line.Function != nil {
                    fmt.Printf("    %s:%d (%s)\n", line.Function.Filename, line.Line, line.Function.Name)
                }
            }
        }
    }
}
