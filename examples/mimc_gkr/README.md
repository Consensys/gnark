#### GKR usage

1. bN is standing the bits of N Hashes, if we got 1024 hashes to prove, the bN should be set to 10.

using `frontend.WithGkrBN(bN)` to preset the bN in the prove system.

2. adding GKR circuit to the circuit you would want to prove gkr.

f.g. 

```go=
// Circuit defines a pre-image knowledge proof
// mimc(secret preImage) = public hash
    type Circuit struct {
    // struct tag on a variable is optional
    // default uses variable name and secret visibility.
        PreImage frontend.Variable
        Hash     frontend.Variable `gnark:",public"`
        // GKRs need to be added here
        GKRs     gkr.GkrCircuit
    }
```

3. allocate for gkr circuit
```go=
	mimcCircuit.GKRs.AllocateGKRCircuit(bN)
	circuit.GKRs.AllocateGKRCircuit(bN)
```

4. using gkr hash in circuit, remember the hash used should not exceeded the 2 ^ bN
```go=
	resultst := mimc_gkr.NewMimcWithGKR(api, circuit.PreImage, circuit.PreImage)
	api.AssertIsEqual(circuit.Hash, resultst)
```

5. add gkr assert valid in the final of total Define
```go=
	circuit.GKRs.AssertValid(api)
```

