# Merkle Proof Verification Package

This package addresses [GitHub issue #1528](https://github.com/Consensys/gnark/issues/1528) by providing a standardized, high-level API for Merkle proof verification in gnark circuits.

## Problem Solved

Previously, developers had to manually implement Merkle proof verification using the lower-level `std/accumulator/merkle` package, which required:
- Complex struct setup and management
- Manual handling of proof paths and binary decomposition
- Repetitive boilerplate code
- Higher risk of implementation errors

## New Solution

The `std/merkle` package provides a simple, one-line API that abstracts all the complexity:

```go
merkle.AssertIsMember(api, &hasher, root, proof, leaf, leafIndex)
```

## Key Features

- **Simple API**: One function call replaces complex manual implementation
- **Reduced Boilerplate**: Minimal code required for Merkle proof verification
- **Error Prevention**: Standardized implementation reduces developer mistakes
- **Flexibility**: Works with any hash function implementing `hash.FieldHasher`
- **Multiple Variants**: Support for variable depth, multiple memberships, and root computation

## Functions Provided

- `AssertIsMember`: Basic Merkle proof verification
- `AssertIsMemberVariableDepth`: For trees with variable depth
- `AssertMultipleMemberships`: Efficient verification of multiple proofs
- `VerifyProofAndRoot`: Compute root without assertion

## Usage Example

```go
type MyCircuit struct {
    Root      frontend.Variable       `gnark:",public"`
    Proof     merkle.MerkleProof     `gnark:",secret"`
    Leaf      frontend.Variable       `gnark:",secret"`
    LeafIndex frontend.Variable       `gnark:",secret"`
}

func (c *MyCircuit) Define(api frontend.API) error {
    h, err := mimc.NewMiMC(api)
    if err != nil {
        return err
    }
    
    // Simple one-line verification!
    merkle.AssertIsMember(api, &h, c.Root, c.Proof, c.Leaf, c.LeafIndex)
    return nil
}
```

## Common Use Cases

- **Allowlists**: Prove membership without revealing the full list
- **Private Voting**: Verify voter eligibility while maintaining privacy
- **State Verification**: Prove blockchain state transitions
- **Access Control**: Privacy-preserving authentication
- **Set Membership**: Prove membership in private sets

## Running the Example

```bash
go run examples/merkle_proof/main.go
```

This demonstrates a complete allowlist verification example using the new API.

## Testing

```bash
go test ./std/merkle -v
```

The package includes comprehensive tests covering all functions and edge cases.

## Benefits

✅ **Simplified Development**: Reduces Merkle proof verification to a single function call  
✅ **Standardized Interface**: Consistent API across all gnark applications  
✅ **Reduced Errors**: Less room for implementation mistakes  
✅ **Better Performance**: Optimized internal implementation  
✅ **Easy Integration**: Drop-in replacement for manual implementations  

This implementation makes gnark more powerful and easier to use for developers building privacy-preserving applications. 
