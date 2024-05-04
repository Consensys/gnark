// Package evmprecompiles implements the Ethereum VM precompile contracts.
//
// This package collects all the precompile functions into a single location for
// easier integration. The main functionality is implemented elsewhere. This
// package right now implements:
//  1. ECRECOVER ✅ -- function [ECRecover]
//  2. SHA256 ❌ -- in progress
//  3. RIPEMD160 ❌ -- postponed
//  4. ID ❌ -- trivial to implement without function
//  5. EXPMOD ✅ -- function [Expmod]
//  6. BN_ADD ✅ -- function [ECAdd]
//  7. BN_MUL ✅ -- function [ECMul]
//  8. SNARKV ✅ -- function [ECPair]
//  9. BLAKE2F ❌ -- postponed
//
// This package uses local representation for the arguments. It is up to the
// user to instantiate corresponding types from their application-specific data.
package evmprecompiles
