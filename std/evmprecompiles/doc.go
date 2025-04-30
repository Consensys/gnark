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
//  10. POINT_EVALUATION ❌ -- work in progress
//  11. BLS12_G1MSM ✅ -- function [ECAddG1BLS]
//  12. BLS12_G1MSM ✅ -- function [ECMSMG1BLS]
//  13. BLS12_G2ADD ✅ -- function [ECAddG2BLS]
//  14. BLS12_G2MSM ✅ -- function [ECMSMG2BLS]
//  15. BLS12_PAIRING_CHECK ✅ -- function [ECPairBLS]
//  16. BLS12_MAP_FP_TO_G1 ✅ -- function [ECMapToG1BLS]
//  17. BLS12_MAP_FP2_TO_G2 ✅ -- function [ECMapToG2BLS]
//
// This package uses local representation for the arguments. It is up to the
// user to instantiate corresponding types from their application-specific data.
package evmprecompiles
