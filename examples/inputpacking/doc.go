// Package inputpacking illustrates input packing for reducing public input.

// Usually in a SNARK circuit there are public and private inputs. The public
// inputs are known to the prover and verifier, while the private inputs are
// known only to the prover. To verify the proof, the verifier needs to provide
// the public inputs as an input to the verification algorithm.
//
// However, there are several drawbacks to this approach:
//  1. The public inputs may not be of a convenient format -- this happens for example when using the non-native arithmetic where we work on limbs.
//  2. The verifier work depends on the number of public inputs -- this is a problem in case of a recursive SNARK verifier, making the recursion more expensive.
//  3. The public input needs to be provided as a calldata to the Solidity verifier, which is expensive.
//
// An alternative approach however is to provide only a hash of the public
// inputs to the verifier. This way, if the verifier computes the hash of the
// inputs on its own, it can be sure that the inputs are correct and we can
// mitigate the issues.
//
// This examples how to use this approach for both native and non-native inputs. We use MiMC hash function.
package inputpacking
