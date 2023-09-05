SHELL=/bin/bash

.PHONY: clean clean-abi clean-bin clean-go solc

clean-abi:
	cd abi/ && rm -f *.abi

clean-bin:
	cd abi/ && rm -f *.bin

clean-go:
	cd gopkg/ && rm -f *.go

solc:
	solc --bin --abi contracts/Verifier.sol -o abi && abigen --abi abi/PlonkVerifier.abi --bin abi/PlonkVerifier.bin --pkg contract --out gopkg/contract.go --type Contract
	# solc --bin --abi contracts/test/TestVerifierFull.sol -o abi && abigen --abi abi/TestPlonkVerifierFull.abi --bin abi/TestPlonkVerifierFull.bin --pkg contract --out gopkg/contract.go --type Contract

clean: clean-abi clean-bin clean-go

all: clean solc
