SHELL=/bin/bash

.PHONY: clean clean-abi clean-bin clean-go solc

clean-abi:
	cd abi/ && rm -f *.abi

clean-bin:
	cd abi/ && rm -f *.bin

clean-go:
	cd gopkg/ && rm -f *.go

solc:
	solc --bin --abi contracts/verifier.sol --optimize-runs=200  -o abi && abigen --abi abi/PlonkVerifier.abi --bin abi/PlonkVerifier.bin --pkg contract --out gopkg/contract.go --type Contract

clean: clean-abi clean-bin clean-go

all: clean solc
