SHELL=/bin/bash

.PHONY: clean clean-abi clean-bin clean-go solc

clean-abi:
	cd contracts/crypto && rm -f *.abi

clean-bin:
	cd contracts/crypto && rm -f *.bin

clean-go:
	cd gopkg/ && rm -f *.go

solc:
	solc --bin --abi contracts/crypto/HashFr.sol -o abi && abigen --abi abi/HashFr.abi --bin abi/HashFr.bin --pkg hashfr --out gopkg/hashfr.go --type HashFr

clean: clean-abi clean-bin clean-go

all: clean solc
