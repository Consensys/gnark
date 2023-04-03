SHELL=/bin/bash

.PHONY: clean clean-abi clean-bin clean-go solc

clean-abi:
	cd contracts/hashfr && rm -f *.abi

clean-bin:
	cd contracts/hashfr && rm -f *.bin

clean-go:
	cd contracts/hashfr && rm -f *.go

solc:
	cd contracts/hashfr && solc --bin --abi HashFr.sol -o . && abigen --abi HashFr.abi --bin HashFr.bin --pkg hashfr --out hashfr.go --type HashFr

clean: clean-abi clean-bin clean-go

all: clean solc
