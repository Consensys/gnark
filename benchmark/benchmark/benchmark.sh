#!/bin/bash

# used by docker 
cd bls377 && ./benchmark
cd ../bls381 && ./benchmark
cd ../bn256 && ./benchmark