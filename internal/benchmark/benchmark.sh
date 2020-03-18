#!/bin/bash

docker build .. -f ../Dockerfile.benchmark -t gnarkbench
echo "4 CPUS"
docker run --cpus="4" --rm -it gnarkbench ./benchmark.sh 
echo "8 CPUS"
docker run --cpus="8" --rm -it gnarkbench ./benchmark.sh
echo "all CPUS"
docker run --rm -it gnarkbench ./benchmark.sh 