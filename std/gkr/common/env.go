package common

import (
	"fmt"
	"os"
	"strconv"
)

const (
	bNEnv         = "BN_GKR"
	nChunksEnv    = "NCHUNKS_GKR"
	profileEnv    = "PROFILE_GKR"
	traceEnv      = "TRACE_GKR"
	nProcessesEnv = "NPROCESSES_ENV"
	panicMsg      = "Please set %q before running the benchmark"
)

// GetBN attempt to parse the environment variable BN_GKR
// It panics if it's not set
func GetBN() int {
	bN, err := strconv.Atoi(os.Getenv(bNEnv))
	if err != nil {
		panic(fmt.Sprintf(panicMsg, bNEnv))
	}
	return bN
}

// GetNChunks attempts to parse the environment variable NCHUNKS_GKR
// It panics if it's not set'
func GetNChunks() int {
	nChunks, err := strconv.Atoi(os.Getenv(nChunksEnv))
	if err != nil {
		panic(fmt.Sprintf(panicMsg, nChunksEnv))
	}
	return nChunks
}

// GetProfiled attempts to parse the environment variable PROFILE_GKR
// It return false if it's not set or set to a value != 1
func GetProfiled() bool {
	return os.Getenv(profileEnv) == "1"
}

// GetTraced attempts to parse the environment variable PROFILE_GKR
// It return false if it's not set or set to a value != 1
func GetTraced() bool {
	return os.Getenv(traceEnv) == "1"
}

// GetNProcesses returns the env variable and panic if it does not find it
func GetNProcesses() int {
	nProcesses, err := strconv.Atoi(os.Getenv(nProcessesEnv))
	if err != nil {
		panic(fmt.Sprintf(panicMsg, nProcessesEnv))
	}
	return nProcesses
}
