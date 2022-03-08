package main

import (
	"encoding/gob"
	"log"
	"os"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/internal/backend/circuits"
)

const refPath = "latest.stats"

var allCircuits []struct {
	circuit frontend.Circuit
	name    string
}

func init() {
	for k := range circuits.Circuits {
		allCircuits = append(allCircuits, struct {
			circuit frontend.Circuit
			name    string
		}{circuits.Circuits[k].Circuit, k})
	}

	// add std circuits
}

func main() {
	stats := newStats()

	// load reference objects
	// for each circuit, on each curve, on each backend
	// compare with reference stats
	var wg sync.WaitGroup
	for _, c := range allCircuits {
		wg.Add(1)
		go func(name string, circuit frontend.Circuit) {
			defer wg.Done()
			for _, curve := range ecc.Implemented() {
				for _, backendID := range backend.Implemented() {
					s, err := newCircuitStats(curve, backendID, circuit, name)
					if err != nil {
						log.Fatalf("building stats for circuit %s %v", name, err)
					}
					stats.add(curve, backendID, s, name)
				}
			}
		}(c.name, c.circuit)
	}
	wg.Wait()
	if err := stats.save(refPath); err != nil {
		log.Fatal(err)
	}
	log.Println("successfully saved new reference stats file", refPath)
}

type stats struct {
	sync.RWMutex
	mStats map[string][backend.PLONK + 1][ecc.BW6_633 + 1]circuitStats
}

type circuitStats struct {
	NbConstraints, Internal, Secret, Public int
}

func newStats() *stats {
	return &stats{
		mStats: make(map[string][backend.PLONK + 1][ecc.BW6_633 + 1]circuitStats),
	}
}

func (s *stats) save(path string) error {
	fStats, err := os.Create(path)
	if err != nil {
		return err
	}
	defer fStats.Close()

	encoder := gob.NewEncoder(fStats)
	return encoder.Encode(s.mStats)
}

func (s *stats) load(path string) error {
	fStats, err := os.Open(path)
	if err != nil {
		return err
	}
	defer fStats.Close()
	decoder := gob.NewDecoder(fStats)
	return decoder.Decode(&s.mStats)
}

func newCircuitStats(curve ecc.ID, backendID backend.ID, circuit frontend.Circuit, circuitName string) (circuitStats, error) {
	var newCompiler frontend.NewBuilder

	switch backendID {
	case backend.GROTH16:
		newCompiler = r1cs.NewBuilder
	case backend.PLONK:
		newCompiler = scs.NewBuilder
	default:
		panic("not implemented")
	}

	ccs, err := frontend.Compile(curve, newCompiler, circuit)
	if err != nil {
		return circuitStats{}, err
	}

	// ensure we didn't introduce regressions that make circuits less efficient
	nbConstraints := ccs.GetNbConstraints()
	internal, secret, public := ccs.GetNbVariables()

	return circuitStats{nbConstraints, internal, secret, public}, nil
}

func (s *stats) add(curve ecc.ID, backendID backend.ID, cs circuitStats, circuitName string) {
	s.Lock()
	defer s.Unlock()
	rs := s.mStats[circuitName]
	rs[backendID][curve] = cs
	s.mStats[circuitName] = rs
}
