package stats

import (
	"encoding/gob"
	"fmt"
	"os"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
)

var AllCircuits = make(map[string]Circuit)

func NewGlobalStats() *globalStats {
	return &globalStats{
		Stats: make(map[string][backend.PLONK + 1][ecc.BW6_633 + 1]circuitStats),
	}
}

func (s *globalStats) Save(path string) error {
	fStats, err := os.Create(path)
	if err != nil {
		return err
	}
	defer fStats.Close()

	encoder := gob.NewEncoder(fStats)
	return encoder.Encode(s.Stats)
}

func (s *globalStats) Load(path string) error {
	fStats, err := os.Open(path)
	if err != nil {
		return err
	}
	defer fStats.Close()
	decoder := gob.NewDecoder(fStats)
	return decoder.Decode(&s.Stats)
}

func NewCircuitStats(curve ecc.ID, backendID backend.ID, circuit frontend.Circuit) (circuitStats, error) {
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
	internal, _, _ := ccs.GetNbVariables()

	return circuitStats{nbConstraints, internal}, nil
}

func (s *globalStats) Add(curve ecc.ID, backendID backend.ID, cs circuitStats, circuitName string) {
	s.Lock()
	defer s.Unlock()
	rs := s.Stats[circuitName]
	rs[backendID][curve] = cs
	s.Stats[circuitName] = rs
}

type Circuit struct {
	Circuit frontend.Circuit
	Curves  []ecc.ID
}

type globalStats struct {
	sync.RWMutex
	Stats map[string][backend.PLONK + 1][ecc.BW6_633 + 1]circuitStats
}

type circuitStats struct {
	NbConstraints, NbInternalWires int
}

func (cs circuitStats) String() string {
	return fmt.Sprintf("nbConstraints: %d, nbInternalWires: %d", cs.NbConstraints, cs.NbInternalWires)
}
