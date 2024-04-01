package stats

import (
	"encoding/gob"
	"fmt"
	"os"
	"sync"

	"github.com/consensys/gnark"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
)

const nbCurves = 7

func CurveIdx(curve ecc.ID) int {
	switch curve {
	case ecc.BN254:
		return 0
	case ecc.BLS12_377:
		return 1
	case ecc.BLS12_381:
		return 2
	case ecc.BLS24_315:
		return 3
	case ecc.BW6_761:
		return 4
	case ecc.BW6_633:
		return 5
	case ecc.BLS24_317:
		return 6
	default:
		panic("not implemented")
	}
}

func init() {
	if nbCurves != len(gnark.Curves()) {
		panic("expected nbCurves == len(gnark.Curves())")
	}
}

func NewGlobalStats() *globalStats {
	return &globalStats{
		Stats: make(map[string][backend.PLONK + 1][nbCurves + 1]snippetStats),
	}
}

func (s *globalStats) Save(path string) error {
	fStats, err := os.Create(path) //#nosec G304 -- ignoring internal package s
	if err != nil {
		return err
	}

	encoder := gob.NewEncoder(fStats)
	err = encoder.Encode(s.Stats)
	_ = fStats.Close()
	return err
}

func (s *globalStats) Load(path string) error {
	fStats, err := os.Open(path) //#nosec G304 -- ignoring internal package
	if err != nil {
		return err
	}

	decoder := gob.NewDecoder(fStats)
	err = decoder.Decode(&s.Stats)
	_ = fStats.Close()
	return err
}

func NewSnippetStats(curve ecc.ID, backendID backend.ID, circuit frontend.Circuit) (snippetStats, error) {
	var newCompiler frontend.NewBuilder

	switch backendID {
	case backend.GROTH16:
		newCompiler = r1cs.NewBuilder
	case backend.PLONK:
		newCompiler = scs.NewBuilder
	default:
		panic("not implemented")
	}

	ccs, err := frontend.Compile(curve.ScalarField(), newCompiler, circuit, frontend.IgnoreUnconstrainedInputs())
	if err != nil {
		return snippetStats{}, err
	}

	// ensure we didn't introduce regressions that make circuits less efficient
	nbConstraints := ccs.GetNbConstraints()
	internal, _, _ := ccs.GetNbVariables()

	return snippetStats{nbConstraints, internal}, nil
}

func (s *globalStats) Add(curve ecc.ID, backendID backend.ID, cs snippetStats, circuitName string) {
	s.Lock()
	defer s.Unlock()
	rs := s.Stats[circuitName]
	rs[backendID][CurveIdx(curve)] = cs
	s.Stats[circuitName] = rs
}

type Circuit struct {
	Circuit frontend.Circuit
	Curves  []ecc.ID
}

type globalStats struct {
	sync.RWMutex
	Stats map[string][backend.PLONK + 1][nbCurves + 1]snippetStats
}

type snippetStats struct {
	NbConstraints, NbInternalWires int
}

func (cs snippetStats) String() string {
	return fmt.Sprintf("nbConstraints: %d, nbInternalWires: %d", cs.NbConstraints, cs.NbInternalWires)
}
