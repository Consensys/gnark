package stats

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"sync"

	"github.com/consensys/gnark"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
)

func NewGlobalStats() *globalStats {
	return &globalStats{
		Stats: make(map[string]map[backend.ID]map[ecc.ID]snippetStats),
	}
}

func (s *globalStats) WriteTo(w io.Writer) (int64, error) {
	csvWriter := csv.NewWriter(w)

	// write header
	if err := csvWriter.Write([]string{"circuit", "curve", "backend", "nbConstraints", "nbWires"}); err != nil {
		return 0, err
	}

	// sort circuits names to have a deterministic output
	var circuitNames []string
	for circuitName := range s.Stats {
		circuitNames = append(circuitNames, circuitName)
	}

	sort.Strings(circuitNames)

	// write data
	for _, circuitName := range circuitNames {
		innerStats := s.Stats[circuitName]
		for _, backendID := range backend.Implemented() {
			backendName := backendID.String()
			for _, curveID := range gnark.Curves() {
				curveName := curveID.String()
				snippet := innerStats[backendID][curveID]
				if err := csvWriter.Write([]string{circuitName, curveName, backendName, strconv.Itoa(snippet.NbConstraints), strconv.Itoa(snippet.NbInternalWires)}); err != nil {
					return 0, err
				}
			}
		}
	}

	csvWriter.Flush()
	return 0, nil
}

func (s *globalStats) Load(path string) error {
	fStats, err := os.Open(path) //#nosec G304 -- ignoring internal package
	if err != nil {
		return err
	}

	defer fStats.Close()

	csvReader := csv.NewReader(fStats)
	records, err := csvReader.ReadAll()
	if err != nil {
		return err
	}

	s.Stats = make(map[string]map[backend.ID]map[ecc.ID]snippetStats)

	for i, record := range records {
		if i == 0 && len(record) == 5 && record[0] == "circuit" {
			continue
		}
		// we don't do validation here, we assume the file is correct;;
		circuitName := record[0]
		curveID, _ := ecc.IDFromString(record[1])
		backendID := backend.IDFromString(record[2])
		nbConstraints, _ := strconv.Atoi(record[3])
		nbWires, _ := strconv.Atoi(record[4])

		if _, ok := s.Stats[circuitName]; !ok {
			s.Stats[circuitName] = make(map[backend.ID]map[ecc.ID]snippetStats)
		}
		if _, ok := s.Stats[circuitName][backendID]; !ok {
			s.Stats[circuitName][backendID] = make(map[ecc.ID]snippetStats)
		}
		s.Stats[circuitName][backendID][curveID] = snippetStats{nbConstraints, nbWires}
	}

	return nil
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
	if _, ok := s.Stats[circuitName]; !ok {
		s.Stats[circuitName] = make(map[backend.ID]map[ecc.ID]snippetStats)
	}
	if _, ok := s.Stats[circuitName][backendID]; !ok {
		s.Stats[circuitName][backendID] = make(map[ecc.ID]snippetStats)
	}
	s.Stats[circuitName][backendID][curve] = cs
}

type Circuit struct {
	Circuit frontend.Circuit
	Curves  []ecc.ID
}

type globalStats struct {
	sync.RWMutex
	Stats map[string]map[backend.ID]map[ecc.ID]snippetStats
}

type snippetStats struct {
	NbConstraints, NbInternalWires int
}

func (cs snippetStats) String() string {
	return fmt.Sprintf("nbConstraints: %d, nbInternalWires: %d", cs.NbConstraints, cs.NbInternalWires)
}
