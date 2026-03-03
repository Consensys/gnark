package gkrtesting

import (
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"sync"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/gkr/gkrcore"
	"github.com/consensys/gnark/std/gkrapi/gkr"
	"github.com/stretchr/testify/require"
)

// Cache for circuits and gates.
// The main functionality is to cache whole circuits, but this package needs to use its own gate registry, in order to avoid import cycles.
// Cache is used in tests for the per-curve GKR packages, but they in turn provide gate degree discovery functions to the gkrgates package.
type Cache struct {
	field    *big.Int
	circuits map[string]circuits
	gates    map[string]gkr.GateFunction
	lock     sync.Mutex
}

type circuits struct {
	serializable gkrcore.SerializableCircuit
	gadget       gkrcore.GadgetCircuit
}

func mimcGate(api gkr.GateAPI, input ...frontend.Variable) frontend.Variable {
	sum := api.Add(input[0], input[1]) //.Add(&sum, &m.ark)  TODO: add ark
	res := api.Mul(sum, sum)           // sum^2
	res = api.Mul(res, sum)            // sum^3
	res = api.Mul(res, res)            // sum^6
	res = api.Mul(res, sum)            // sum^7

	return res
}

func selectInput3Gate(_ gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
	return in[2]
}

func NewCache(field *big.Int) *Cache {
	gates := make(map[string]gkr.GateFunction, 7)
	gates[""] = nil
	gates["identity"] = gkrcore.Identity
	gates["add2"] = gkrcore.Add2
	gates["sub2"] = gkrcore.Sub2
	gates["neg"] = gkrcore.Neg
	gates["mul2"] = gkrcore.Mul2
	gates["mimc"] = mimcGate
	gates["select-input-3"] = selectInput3Gate

	return &Cache{
		field:    field,
		circuits: make(map[string]circuits),
		gates:    gates,
	}
}

// JSONWire is the JSON serialization format for circuit wires (gate name + inputs)
type JSONWire struct {
	Gate   string `json:"gate"`   // gate name, empty for input wires
	Inputs []int  `json:"inputs"` // indices of input wires
}

// JSONCircuit is the JSON serialization format for circuits
type JSONCircuit []JSONWire

// Compile compiles a RawCircuit into a SerializableCircuit.
func (c *Cache) Compile(t require.TestingT, circuit gkrcore.RawCircuit) (gkrcore.GadgetCircuit, gkrcore.SerializableCircuit) {
	gadget, serializable, err := circuit.Compile(c.field)
	require.NoError(t, err)
	return gadget, serializable
}

func (c *Cache) GetCircuit(path string) (gkrcore.SerializableCircuit, gkrcore.GadgetCircuit) {
	c.lock.Lock()
	defer c.lock.Unlock()

	path, err := filepath.Abs(path)
	if err != nil {
		panic(err)
	}
	if circuit, ok := c.circuits[path]; ok {
		return circuit.serializable, circuit.gadget
	}

	var bytes []byte
	if bytes, err = os.ReadFile(path); err != nil {
		panic(err)
	}

	// Unmarshal from JSON format (gate names as strings)
	var jsonCircuit JSONCircuit
	if err = json.Unmarshal(bytes, &jsonCircuit); err != nil {
		panic(err)
	}

	// Convert JSON format to RawCircuit
	rawCircuit := make(gkrcore.RawCircuit, len(jsonCircuit))
	for i, wJSON := range jsonCircuit {
		rawCircuit[i] = gkrcore.RawWire{
			Gate:   c.GetGate(wJSON.Gate),
			Inputs: wJSON.Inputs,
		}
	}
	gCircuit, sCircuit, err := rawCircuit.Compile(c.field)
	if err != nil {
		panic(err)
	}

	c.circuits[path] = circuits{
		serializable: sCircuit,
		gadget:       gCircuit,
	}

	return sCircuit, gCircuit
}

func (c *Cache) RegisterGate(name string, gate gkr.GateFunction) {
	if _, ok := c.gates[name]; ok {
		panic("gate already registered")
	}
	c.gates[name] = gate
}

func (c *Cache) GetGate(name string) gkr.GateFunction {
	if gate, ok := c.gates[name]; ok {
		return gate
	}
	panic("gate not found: " + name)
}

func MiMCCircuit(numRounds int) gkrcore.RawCircuit {
	c := make(gkrcore.RawCircuit, numRounds+2)
	for i := 2; i < len(c); i++ {
		c[i] = gkrcore.RawWire{Gate: mimcGate, Inputs: []int{i - 1, 0}}
	}
	return c
}

type PrintableProof []PrintableSumcheckProof

type PrintableSumcheckProof struct {
	FinalEvalProof  interface{}     `json:"finalEvalProof"`
	PartialSumPolys [][]interface{} `json:"partialSumPolys"`
}

type HashDescription map[string]interface{}
type testCaseInfoJSON struct {
	Hash     HashDescription `json:"hash"`
	Circuit  string          `json:"circuit"`
	Input    [][]interface{} `json:"input"`
	Output   [][]interface{} `json:"output"`
	Proof    PrintableProof  `json:"proof"`
	Schedule *jsonSchedule   `json:"schedule,omitempty"` // nil means DefaultProvingSchedule
}

type TestCaseInfo struct {
	Hash     HashDescription
	Circuit  string
	Input    [][]interface{}
	Output   [][]interface{}
	Proof    PrintableProof
	Schedule gkrcore.ProvingSchedule // nil means DefaultProvingSchedule
}

func (t *TestCaseInfo) UnmarshalJSON(data []byte) error {
	var raw testCaseInfoJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	t.Hash = raw.Hash
	t.Circuit = raw.Circuit
	t.Input = raw.Input
	t.Output = raw.Output
	t.Proof = raw.Proof
	if raw.Schedule != nil {
		t.Schedule = raw.Schedule.ProvingSchedule
	}
	return nil
}

func (t TestCaseInfo) MarshalJSON() ([]byte, error) {
	raw := testCaseInfoJSON{
		Hash:    t.Hash,
		Circuit: t.Circuit,
		Input:   t.Input,
		Output:  t.Output,
		Proof:   t.Proof,
	}
	if t.Schedule != nil {
		raw.Schedule = &jsonSchedule{t.Schedule}
	}
	return json.Marshal(raw)
}

// provingStepJSON is the JSON representation of a ProvingStep with a type discriminator.
type provingStepJSON struct {
	Type   string                `json:"type"`
	Groups []gkrcore.ClaimGroup `json:"groups,omitempty"` // for SumcheckStep
	Wires  []int                 `json:"wires,omitempty"`  // for SkipStep
	Claims []int                 `json:"claimSources,omitempty"` // for SkipStep
}

// marshalSchedule marshals a ProvingSchedule to JSON.
func marshalSchedule(s gkrcore.ProvingSchedule) ([]byte, error) {
	steps := make([]provingStepJSON, len(s))
	for i, step := range s {
		switch v := step.(type) {
		case gkrcore.SumcheckStep:
			steps[i] = provingStepJSON{Type: "sumcheck", Groups: []gkrcore.ClaimGroup(v)}
		case gkrcore.SkipStep:
			steps[i] = provingStepJSON{Type: "skip", Wires: v.Wires, Claims: v.ClaimSources}
		default:
			return nil, errors.New("unknown ProvingStep type")
		}
	}
	return json.Marshal(steps)
}

// unmarshalSchedule unmarshals a ProvingSchedule from JSON.
func unmarshalSchedule(data []byte) (gkrcore.ProvingSchedule, error) {
	var steps []provingStepJSON
	if err := json.Unmarshal(data, &steps); err != nil {
		return nil, err
	}
	s := make(gkrcore.ProvingSchedule, len(steps))
	for i, step := range steps {
		switch step.Type {
		case "sumcheck":
			groups := step.Groups
			if groups == nil {
				groups = []gkrcore.ClaimGroup{}
			}
			s[i] = gkrcore.SumcheckStep(groups)
		case "skip":
			s[i] = gkrcore.SkipStep{Wires: step.Wires, ClaimSources: step.Claims}
		default:
			return nil, errors.New("unknown ProvingStep type: " + step.Type)
		}
	}
	return s, nil
}

// jsonSchedule is a local wrapper enabling custom JSON marshaling for ProvingSchedule
// within TestCaseInfo, since methods cannot be defined on non-local types.
type jsonSchedule struct {
	gkrcore.ProvingSchedule
}

func (j jsonSchedule) MarshalJSON() ([]byte, error) {
	return marshalSchedule(j.ProvingSchedule)
}

func (j *jsonSchedule) UnmarshalJSON(data []byte) (err error) {
	j.ProvingSchedule, err = unmarshalSchedule(data)
	return
}

func (c *Cache) ReadTestCaseInfo(filePath string) (info TestCaseInfo, err error) {
	f, err := os.Open(filePath)
	if err != nil {
		return
	}
	defer func() {
		err = errors.Join(err, f.Close())
	}()
	err = json.NewDecoder(f).Decode(&info)
	return
}

func NoGateCircuit() gkrcore.RawCircuit {
	return gkrcore.RawCircuit{
		{},
	}
}

func SingleAddGateCircuit() gkrcore.RawCircuit {
	return gkrcore.RawCircuit{
		{},
		{},
		{Gate: gkrcore.Add2, Inputs: []int{0, 1}},
	}
}

func SingleMulGateCircuit() gkrcore.RawCircuit {
	return gkrcore.RawCircuit{
		{},
		{},
		{Gate: gkrcore.Mul2, Inputs: []int{0, 1}},
	}
}

func SingleInputTwoIdentityGatesCircuit() gkrcore.RawCircuit {
	return gkrcore.RawCircuit{
		{},
		{Gate: gkrcore.Identity, Inputs: []int{0}},
		{Gate: gkrcore.Identity, Inputs: []int{0}},
	}
}

func SingleInputTwoIdentityGatesComposedCircuit() gkrcore.RawCircuit {
	return gkrcore.RawCircuit{
		{},
		{Gate: gkrcore.Identity, Inputs: []int{0}},
		{Gate: gkrcore.Identity, Inputs: []int{1}},
	}
}

func APowNTimesBCircuit(n int) gkrcore.RawCircuit {
	c := make(gkrcore.RawCircuit, n+2)
	for i := 2; i < len(c); i++ {
		c[i] = gkrcore.RawWire{Gate: gkrcore.Mul2, Inputs: []int{i - 1, 0}}
	}
	return c
}

func SingleMimcCipherGateCircuit() gkrcore.RawCircuit {
	return gkrcore.RawCircuit{
		{},
		{},
		{Gate: mimcGate, Inputs: []int{0, 1}},
	}
}
