package smt

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/debug"
	pproflib "github.com/google/pprof/profile"
)

// DebugExporter provides interface for extracting debug info from constraint systems.
// This interface uses method-based access. For direct field access, use ExtractDebugInfoFromSystem.
type DebugExporter interface {
	// GetDebugInfo returns the debug info entries
	GetDebugInfo() []constraint.LogEntry
	// GetSymbolTable returns the symbol table for resolving locations
	GetSymbolTable() debug.SymbolTable
	// GetMDebug returns the mapping from constraint ID to debug info ID
	GetMDebug() map[int]int
}

// SystemDebugFields provides direct access to System debug fields.
// This is used when the constraint system embeds constraint.System.
type SystemDebugFields struct {
	DebugInfo   []constraint.LogEntry
	SymbolTable debug.SymbolTable
	MDebug      map[int]int
}

// SourceLocation represents a location in source code.
type SourceLocation struct {
	File     string `json:"file"`
	Function string `json:"function"`
	Line     int64  `json:"line"`
}

// String returns a formatted source location string.
func (s SourceLocation) String() string {
	if s.File == "" {
		return ""
	}
	// Use just the base filename for cleaner output
	base := filepath.Base(s.File)
	if s.Function != "" {
		return s.Function + " at " + base + ":" + formatInt64(s.Line)
	}
	return base + ":" + formatInt64(s.Line)
}

// ShortString returns a concise source location (file:line only).
func (s SourceLocation) ShortString() string {
	if s.File == "" {
		return ""
	}
	return filepath.Base(s.File) + ":" + formatInt64(s.Line)
}

// ConstraintDebugInfo contains debug information for a constraint.
type ConstraintDebugInfo struct {
	// ConstraintIndex is the index of the constraint
	ConstraintIndex int `json:"constraint_index"`
	// Caller is the high-level description of what created this constraint
	Caller string `json:"caller,omitempty"`
	// Stack is the call stack leading to this constraint
	Stack []SourceLocation `json:"stack,omitempty"`
}

// ExtractedDebugInfo contains all debug information from a constraint system.
type ExtractedDebugInfo struct {
	// ConstraintDebug maps constraint index to its debug info
	ConstraintDebug map[int]*ConstraintDebugInfo
	// VariableDebug maps variable index to where it was created
	VariableDebug map[int]*ConstraintDebugInfo
	// Functions is the list of all functions in the symbol table
	Functions []debug.Function
	// HasDebugInfo indicates whether debug info was available
	HasDebugInfo bool
}

// ExtractDebugInfo extracts debug information from a constraint system using the DebugExporter interface.
func ExtractDebugInfo(cs DebugExporter) *ExtractedDebugInfo {
	fields := SystemDebugFields{
		DebugInfo:   cs.GetDebugInfo(),
		SymbolTable: cs.GetSymbolTable(),
		MDebug:      cs.GetMDebug(),
	}
	return ExtractDebugInfoFromFields(fields)
}

// ExtractDebugInfoFromFields extracts debug information from System debug fields directly.
// This is useful when the constraint system embeds constraint.System but doesn't implement DebugExporter.
func ExtractDebugInfoFromFields(fields SystemDebugFields) *ExtractedDebugInfo {
	result := &ExtractedDebugInfo{
		ConstraintDebug: make(map[int]*ConstraintDebugInfo),
		VariableDebug:   make(map[int]*ConstraintDebugInfo),
	}

	result.Functions = fields.SymbolTable.Functions
	result.HasDebugInfo = len(fields.DebugInfo) > 0

	// Build constraint debug info from MDebug mapping
	for constraintID, debugID := range fields.MDebug {
		if debugID < 0 || debugID >= len(fields.DebugInfo) {
			continue
		}

		entry := fields.DebugInfo[debugID]
		cdi := &ConstraintDebugInfo{
			ConstraintIndex: constraintID,
			Caller:          entry.Caller,
		}

		// Resolve stack locations
		for _, locID := range entry.Stack {
			if locID < 0 || locID >= len(fields.SymbolTable.Locations) {
				continue
			}
			loc := fields.SymbolTable.Locations[locID]

			var funcName, fileName string
			if loc.FunctionID >= 0 && loc.FunctionID < len(fields.SymbolTable.Functions) {
				fn := fields.SymbolTable.Functions[loc.FunctionID]
				funcName = fn.Name
				fileName = fn.Filename
			}

			cdi.Stack = append(cdi.Stack, SourceLocation{
				File:     fileName,
				Function: funcName,
				Line:     loc.Line,
			})
		}

		result.ConstraintDebug[constraintID] = cdi
	}

	return result
}

// ExtractDebugInfoWithProfile extracts debug info from both the constraint system
// and a pprof profile file. The profile provides constraint-by-constraint source locations.
func ExtractDebugInfoWithProfile(cs DebugExporter, profilePath string) *ExtractedDebugInfo {
	result := ExtractDebugInfo(cs)
	return enrichWithProfile(result, profilePath)
}

// ExtractDebugInfoFromProfile extracts debug info primarily from a pprof profile file.
// Use this when you only have access to the profile file (profiling was enabled during compilation).
func ExtractDebugInfoFromProfile(profilePath string) *ExtractedDebugInfo {
	result := &ExtractedDebugInfo{
		ConstraintDebug: make(map[int]*ConstraintDebugInfo),
		VariableDebug:   make(map[int]*ConstraintDebugInfo),
	}
	return enrichWithProfile(result, profilePath)
}

// ExtractDebugInfoWithFieldsAndProfile extracts debug info from both System fields and a profile.
func ExtractDebugInfoWithFieldsAndProfile(fields SystemDebugFields, profilePath string) *ExtractedDebugInfo {
	result := ExtractDebugInfoFromFields(fields)
	return enrichWithProfile(result, profilePath)
}

// enrichWithProfile adds profile-based source locations to an existing debug info.
func enrichWithProfile(result *ExtractedDebugInfo, profilePath string) *ExtractedDebugInfo {
	if profilePath == "" {
		return result
	}

	// Check if file exists
	if _, err := os.Stat(profilePath); os.IsNotExist(err) {
		return result
	}

	// Read the profile from disk
	pprofData, err := readPprofProfile(profilePath)
	if err != nil || pprofData == nil {
		return result
	}

	// Extract locations from profile samples
	// Each sample corresponds to one constraint (in order)
	for sampleIdx, sample := range pprofData.Sample {
		if sample == nil || len(sample.Location) == 0 {
			continue
		}

		// Skip if we already have debug info for this constraint from the CS
		if _, exists := result.ConstraintDebug[sampleIdx]; exists {
			continue
		}

		cdi := &ConstraintDebugInfo{
			ConstraintIndex: sampleIdx,
		}

		// Extract stack from profile locations
		for _, loc := range sample.Location {
			if loc == nil || len(loc.Line) == 0 {
				continue
			}

			for _, line := range loc.Line {
				if line.Function == nil {
					continue
				}

				cdi.Stack = append(cdi.Stack, SourceLocation{
					File:     line.Function.Filename,
					Function: cleanFunctionName(line.Function.Name),
					Line:     line.Line,
				})
			}
		}

		if len(cdi.Stack) > 0 {
			result.ConstraintDebug[sampleIdx] = cdi
		}
	}

	result.HasDebugInfo = len(result.ConstraintDebug) > 0
	return result
}

// readPprofProfile reads a pprof profile from disk.
func readPprofProfile(path string) (*pproflib.Profile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return pproflib.Parse(f)
}

// cleanFunctionName simplifies a fully qualified function name.
func cleanFunctionName(name string) string {
	// Remove package path, keep just the function name
	if idx := strings.LastIndex(name, "/"); idx >= 0 {
		name = name[idx+1:]
	}
	// Handle generics syntax
	name = strings.ReplaceAll(name, "[...]", "[T]")
	return name
}

// GetConstraintLocation returns a human-readable location for a constraint.
// It prioritizes user code over internal gnark code.
func (d *ExtractedDebugInfo) GetConstraintLocation(constraintIdx int) string {
	if d == nil || d.ConstraintDebug == nil {
		return ""
	}

	cdi, ok := d.ConstraintDebug[constraintIdx]
	if !ok || len(cdi.Stack) == 0 {
		return ""
	}

	// Find the first user code frame (not internal gnark code)
	for _, loc := range cdi.Stack {
		if !isInternalGnarkFrame(loc) {
			return loc.ShortString()
		}
	}

	// Fall back to first frame if all are internal
	return cdi.Stack[0].ShortString()
}

// isInternalGnarkFrame returns true if the location is internal gnark code.
func isInternalGnarkFrame(loc SourceLocation) bool {
	// Filter out gnark internal packages (specific paths within gnark repo)
	internalPaths := []string{
		"/frontend/cs/scs/",
		"/frontend/cs/r1cs/",
		"/constraint/bn254/",
		"/constraint/bls",
		"/constraint/core.go",
		"gnark/profile/",
	}
	for _, path := range internalPaths {
		if strings.Contains(loc.File, path) {
			return true
		}
	}
	// Also filter by function name patterns
	internalFunctions := []string{
		"scs.(*builder",
		"r1cs.(*builder",
		"constraint.",
	}
	for _, fn := range internalFunctions {
		if strings.Contains(loc.Function, fn) {
			return true
		}
	}
	return false
}

// GetConstraintStack returns the full stack trace for a constraint.
func (d *ExtractedDebugInfo) GetConstraintStack(constraintIdx int) []SourceLocation {
	if d == nil || d.ConstraintDebug == nil {
		return nil
	}

	cdi, ok := d.ConstraintDebug[constraintIdx]
	if !ok {
		return nil
	}

	return cdi.Stack
}

// GetConstraintStackString returns a formatted stack trace string.
func (d *ExtractedDebugInfo) GetConstraintStackString(constraintIdx int) string {
	stack := d.GetConstraintStack(constraintIdx)
	if len(stack) == 0 {
		return ""
	}

	var parts []string
	for _, loc := range stack {
		if s := loc.String(); s != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, " <- ")
}

// GetVariableLocation attempts to find where a variable was created.
// This is heuristic - we look for the first constraint that defines this variable.
func (d *ExtractedDebugInfo) GetVariableLocation(varIdx int, constraints []ExtractedConstraint) string {
	if d == nil || d.ConstraintDebug == nil {
		return ""
	}

	// Find first constraint where this variable appears as output (XC with QO != 0)
	for i, c := range constraints {
		if int(c.XC) == varIdx && c.QO.Sign() != 0 {
			return d.GetConstraintLocation(i)
		}
	}

	// Fall back to first constraint where variable appears
	for i, c := range constraints {
		if int(c.XA) == varIdx || int(c.XB) == varIdx || int(c.XC) == varIdx {
			return d.GetConstraintLocation(i)
		}
	}

	return ""
}

func formatInt64(n int64) string {
	if n < 0 {
		return "-" + formatUint64(uint64(-n))
	}
	return formatUint64(uint64(n))
}

func formatUint64(n uint64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
