package smt

import (
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/debug"
)

// DebugExporter provides interface for extracting debug info from constraint systems.
type DebugExporter interface {
	// GetDebugInfo returns the debug info entries
	GetDebugInfo() []constraint.LogEntry
	// GetSymbolTable returns the symbol table for resolving locations
	GetSymbolTable() debug.SymbolTable
	// GetMDebug returns the mapping from constraint ID to debug info ID
	GetMDebug() map[int]int
}

// SourceLocation represents a location in source code.
type SourceLocation struct {
	File     string `json:"file"`
	Function string `json:"function"`
	Line     int64  `json:"line"`
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
	// Functions is the list of all functions in the symbol table
	Functions []debug.Function
	// HasDebugInfo indicates whether debug info was available
	HasDebugInfo bool
}

// ExtractDebugInfo extracts debug information from a constraint system.
func ExtractDebugInfo(cs DebugExporter) *ExtractedDebugInfo {
	result := &ExtractedDebugInfo{
		ConstraintDebug: make(map[int]*ConstraintDebugInfo),
	}

	debugInfo := cs.GetDebugInfo()
	symbolTable := cs.GetSymbolTable()
	mDebug := cs.GetMDebug()

	result.Functions = symbolTable.Functions
	result.HasDebugInfo = len(debugInfo) > 0

	// Build constraint debug info from MDebug mapping
	for constraintID, debugID := range mDebug {
		if debugID < 0 || debugID >= len(debugInfo) {
			continue
		}

		entry := debugInfo[debugID]
		cdi := &ConstraintDebugInfo{
			ConstraintIndex: constraintID,
			Caller:          entry.Caller,
		}

		// Resolve stack locations
		for _, locID := range entry.Stack {
			if locID < 0 || locID >= len(symbolTable.Locations) {
				continue
			}
			loc := symbolTable.Locations[locID]

			var funcName, fileName string
			if loc.FunctionID >= 0 && loc.FunctionID < len(symbolTable.Functions) {
				fn := symbolTable.Functions[loc.FunctionID]
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

// GetConstraintLocation returns a human-readable location for a constraint.
func (d *ExtractedDebugInfo) GetConstraintLocation(constraintIdx int) string {
	if d == nil || d.ConstraintDebug == nil {
		return ""
	}

	cdi, ok := d.ConstraintDebug[constraintIdx]
	if !ok || len(cdi.Stack) == 0 {
		return ""
	}

	// Return the first (most relevant) stack frame
	loc := cdi.Stack[0]
	if loc.File != "" && loc.Line > 0 {
		return loc.File + ":" + formatInt64(loc.Line)
	}
	return ""
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
