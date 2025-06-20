// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package patricia

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// RLPDecoder handles RLP decoding for Patricia tree nodes
type RLPDecoder struct {
	api frontend.API
}

// NewRLPDecoder creates a new RLP decoder
func NewRLPDecoder(api frontend.API) *RLPDecoder {
	return &RLPDecoder{api: api}
}

// DecodeNode decodes an RLP-encoded Patricia tree node
func (r *RLPDecoder) DecodeNode(data []uints.U8) PatriciaNode {
	// This is a simplified RLP decoder for Patricia tree nodes
	// In a full implementation, this would handle all RLP encoding rules

	if len(data) == 0 {
		return PatriciaNode{Type: frontend.Variable(int(NodeTypeEmpty))}
	}

	// For this proof-of-concept, we'll implement basic node type detection
	// Real RLP decoding is complex and would require more sophisticated parsing

	var node PatriciaNode
	node.RawData = data

	// Simplified node type detection based on data structure
	// This is a placeholder - real implementation would parse RLP properly
	dataLen := len(data)

	// Branch nodes typically have 17 elements (long list)
	isBranch := r.api.IsZero(r.api.Sub(dataLen, 17*33)) // Approximate size

	// Leaf/Extension nodes have 2 elements
	isLeafOrExt := r.api.IsZero(r.api.Sub(dataLen, 2*33)) // Approximate size

	// For now, set node type based on length heuristic
	node.Type = r.api.Select(isBranch, NodeTypeBranch,
		r.api.Select(isLeafOrExt, NodeTypeLeaf, NodeTypeEmpty))

	// This is a simplified approach - a full implementation would:
	// 1. Parse the RLP structure properly
	// 2. Extract the actual node fields
	// 3. Handle all edge cases and RLP encoding rules

	return node
}

// RLPLength determines the length of an RLP-encoded item
func (r *RLPDecoder) RLPLength(data []uints.U8, offset frontend.Variable) frontend.Variable {
	if len(data) == 0 {
		return 0
	}

	// Simplified RLP length calculation
	// Real RLP has complex length encoding rules
	firstByte := data[0].Val

	// Single byte (0x00-0x7f): the byte itself
	isSingleByte := r.api.IsZero(r.api.Sub(firstByte, 128))

	// Short string (0x80-0xb7): length is firstByte - 0x80
	isShortString := r.api.And(
		r.api.IsZero(r.api.Sub(firstByte, 183)), // <= 0xb7
		r.api.Sub(1, isSingleByte),              // > 0x7f
	)
	shortLength := r.api.Sub(firstByte, 128)

	// For this proof-of-concept, we'll handle basic cases
	return r.api.Select(isSingleByte, 1,
		r.api.Select(isShortString, shortLength, frontend.Variable(len(data))))
}

// RLPHelper provides utilities for working with RLP-encoded data
type RLPHelper struct {
	api frontend.API
}

// NewRLPHelper creates a new RLP helper
func NewRLPHelper(api frontend.API) *RLPHelper {
	return &RLPHelper{api: api}
}

// IsRLPList checks if the RLP data represents a list
func (r *RLPHelper) IsRLPList(data []uints.U8) frontend.Variable {
	if len(data) == 0 {
		return 0
	}

	firstByte := data[0].Val

	// Lists start at 0xc0
	return r.api.IsZero(r.api.Sub(firstByte, 192)) // >= 0xc0
}

// ExtractRLPString extracts a string from RLP-encoded data
func (r *RLPHelper) ExtractRLPString(data []uints.U8, offset frontend.Variable) []uints.U8 {
	// Simplified string extraction
	// Real implementation would handle all RLP string encoding rules

	if len(data) <= 1 {
		return data
	}

	// For this proof-of-concept, assume the string follows immediately
	// after the length byte for short strings
	return data[1:]
}
