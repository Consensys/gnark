package gkr

import "github.com/consensys/gnark/constraint"

type BlueprintSolve interface {
	constraint.Blueprint
	SetNbInstances(nbInstances uint32)
}

// Blueprints holds all GKR-related blueprint IDs and references
type Blueprints struct {
	SolveID         constraint.BlueprintID
	Solve           BlueprintSolve
	ProveID         constraint.BlueprintID
	GetAssignmentID constraint.BlueprintID
}
