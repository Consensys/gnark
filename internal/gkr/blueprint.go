package gkr

import "github.com/consensys/gnark/constraint"

type BlueprintSolve interface {
	constraint.Blueprint
	SetNbInstances(nbInstances int)
}
