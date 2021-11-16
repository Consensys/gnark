package frontend

import (
	"fmt"
)

// Tag contains informations needed to measure and display statistics of a delimited piece of circuit
type Tag struct {
	Name     string
	vID, cID int
}

// Counter contains measurements of useful statistics between two Tag
type Counter struct {
	From, To      Tag
	NbVariables   int
	NbConstraints int
}

func (c Counter) String() string {
	return fmt.Sprintf("%s to %s: %d variables, %d constraints", c.From.Name, c.To.Name, c.NbVariables, c.NbConstraints)
}
