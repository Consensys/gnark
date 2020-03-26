package backend

import "errors"

// OneWire is the assignment label / name used for the constant wire one
const OneWire = "ONE_WIRE"

// Visibility type alias on string to define circuit input's visibility
type Visibility string

// Possible Visibility attributes for circuit inputs
const (
	Secret Visibility = "secret"
	Public Visibility = "public"
)

var (
	ErrDuplicateTag          = errors.New("duplicate tag")
	ErrInputNotSet           = errors.New("input not set")
	ErrInputVisiblity        = errors.New("input has incorrect visibility (secret / public)")
	ErrUnsatisfiedConstraint = errors.New("constraint is not satisfied")
	ErrInvalidInputFormat    = errors.New("incorrect input format")
)
