package merkle

import "errors"

var (
	ErrArity = errors.New("inconsistant arity")
	ErrIndex = errors.New("index too high")
)
