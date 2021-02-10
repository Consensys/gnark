// Package frontend contains the object and logic to define and compile gnark circuits
package frontend

import "errors"

// ErrInputNotSet triggered when trying to access a variable that was not allocated
var ErrInputNotSet = errors.New("variable is not allocated")
