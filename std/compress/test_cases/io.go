package test_cases

import (
	"encoding/hex"
	"io"
)

// ReadHexFile reads a hex file, ignoring all characters except hexadecimal digits.
// It is dangerously forgiving and should only be used for testing.
func ReadHexFile(in io.Reader) ([]byte, error) {
	parentheses := 0

	_in, err := io.ReadAll(in)
	if err != nil {
		return nil, err
	}

	I := 0
	for _, c := range _in {
		if c == '(' || c == '[' {
			parentheses++
		} else if c == ')' || c == ']' {
			parentheses--
		} else if parentheses == 0 {
			if c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' {
				_in[I] = c
				I++
			}
		}
	}

	return hex.DecodeString(string(_in[:I]))
}
