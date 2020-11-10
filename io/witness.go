package io

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"strings"

	"github.com/consensys/gnark/backend"
)

// TODO this is deprecated, we might need a type Witness = map[string]interface{}

// WriteWitness serialize variable map[name]value into writer
//
// map[string]interface{} --> interface must be convertible to big.Int
// using backend.FromInterface()
//
// the resulting format is human readable (JSON)
//
// big.Int are serialized in hexadecimal strings
func WriteWitness(writer io.Writer, from map[string]interface{}) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "    ")

	toWrite := make(map[string]string)
	for k, v := range from {
		b := backend.FromInterface(v)
		toWrite[k] = "0x" + hex.EncodeToString(b.Bytes())
	}

	// encode our object
	if err := encoder.Encode(toWrite); err != nil {
		return err
	}

	return nil
}

// ReadWitness read and deserialize JSON file from reader
//
// returned object will contain map[string]interface{}
//
// keys being variable names and interface{} being big.Int
//
// big.Int values in files can be in base10 or base16 strings
func ReadWitness(reader io.Reader, into map[string]interface{}) error {
	decoder := json.NewDecoder(reader)

	toRead := make(map[string]string)

	if err := decoder.Decode(&toRead); err != nil {
		return err
	}

	for k, v := range toRead {
		if strings.HasPrefix(v, "0x") {
			bytes, err := hex.DecodeString(v[2:])
			if err != nil {
				return err
			}
			b := new(big.Int).SetBytes(bytes)
			into[k] = *b
		} else {
			// decimal user input
			b, ok := new(big.Int).SetString(v, 10)
			if !ok {
				return errors.New("could read base10 input " + v)
			}
			into[k] = *b
		}

	}

	return nil
}
