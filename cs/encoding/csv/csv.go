/*
Copyright © 2020 ConsenSys

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package csv

import (
	"bufio"
	"encoding/csv"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/consensys/gnark/cs"
)

const (
	privateLabel = string(cs.Secret)
	publicLabel  = string(cs.Public)
)

var (
	ErrInvalidInputFormat = errors.New("incorrect input format")
)

// Read parse cs.Assigments from given file
// file line structure: secret/public, assignmentName, assignmentValue
// note this is a cs/ subpackage because we need to instantiate internal/curve.Element
func Read(filePath string) (map[string]cs.Assignment, error) {
	csvFile, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer csvFile.Close()
	reader := csv.NewReader(bufio.NewReader(csvFile))
	toReturn := cs.NewAssignment()
	for {
		line, err := reader.Read()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		} else if len(line) != 3 {
			return nil, ErrInvalidInputFormat
		}
		visibility := strings.ToLower(strings.TrimSpace(line[0]))
		name := strings.TrimSpace(line[1])
		value := strings.TrimSpace(line[2])

		toReturn.Assign(cs.Visibility(visibility), name, value)
	}
	//toReturn.Assign(cs.Public, cs.OneWire, 1)
	return toReturn, nil
}

// Write serialize given assigment to disk
// file line structure: secret/public, assignmentName, assignmentValue
func Write(assignment map[string]cs.Assignment, path string) error {
	csvFile, err := os.Create(path)
	if err != nil {
		return err
	}
	defer csvFile.Close()
	writer := csv.NewWriter(csvFile)
	for k, v := range assignment {
		r := v.Value
		record := []string{privateLabel, k, r.String()}
		if v.IsPublic {
			record[0] = publicLabel
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}
	writer.Flush()
	return nil
}
