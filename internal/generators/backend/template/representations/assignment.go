package representations

const Assignment = `
{{ template "header" . }}

package backend

import (
	"bufio"
	"encoding/csv"
	"io"
	"os"
	"strings"

	{{ template "import_curve" . }}
	{{if ne .Curve "GENERIC"}}
   	"github.com/consensys/gnark/backend"
	{{end}}
)


// Assignment is used to specify inputs to the Prove and Verify functions
type Assignment struct {
	Value    fr.Element
	IsPublic bool // default == false (assignemnt is private)
}

// Assignments is used to specify inputs to the Prove and Verify functions
type Assignments map[string]Assignment

// NewAssignment returns an empty Assigments object
func NewAssignment() Assignments {
	return make(Assignments)
}

// Assign assign a value to a Secret/Public input identified by its name
func (a Assignments) Assign(visibility {{if ne .Curve "GENERIC"}} backend.{{- end}}Visibility, name string, v interface{}) {
	if _, ok := a[name]; ok {
		panic(name + " already assigned")
	}
	switch visibility {
	case {{if ne .Curve "GENERIC"}} backend.{{- end}}Secret:
		a[name] = Assignment{Value: fr.FromInterface(v)}
	case {{if ne .Curve "GENERIC"}} backend.{{- end}}Public:
		a[name] = Assignment{
			Value:    fr.FromInterface(v),
			IsPublic: true,
		}
	default:
		panic("supported visibility attributes are SECRET and PUBLIC")
	}
}

// Read parse r1cs.Assigments from given file
// file line structure: secret/public, assignmentName, assignmentValue
// note this is a cs/ subpackage because we need to instantiate internal/fr.Element
func (assigment Assignments) Read(filePath string) error {
	csvFile, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer csvFile.Close()
	reader := csv.NewReader(bufio.NewReader(csvFile))
	for {
		line, err := reader.Read()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		} else if len(line) != 3 {
			return {{if ne .Curve "GENERIC"}} backend.{{- end}}ErrInvalidInputFormat
		}
		visibility := strings.ToLower(strings.TrimSpace(line[0]))
		name := strings.TrimSpace(line[1])
		value := strings.TrimSpace(line[2])

		assigment.Assign({{if ne .Curve "GENERIC"}} backend.{{- end}}Visibility(visibility), name, value)
	}
	return nil
}

// Write serialize given assigment to disk
// file line structure: secret/public, assignmentName, assignmentValue
func (assignment Assignments) Write(path string) error {
	csvFile, err := os.Create(path)
	if err != nil {
		return err
	}
	defer csvFile.Close()
	writer := csv.NewWriter(csvFile)
	for k, v := range assignment {
		r := v.Value
		record := []string{string({{if ne .Curve "GENERIC"}} backend.{{- end}}Secret), k, r.String()}
		if v.IsPublic {
			record[0] = string({{if ne .Curve "GENERIC"}} backend.{{- end}}Public)
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}
	writer.Flush()
	return nil
}

// DiscardSecrets returns a copy of self without Secret Assigment
func (assignments Assignments) DiscardSecrets() Assignments {
	toReturn := NewAssignment()
	for k, v := range assignments {
		if v.IsPublic {
			toReturn[k] = v
		}
	}
	return toReturn
}

`
