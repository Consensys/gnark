package main

import (
	"fmt"
	"html/template"
	"os"
	"os/exec"
	"strings"

	templates "github.com/consensys/gnark/internal/generators/backend/template"
)

//go:generate go run main.go
func main() {
	v, err := exec.Command("git", "describe", "--abbrev=0").CombinedOutput()
	if err != nil {
		panic(err)
	}
	version := strings.TrimSpace(string(v))
	src := []string{
		templates.Header,
		Version,
	}

	generateCode("../../../cmd/version.go", src, struct{ Version string }{version})
}

const Version = `
{{ template "header" . }}

package cmd

const Version = "{{.Version}}"
`

// TODO from goff, need factorizing all this code generation business
func generateCode(output string, templates []string, tData struct{ Version string }) error {
	// create output file
	file, err := os.Create(output)
	if err != nil {
		return err
	}
	fmt.Printf("generating %-70s\n", output)

	// parse templates
	tmpl := template.Must(template.New("").
		// Funcs(helpers()).
		Parse(aggregate(templates)))

	// execute template
	if err = tmpl.Execute(file, tData); err != nil {
		file.Close()
		return err
	}
	file.Close()

	// run goformat to prettify output source
	if err := exec.Command("gofmt", "-s", "-w", output).Run(); err != nil {
		return err
	}
	return nil
}

func aggregate(values []string) string {
	var sb strings.Builder
	for _, v := range values {
		sb.WriteString(v)
	}
	return sb.String()
}
