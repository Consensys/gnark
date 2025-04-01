package gkr

import (
	"path/filepath"

	"github.com/consensys/bavard"
)

type Config struct {
	GenerateTests           bool
	RetainTestCaseRawInfo   bool
	CanUseFFT               bool
	OutsideGkrPackage       bool
	TestVectorsRelativePath string
}

func Generate(config Config, baseDir string, bgen *bavard.BatchGenerator) error {
	entries := []bavard.Entry{
		{File: filepath.Join(baseDir, "gkr.go"), Templates: []string{"gkr.go.tmpl"}},
		{File: filepath.Join(baseDir, "registry.go"), Templates: []string{"registry.go.tmpl"}},
	}

	if config.GenerateTests {
		entries = append(entries,
			bavard.Entry{File: filepath.Join(baseDir, "gkr_test.go"), Templates: []string{"gkr.test.go.tmpl", "gkr.test.vectors.go.tmpl"}})
	}

	return bgen.Generate(config, "gkr", "./gkr/template/", entries...)
}
