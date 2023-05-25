// Package ignition is a package that provides helper functions to download, parse
// and validate the AZTEC Ignition Ceremony data.
// The specs are described here:
//
//	https://github.com/AztecProtocol/ignition-verification/blob/c333ec4775045139f86732abfbbd65728404ab7f/Transcript_spec.md
//
// The verification logic follows
//
//	https://github.com/AztecProtocol/ignition-verification
package ignition

import (
	"net/url"
	"path/filepath"
)

// Config specify from where to download the data and where to store it
type Config struct {
	BaseURL  string // "https://aztec-ignition.s3.amazonaws.com/"
	Ceremony string // TINY_TEST_7
	CacheDir string // if empty, files are not cached. Otherwise, they are stored in this directory
}

func (c *Config) ceremonyURL() string {
	r, err := url.JoinPath(c.BaseURL, c.Ceremony)
	if err != nil {
		panic("invalid configuration")
	}
	return r
}

func (c *Config) cache() string {
	return filepath.Join(c.CacheDir, c.Ceremony)
}
