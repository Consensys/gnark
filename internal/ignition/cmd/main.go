package main

import (
	"log"
	"os"

	"github.com/consensys/gnark/internal/ignition"
)

func main() {

	// Example usage of the ignition package
	config := ignition.Config{
		BaseURL:  "https://aztec-ignition.s3.amazonaws.com/",
		Ceremony: "TINY_TEST_7",
		CacheDir: "./data",
	}
	if config.CacheDir != "" {
		os.MkdirAll(config.CacheDir, os.ModePerm)
	}

	// 1. fetch manifest
	log.Println("fetch manifest")
	manifest, err := ignition.NewManifest(config)
	if err != nil {
		log.Fatal("when fetching manifest: ", err)
	}

	// sanity check
	if len(manifest.Participants) <= 1 {
		log.Fatal("not enough participants")
	}

	// 2. we read two contributions at a time, and check that the second one follows the first one
	current, next := ignition.NewContribution(manifest.NumG1Points), ignition.NewContribution(manifest.NumG1Points)

	log.Println("processing contributions 1 and 2")
	if err := current.Get(manifest.Participants[0], config); err != nil {
		log.Fatal("when fetching contribution 1: ", err)
	}
	if err := next.Get(manifest.Participants[1], config); err != nil {
		log.Fatal("when fetching contribution 2: ", err)
	}
	if !next.Follows(&current) {
		log.Fatal("contribution 2 does not follow contribution 1: ", err)
	}
	for i := 2; i < len(manifest.Participants); i++ {
		log.Println("processing contribution ", i+1)
		current, next = next, current
		if err := next.Get(manifest.Participants[i], config); err != nil {
			log.Fatal("when fetching contribution ", i+1, ": ", err)
		}
		if !next.Follows(&current) {
			log.Fatal("contribution ", i+1, " does not follow contribution ", i, ": ", err)
		}
	}

	log.Println("success ✅: all contributions are valid")
}
