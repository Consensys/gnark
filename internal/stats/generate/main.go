package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"sync"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/internal/stats"
)

var (
	fSave   = flag.Bool("s", false, "save new stats in file ")
	fFilter = flag.String("run", "", "filter runs with regexp; example 'pairing*'")
)

func main() {
	flag.Parse()

	var r *regexp.Regexp
	if *fFilter != "" {
		r = regexp.MustCompile(*fFilter)
	}

	s := stats.NewGlobalStats()

	// load reference objects
	// for each circuit, on each curve, on each backend
	// compare with reference stats
	snippets := stats.GetSnippets()
	var wg sync.WaitGroup
	for name, c := range snippets {
		if r != nil && !r.MatchString(name) {
			continue
		}
		wg.Add(1)
		go func(name string, circuit stats.Circuit) {
			defer wg.Done()
			for _, curve := range circuit.Curves {
				for _, backendID := range backend.Implemented() {
					cs, err := stats.NewSnippetStats(curve, backendID, circuit.Circuit)
					if err != nil {
						log.Fatalf("building stats for circuit %s %v", name, err)
					}
					s.Add(curve, backendID, cs, name)
				}
			}
		}(name, c)
	}
	wg.Wait()

	// write csv to buffer
	var buf bytes.Buffer
	if _, err := s.WriteTo(&buf); err != nil {
		log.Fatal(err)
	}

	// print csv
	fmt.Println(buf.String())

	if *fSave {
		const refPath = "../latest_stats.csv"
		// write buffer to file

		if err := os.WriteFile(refPath, buf.Bytes(), 0600); err != nil {
			log.Fatal(err)
		}

		log.Println("successfully saved new reference stats file", refPath)
	}

}
