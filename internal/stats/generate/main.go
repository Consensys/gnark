package main

import (
	"flag"
	"fmt"
	"log"
	"regexp"
	"sync"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/internal/stats"
)

var (
	fSave    = flag.Bool("s", false, "save new stats in file ")
	fVerbose = flag.Bool("v", false, "verbose")
	fFilter  = flag.String("run", "", "filter runs with regexp; example 'pairing*'")
)

func main() {
	flag.Parse()
	if !*fSave && !*fVerbose {
		log.Fatal("no flag defined (-s or -v)")
	}

	var r *regexp.Regexp
	if *fFilter != "" {
		r = regexp.MustCompile(*fFilter)
	}

	s := stats.NewGlobalStats()

	// load reference objects
	// for each circuit, on each curve, on each backend
	// compare with reference stats
	var wg sync.WaitGroup
	for name, c := range stats.Snippets {
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

	if *fVerbose {
		fmt.Println("id,curve,backend,nbConstraints,nbWires")
		for name, c := range stats.Snippets {
			if r != nil && !r.MatchString(name) {
				continue
			}
			ss := s.Stats[name]
			for _, curve := range c.Curves {
				for _, backendID := range backend.Implemented() {
					cs := ss[backendID][curve]
					fmt.Printf("%s,%s,%s,%d,%d\n", name, curve, backendID, cs.NbConstraints, cs.NbInternalWires)
				}
			}
		}
	}

	if *fSave {
		const refPath = "../latest.stats"
		if err := s.Save(refPath); err != nil {
			log.Fatal(err)
		}
		log.Println("successfully saved new reference stats file", refPath)
	}

}
