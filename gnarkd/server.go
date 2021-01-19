// Copyright 2020 ConsenSys Software Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	context "context"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/consensys/gurvy"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/r1cs"
	"github.com/consensys/gnark/gnarkd/pb"
)

// server implements Groth16Server
type server struct {
	pb.UnimplementedGroth16Server
	circuits map[string]circuit
}

const (
	pkExt   = ".pk"
	vkExt   = ".vk"
	r1csExt = ".r1cs"
)

type circuit struct {
	pk   groth16.ProvingKey
	vk   groth16.VerifyingKey
	r1cs r1cs.R1CS
}

func newServer() (*server, error) {

	toReturn := &server{}

	if err := toReturn.loadCircuits(); err != nil {
		return nil, err
	}

	return toReturn, nil
}

// loadCircuits walk through fCircuitDir and caches proving keys, verifying keys, and R1CS
// path must be circuits/curveXX/circuitName/ and contains exactly one of each .pk, .vk and .R1CS
// TODO @gbotrel caching strategy, v1 caches everything.
func (s *server) loadCircuits() error {
	s.circuits = make(map[string]circuit)
	// ensure root dir exists
	if _, err := os.Stat(*fCircuitDir); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("directory %s doesn't exist", *fCircuitDir)
		}
		return err
	}

	curves := []gurvy.ID{gurvy.BN256, gurvy.BLS381, gurvy.BLS377, gurvy.BW761}
	for _, curve := range curves {
		curveDir := filepath.Join(*fCircuitDir, curve.String())

		subDirectories, err := ioutil.ReadDir(curveDir)
		if err != nil {
			continue
		}

		for _, f := range subDirectories {
			if !f.IsDir() {
				continue
			}

			if err := s.loadCircuit(curve, filepath.Join(curveDir, f.Name())); err != nil {
				return err
			}

		}

	}

	if len(s.circuits) == 0 {
		return fmt.Errorf("didn't find any circuits in %s", *fCircuitDir)
	}

	return nil
}

func (s *server) loadCircuit(curveID gurvy.ID, baseDir string) error {
	circuitID := fmt.Sprintf("%s/%s", curveID.String(), filepath.Base(baseDir))
	log.Debugw("walking through circuit", "ID", circuitID)
	var (
		pkPath   string
		vkPath   string
		r1csPath string
	)

	files, err := ioutil.ReadDir(baseDir)
	if err != nil {
		return err
	}

	for _, f := range files {
		if filepath.Ext(f.Name()) == pkExt {
			if pkPath != "" {
				return fmt.Errorf("%s contains multiple %s files", baseDir, pkExt)
			}
			pkPath = f.Name()
		} else if filepath.Ext(f.Name()) == vkExt {
			if vkPath != "" {
				return fmt.Errorf("%s contains multiple %s files", baseDir, vkExt)
			}
			vkPath = f.Name()
		} else if filepath.Ext(f.Name()) == r1csExt {
			if r1csPath != "" {
				return fmt.Errorf("%s contains multiple %s files", baseDir, r1csExt)
			}
			r1csPath = f.Name()
		}
	}

	if pkPath == "" && vkPath == "" && r1csPath == "" {
		log.Warnw("directory contains no circuit objects", "dir", baseDir)
		return nil
	}
	if pkPath == "" {
		return fmt.Errorf("%s contains no %s files", baseDir, pkExt)
	}
	if vkPath == "" {
		return fmt.Errorf("%s contains no %s files", baseDir, pkExt)
	}
	if r1csPath == "" {
		return fmt.Errorf("%s contains no %s files", baseDir, pkExt)
	}

	pk := groth16.NewProvingKey(curveID)
	vk := groth16.NewVerifyingKey(curveID)
	r1cs := r1cs.New(curveID)
	// load proving key
	{
		file, err := os.Open(filepath.Join(baseDir, pkPath))
		if err != nil {
			return err
		}
		_, err = pk.ReadFrom(file)
		file.Close()
		if err != nil {
			return err
		}
	}

	{
		file, err := os.Open(filepath.Join(baseDir, vkPath))
		if err != nil {
			return err
		}
		_, err = vk.ReadFrom(file)
		file.Close()
		if err != nil {
			return err
		}
	}

	{
		file, err := os.Open(filepath.Join(baseDir, r1csPath))
		if err != nil {
			return err
		}
		_, err = r1cs.ReadFrom(file)
		file.Close()
		if err != nil {
			return err
		}
	}

	s.circuits[circuitID] = circuit{
		pk, vk, r1cs,
	}

	log.Infow("successfully loaded circuit", "ID", circuitID)

	return nil
}

// Prove takes circuitID and optional witness as parameter. If optional witness is not specified
// ProveJobStatus will be in a status "awaiting for witness" which must be sent outside gRPC
// through a TCP connection. This ensure that the API can deal with large witnesses.
// For small circuits, ProveResult may contain the proof. For large circuits, must use JobStatus and
// await for async result
func (s *server) Prove(ctx context.Context, request *pb.ProveRequest) (*pb.ProveResult, error) {
	log.Debugw("Prove", "circuitID", request.CircuitID)
	if (request.Witness == nil) || (len(request.Witness) == 0) {
		log.Debug("request has no witness attached")
	}
	return nil, nil
}

// JobStatus is a bidirectional stream enabling clients to regularly poll the server to get their job status
func (s *server) JobStatus(ss pb.Groth16_JobStatusServer) error {
	log.Debugw("JobStatus")
	return errors.New("not implemented")
}
