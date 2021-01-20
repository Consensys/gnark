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
	"bytes"
	context "context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

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

// Prove takes circuitID and witness as parameter
// this is a synchronous call and bypasses the job queue
// it is meant to be used for small circuits, for larger circuits (proving time) and witnesses,
// use CreateProveJob instead
func (s *server) Prove(ctx context.Context, request *pb.ProveRequest) (*pb.ProveResult, error) {
	log.Debugw("Prove", "circuitID", request.CircuitID)
	circuit, ok := s.circuits[request.CircuitID]
	if !ok {
		log.Errorw("Prove called with unknown circuitID", "ID", request.CircuitID)
		return nil, grpc.Errorf(codes.NotFound, "unknown circuit %s", request.CircuitID)
	}

	proof, err := groth16.DeserializeAndProve(circuit.r1cs, circuit.pk, request.Witness)
	if err != nil {
		log.Error(err)
		return nil, grpc.Errorf(codes.Internal, err.Error())
	}

	var buf bytes.Buffer
	_, err = proof.WriteTo(&buf)
	if err != nil {
		log.Error(err)
		return nil, grpc.Errorf(codes.Internal, err.Error())
	}
	log.Infow("successfully created proof", "circuitID", request.CircuitID)
	return &pb.ProveResult{Proof: buf.Bytes()}, nil
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
