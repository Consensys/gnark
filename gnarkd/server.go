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
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	"github.com/consensys/gurvy"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/r1cs"
	"github.com/consensys/gnark/gnarkd/pb"
)

// TODO @gbotrel add io.LimitReader with expect witness size in circuit struct in TCP protocol

const defaultTTL = time.Hour * 3 // default TTL for keeping jobs in server.jobs

// server implements Groth16Server
type server struct {
	pb.UnimplementedGroth16Server
	circuits map[string]circuit // not thread safe as it is loaded once only
	jobs     sync.Map           // key == uuid[string], value == proveJob
}

func newServer() (*server, error) {
	s := &server{}
	if err := s.loadCircuits(); err != nil {
		return nil, err
	}
	return s, nil
}

// Prove takes circuitID and witness as parameter
// this is a synchronous call and bypasses the job queue
// it is meant to be used for small circuits, for larger circuits (proving time) and witnesses,
// use CreateProveJob instead
func (s *server) Prove(ctx context.Context, request *pb.ProveRequest) (*pb.ProveResult, error) {
	log.Debugw("Prove", "circuitID", request.CircuitID)

	// get circuit
	circuit, ok := s.circuits[request.CircuitID]
	if !ok {
		log.Errorw("Prove called with unknown circuitID", "circuitID", request.CircuitID)
		return nil, grpc.Errorf(codes.NotFound, "unknown circuit %s", request.CircuitID)
	}

	// call groth16.Prove with witness
	proof, err := groth16.DeserializeAndProve(circuit.r1cs, circuit.pk, request.Witness)
	if err != nil {
		log.Error(err)
		return nil, grpc.Errorf(codes.Internal, err.Error())
	}

	// serialize proof
	var buf bytes.Buffer
	_, err = proof.WriteTo(&buf)
	if err != nil {
		log.Error(err)
		return nil, grpc.Errorf(codes.Internal, err.Error())
	}

	// return proof
	log.Infow("successfully created proof", "circuitID", request.CircuitID)
	return &pb.ProveResult{Proof: buf.Bytes()}, nil
}

// CreateProveJob enqueue a job into the job queue with WAITING_WITNESS status
func (s *server) CreateProveJob(ctx context.Context, request *pb.CreateProveJobRequest) (*pb.CreateProveJobResponse, error) {
	// ensure circuitID is valid
	if _, ok := s.circuits[request.CircuitID]; !ok {
		log.Errorw("CreateProveJob called with unknown circuitID", "circuitID", request.CircuitID)
		return nil, grpc.Errorf(codes.NotFound, "unknown circuit %s", request.CircuitID)
	}

	// create job
	job := proveJob{
		id:         jobID(uuid.New().String()),
		status:     pb.ProveJobResult_WAITING_WITNESS, // default value
		expiration: time.Now().Add(defaultTTL),
	}

	// store job, waiting for witness via TCP socket
	s.jobs.Store(job.id, &job)
	log.Infow("prove job created", "circuitID", request.CircuitID, "jobID", job.id)

	// TODO @gbotrel remove this, temporary, trigger job status change .
	go func() {

		<-time.After(time.Second * 2)
		job.Lock()
		job.status = pb.ProveJobResult_QUEUED
		// job.Unlock()
		// job.RLock()
		for _, ch := range job.subscribers {
			ch <- struct{}{}
		}
		job.Unlock()
		<-time.After(time.Second * 2)
		job.Lock()
		job.status = pb.ProveJobResult_COMPLETED
		// job.Unlock()
		// job.RLock()
		for _, ch := range job.subscribers {
			ch <- struct{}{}
		}
		job.Unlock()
	}()

	// return job id
	return &pb.CreateProveJobResponse{JobID: string(job.id)}, nil
}

// SubscribeToProveJob enables a client to get job status changes from the server
// at connection start, server sends current job status
// when job is done (ok or errored), server closes connection
func (s *server) SubscribeToProveJob(request *pb.SubscribeToProveJobRequest, stream pb.Groth16_SubscribeToProveJobServer) error {
	// ensure jobID is valid
	_job, ok := s.jobs.Load(jobID(request.JobID))
	if !ok {
		log.Errorw("SubscribeToProveJob called with unknown jobID", "jobID", request.JobID)
		return grpc.Errorf(codes.NotFound, "unknown job %s", request.JobID)
	}

	// check job status
	job := _job.(*proveJob)
	chJobUpdate := make(chan struct{}, 1)
	job.Lock()
	jobFinished := job.isFinished()
	if !jobFinished {
		// subscribe to updates
		job.subscribe(chJobUpdate) // must be called under lock
	}
	job.Unlock()

	// job is done we don't need to subscribe and just send the result, close the conn.
	if jobFinished {
		close(chJobUpdate)
		result := &pb.ProveJobResult{JobID: request.JobID, Status: job.status, Proof: job.proof}
		if job.err != nil {
			errMsg := job.err.Error()
			result.Err = &errMsg
		}
		if err := stream.Send(result); err != nil {
			log.Errorw("couldn't send response of finished job", "jobID", request.JobID, "err", err)
			return grpc.Errorf(codes.Internal, "couldn't send response of finished job")
		}
		return nil
	}

	// ensure we clean up after ourselves
	defer func() {
		job.Lock()
		job.unsubscribe(chJobUpdate)
		close(chJobUpdate)
		job.Unlock()
	}()

	log.Debugw("waiting for updates on job", "jobID", request.JobID)

	// wait for job update or connection being terminated
	for {
		select {
		case <-stream.Context().Done():
			log.Warnw("connection terminated", "jobID", request.JobID)
			return grpc.ErrClientConnClosing
		case _, ok := <-chJobUpdate:
			// job status updated.
			job.RLock()
			result := &pb.ProveJobResult{JobID: request.JobID, Status: job.status, Proof: job.proof}
			if job.err != nil {
				errMsg := job.err.Error()
				result.Err = &errMsg
			}
			jobFinished := job.isFinished()
			job.RUnlock()

			// send job status on stream.
			log.Infow("sending job status update", "jobID", request.JobID, "status", job.status.String())
			if err := stream.Send(result); err != nil {
				log.Errorw("couldn't send response of finished job", "jobID", request.JobID, "err", err)
				return grpc.Errorf(codes.Internal, "couldn't send response of finished job")
			}

			// we are done
			if jobFinished {
				return nil
			}
			if !ok {
				// channel was closed
				// TODO @gbotrel check under which circonstances this happens.
				return nil
			}
		}
	}
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
	log.Debugw("looking for circuit in", "dir", circuitID)

	// list files in dir
	files, err := ioutil.ReadDir(baseDir)
	if err != nil {
		return err
	}

	// empty circuit with nil values
	var circuit circuit

	for _, f := range files {
		if f.IsDir() {
			continue
		}
		switch filepath.Ext(f.Name()) {
		case pkExt:
			if circuit.pk != nil {
				return fmt.Errorf("%s contains multiple %s files", baseDir, pkExt)
			}
			circuit.pk = groth16.NewProvingKey(curveID)
			if err := loadGnarkObject(circuit.pk, filepath.Join(baseDir, f.Name())); err != nil {
				return err
			}
		case vkExt:
			if circuit.vk != nil {
				return fmt.Errorf("%s contains multiple %s files", baseDir, pkExt)
			}
			circuit.vk = groth16.NewVerifyingKey(curveID)
			if err := loadGnarkObject(circuit.vk, filepath.Join(baseDir, f.Name())); err != nil {
				return err
			}
		case r1csExt:
			if circuit.r1cs != nil {
				return fmt.Errorf("%s contains multiple %s files", baseDir, pkExt)
			}
			circuit.r1cs = r1cs.New(curveID)
			if err := loadGnarkObject(circuit.r1cs, filepath.Join(baseDir, f.Name())); err != nil {
				return err
			}
		}
	}

	// ensure our circuit is full.
	if circuit.pk == nil {
		return fmt.Errorf("%s contains no %s files", baseDir, pkExt)
	}
	if circuit.vk == nil {
		return fmt.Errorf("%s contains no %s files", baseDir, vkExt)
	}
	if circuit.r1cs == nil {
		return fmt.Errorf("%s contains no %s files", baseDir, r1csExt)
	}

	s.circuits[circuitID] = circuit

	log.Infow("successfully loaded circuit", "circuitID", circuitID)

	return nil
}

func loadGnarkObject(o io.ReaderFrom, filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	_, err = o.ReadFrom(file)
	file.Close()
	return err
}
