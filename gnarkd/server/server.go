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

// Package server implements a gRPC server following protobuf description of the proof service in gnarkd/pb.
package server

import (
	"bytes"
	context "context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/kzg"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/gnarkd/pb"
)

const (
	gcTicker     = time.Minute * 2 // gc running periodically
	defaultTTL   = time.Hour * 3   // default TTL for keeping jobs in Server.jobs
	jobQueueSize = 10
)

var (
	errJobExpired   = errors.New("job expired")
	errJobCancelled = errors.New("job cancelled")
)

// Server implements Groth16Server
type Server struct {
	pb.UnimplementedZKSnarkServer
	circuits   map[string]circuit // not thread safe as it is loaded once only
	jobs       sync.Map           // key == uuid[string], value == proveJob
	chJobQueue chan jobID
	log        *zap.SugaredLogger
	circuitDir string
	ctx        context.Context
}

// NewServer returns a server implementing the service as defined in pb/gnarkd.proto
func NewServer(ctx context.Context, log *zap.SugaredLogger, circuitDir string) (*Server, error) {
	if log == nil {
		return nil, errors.New("please provide a logger")
	}
	s := &Server{
		ctx:        ctx,
		log:        log,
		circuitDir: circuitDir,
	}
	if err := s.loadCircuits(); err != nil {
		return nil, err
	}
	s.chJobQueue = make(chan jobID, jobQueueSize)
	go s.startWorker(ctx)
	go s.startGC(ctx)
	return s, nil
}

// StartWitnessListener listen on given socket for incoming connection
// and read and try to interpret stream of bytes as a circuit witness
func (s *Server) StartWitnessListener(l net.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			s.log.Fatalw("couldn't accept connection on witness tcp socket", "err", err)
		}
		go s.receiveWitness(c)
	}
}

// GC periodically walk through the jobs to remove them from the cache if TTL is expired.
func (s *Server) startGC(ctx context.Context) {
	gcTicker := time.NewTicker(gcTicker)
	for {
		select {
		case <-ctx.Done():
			gcTicker.Stop()
			s.log.Info("stopping GC (context is Done())")
			return
		case <-gcTicker.C:
			s.log.Debug("running GC")
			s.jobs.Range(func(k, v interface{}) bool {
				job := v.(*proveJob)
				if s.isExpired(job) {
					s.log.Infow("job TTL expired", "jobID", job.id.String())
					s.jobs.Delete(job.id)
				}
				return true
			})
		}
	}
}

// worker executes groth16 prove async calls (listens to s.chJobQueue)
func (s *Server) startWorker(ctx context.Context) {
	s.log.Info("starting worker")
	var buf bytes.Buffer
	for {
		select {
		case <-ctx.Done():
			s.log.Info("stopping worker (context is Done())")
			return
		case jobID, ok := <-s.chJobQueue:
			if !ok {
				s.log.Info("stopping worker (s.chJobQueue is closed)")
				return
			}
			s.log.Infow("executing job", "jobID", jobID)

			_job, ok := s.jobs.Load(jobID)
			if !ok {
				s.log.Errorw("inconsistant Server state: received a job in the job queue, that's not in the job sync.Map", "jobID", jobID)
				continue
			}
			job := _job.(*proveJob)

			if s.isExpired(job) {
				s.log.Warnw("job TTL expired", "jobID", job.id.String())
				continue
			}

			s.updateJobStatusOrDie(job, pb.ProveJobResult_RUNNING)

			// note that job.witness and job.prove can only be accessed by this go routine at this point
			circuit, ok := s.circuits[job.circuitID]
			if !ok {
				s.log.Fatalw("inconsistant Server state: couldn't find circuit pointed by job", "jobID", jobID.String(), "circuitID", job.circuitID)
			}

			// run prove
			var proof io.WriterTo
			var err error
			if circuit.backendID == backend.GROTH16 {
				proof, err = groth16.ReadAndProve(circuit.ccs, circuit.groth16.pk, bytes.NewReader(job.witness))
			} else if circuit.backendID == backend.PLONK {
				proof, err = plonk.ReadAndProve(circuit.ccs, circuit.plonk.pk, bytes.NewReader(job.witness))
			}

			job.witness = nil // set witness to nil
			if err != nil {
				s.log.Errorw("proving job failed", "jobID", jobID.String(), "circuitID", job.circuitID, "err", err)
				job.err = err
				s.updateJobStatusOrDie(job, pb.ProveJobResult_ERRORED)
				continue
			}

			// serialize proof
			buf.Reset()
			_, err = proof.WriteTo(&buf)
			if err != nil {
				s.log.Errorw("couldn't serialize proof", "err", err)
				job.err = err
				s.updateJobStatusOrDie(job, pb.ProveJobResult_ERRORED)
				continue
			}

			s.log.Infow("successfully computed proof", "jobID", job.id)
			job.proof = buf.Bytes()
			s.updateJobStatusOrDie(job, pb.ProveJobResult_COMPLETED)
		}
	}
}

func (s *Server) isExpired(job *proveJob) bool {
	job.Lock()
	defer job.Unlock()

	if job.expiration.Before(time.Now()) {
		job.status = pb.ProveJobResult_ERRORED
		job.err = errJobExpired
		for _, ch := range job.subscribers {
			ch <- struct{}{}
		}
		return true
	}
	return false
}

func (s *Server) updateJobStatusOrDie(job *proveJob, status pb.ProveJobResult_Status) {
	if err := job.setStatus(status); err != nil {
		s.log.Fatalw("when updating job status", "err", err, "jobID", job.id.String())
	}
}

func (s *Server) receiveWitness(c net.Conn) {
	s.log.Infow("receiving a witness", "remoteAddr", c.RemoteAddr().String())

	// success handler
	success := func() {
		if _, err := c.Write([]byte("ok")); err != nil {
			s.log.Errorw("when responding OK on witness socket", "err", err)
		}
		if err := c.Close(); err != nil {
			s.log.Errorw("when closing", "err", err)
		}
	}

	// fail handler
	fail := func(err error) {
		s.log.Errorw("receive witness failed", "err", err)
		if _, err := c.Write([]byte("nok")); err != nil {
			s.log.Errorw("when responding NOK on witness socket", "err", err)
		}
		if err := c.Close(); err != nil {
			s.log.Errorw("when closing", "err", err)
		}
	}

	// read jobID
	var bufJobID [jobIDSize]byte
	if _, err := io.ReadFull(c, bufJobID[:]); err != nil {
		fail(err)
		return
	}

	// parse jobid
	var jobID uuid.UUID
	if err := jobID.UnmarshalBinary(bufJobID[:]); err != nil {
		fail(err)
		return
	}

	// find job
	_job, ok := s.jobs.Load(jobID)
	if !ok {
		fail(fmt.Errorf("unknown jobID %s", jobID.String()))
		return
	}

	// check job status
	job := _job.(*proveJob)
	job.Lock()
	if job.status != pb.ProveJobResult_WAITING_WITNESS {
		job.Unlock()
		fail(fmt.Errorf("job is not waiting for witness, jobID %s", jobID.String()))
		return
	}

	// /!\  keeping the lock on the job while we get the witness /!\

	circuit, ok := s.circuits[job.circuitID]
	if !ok {
		s.log.Fatalw("inconsistant Server state: couldn't find circuit pointed by job", "jobID", jobID.String(), "circuitID", job.circuitID)
	}

	wBuf := make([]byte, circuit.fullWitnessSize)
	if _, err := io.ReadFull(c, wBuf); err != nil {
		job.Unlock()
		fail(err)
		return
	}
	job.witness = wBuf
	job.Unlock()
	s.updateJobStatusOrDie(job, pb.ProveJobResult_QUEUED)
	s.chJobQueue <- jobID // queue the job

	success()
}

// loadCircuits walk through s.circuitDir and caches proving keys, verifying keys, and CCS
// path must be circuits/provingScheme/curveID/circuitName/ and contains circuit .ccs file and precomputed data (pk, vk or .data files)
// TODO @gbotrel caching strategy, v1 caches everything.
func (s *Server) loadCircuits() error {
	s.circuits = make(map[string]circuit)
	// ensure root dir exists
	if _, err := os.Stat(s.circuitDir); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("directory %s doesn't exist", s.circuitDir)
		}
		return err
	}

	for _, b := range backend.Implemented() {
		backendDir := filepath.Join(s.circuitDir, b.String())
		for _, curve := range ecc.Implemented() {
			curveDir := filepath.Join(backendDir, curve.String())

			subDirectories, err := ioutil.ReadDir(curveDir)
			if err != nil {
				continue
			}

			for _, f := range subDirectories {
				if !f.IsDir() {
					continue
				}

				if err := s.loadCircuit(b, curve, filepath.Join(curveDir, f.Name())); err != nil {
					return err
				}
			}

		}

	}

	if len(s.circuits) == 0 {
		return fmt.Errorf("didn't find any circuits in %s", s.circuitDir)
	}

	return nil
}

func (s *Server) loadCircuit(backendID backend.ID, curveID ecc.ID, baseDir string) error {
	circuitID := fmt.Sprintf("%s/%s/%s", backendID.String(), curveID.String(), filepath.Base(baseDir))
	s.log.Debugw("looking for circuit in", "dir", circuitID)

	// list files in dir
	files, err := ioutil.ReadDir(baseDir)
	if err != nil {
		return err
	}

	// empty circuit with nil values
	circuit := circuit{
		backendID: backendID,
		curveID:   curveID,
	}

	for _, f := range files {
		if f.IsDir() {
			continue
		}
		if backendID == backend.GROTH16 {
			switch filepath.Ext(f.Name()) {
			case pkExt:
				if circuit.groth16.pk != nil {
					return fmt.Errorf("%s contains multiple %s files", baseDir, pkExt)
				}
				circuit.groth16.pk = groth16.NewProvingKey(curveID)
				if err := loadGnarkObject(circuit.groth16.pk, filepath.Join(baseDir, f.Name())); err != nil {
					return err
				}
			case vkExt:
				if circuit.groth16.vk != nil {
					return fmt.Errorf("%s contains multiple %s files", baseDir, pkExt)
				}
				circuit.groth16.vk = groth16.NewVerifyingKey(curveID)
				if err := loadGnarkObject(circuit.groth16.vk, filepath.Join(baseDir, f.Name())); err != nil {
					return err
				}
			case circuitExt:
				if circuit.ccs != nil {
					return fmt.Errorf("%s contains multiple %s files", baseDir, pkExt)
				}
				circuit.ccs = groth16.NewCS(curveID)
				if err := loadGnarkObject(circuit.ccs, filepath.Join(baseDir, f.Name())); err != nil {
					return err
				}
			}
		} else if backendID == backend.PLONK {
			switch filepath.Ext(f.Name()) {
			case pkExt:
				if circuit.plonk.pk != nil {
					return fmt.Errorf("%s contains multiple %s files", baseDir, pkExt)
				}
				circuit.plonk.pk = plonk.NewProvingKey(curveID)
				if err := loadGnarkObject(circuit.plonk.pk, filepath.Join(baseDir, f.Name())); err != nil {
					return err
				}
			case circuitExt:
				if circuit.ccs != nil {
					return fmt.Errorf("%s contains multiple %s files", baseDir, pkExt)
				}
				circuit.ccs = plonk.NewCS(curveID)
				if err := loadGnarkObject(circuit.ccs, filepath.Join(baseDir, f.Name())); err != nil {
					return err
				}
			case kzgExt:
				if circuit.plonk.kzgSRS != nil {
					return fmt.Errorf("%s contains multiple %s files", baseDir, pkExt)
				}
				circuit.plonk.kzgSRS = kzg.NewSRS(curveID)
				if err := loadGnarkObject(circuit.plonk.kzgSRS, filepath.Join(baseDir, f.Name())); err != nil {
					return err
				}
			}
		}
	}

	// ensure our circuit is full.
	if circuit.ccs == nil {
		return fmt.Errorf("%s contains no %s files", baseDir, circuitExt)
	}
	if backendID == backend.GROTH16 {
		if circuit.groth16.pk == nil {
			return fmt.Errorf("%s contains no %s files", baseDir, pkExt)
		}
		if circuit.groth16.vk == nil {
			return fmt.Errorf("%s contains no %s files", baseDir, vkExt)
		}
	} else if backendID == backend.PLONK {
		if circuit.plonk.pk == nil {
			return fmt.Errorf("%s contains no %s files", baseDir, pkExt)
		}
		if circuit.plonk.kzgSRS == nil {
			return fmt.Errorf("%s contains no %s files", baseDir, kzgExt)
		}
		if err := circuit.plonk.pk.InitKZG(circuit.plonk.kzgSRS); err != nil {
			return fmt.Errorf("calling pk.InitKZG using %s %s", baseDir, kzgExt)
		}
	}

	_, nbSecretVariables, nbPublicVariables := circuit.ccs.GetNbVariables()
	if circuit.backendID == backend.GROTH16 {
		circuit.fullWitnessSize = 4 + int(nbPublicVariables+nbSecretVariables-1)*circuit.ccs.FrSize()
		circuit.publicWitnessSize = 4 + int(nbPublicVariables-1)*circuit.ccs.FrSize()
	} else if circuit.backendID == backend.PLONK {
		circuit.fullWitnessSize = 4 + int(nbPublicVariables+nbSecretVariables)*circuit.ccs.FrSize()
		circuit.publicWitnessSize = 4 + int(nbPublicVariables)*circuit.ccs.FrSize()
	}

	s.circuits[circuitID] = circuit

	s.log.Infow("successfully loaded circuit", "circuitID", circuitID)

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
