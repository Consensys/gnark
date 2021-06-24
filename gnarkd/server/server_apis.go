package server

import (
	"bytes"
	context "context"
	"io"
	"time"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/gnarkd/pb"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Prove takes circuitID and witness as parameter
// this is a synchronous call and bypasses the job queue
// it is meant to be used for small circuits, for larger circuits (proving time) and witnesses,
// use CreateProveJob instead
func (s *Server) Prove(ctx context.Context, request *pb.ProveRequest) (*pb.ProveResult, error) {
	s.log.Debugw("Prove", "circuitID", request.CircuitID)

	// get circuit
	circuit, ok := s.circuits[request.CircuitID]
	if !ok {
		s.log.Errorw("Prove called with unknown circuitID", "circuitID", request.CircuitID)
		return nil, status.Errorf(codes.NotFound, "unknown circuit %s", request.CircuitID)
	}

	var buf bytes.Buffer
	var pw io.WriterTo

	switch circuit.backendID {
	case backend.GROTH16:
		// call groth16.Prove with witness
		proof, err := groth16.ReadAndProve(circuit.ccs, circuit.groth16.pk, bytes.NewReader(request.Witness))
		if err != nil {
			s.log.Error(err)
			return nil, status.Errorf(codes.Internal, err.Error())
		}
		pw = proof

	case backend.PLONK:
		// call plonk.Prove with witness
		proof, err := plonk.ReadAndProve(circuit.ccs, circuit.plonk.pk, bytes.NewReader(request.Witness))
		if err != nil {
			s.log.Error(err)
			return nil, status.Errorf(codes.Internal, err.Error())
		}
		pw = proof
	default:
		panic("backend not implemented")
	}

	// serialize proof
	_, err := pw.WriteTo(&buf)
	if err != nil {
		s.log.Error(err)
		return nil, status.Errorf(codes.Internal, err.Error())
	}

	// return proof
	s.log.Infow("successfully created proof", "circuitID", request.CircuitID)
	return &pb.ProveResult{Proof: buf.Bytes()}, nil
}

// CreateProveJob enqueue a job into the job queue with WAITING_WITNESS status
func (s *Server) CreateProveJob(ctx context.Context, request *pb.CreateProveJobRequest) (*pb.CreateProveJobResponse, error) {
	// ensure circuitID is valid
	if _, ok := s.circuits[request.CircuitID]; !ok {
		s.log.Errorw("CreateProveJob called with unknown circuitID", "circuitID", request.CircuitID)
		return nil, status.Errorf(codes.NotFound, "unknown circuit %s", request.CircuitID)
	}

	ttl := defaultTTL
	if request.TTL != nil && (*request.TTL) > 0 {
		ttl = time.Duration(*request.TTL) * time.Second
	}

	// create job
	job := proveJob{
		id:         uuid.New(),
		status:     pb.ProveJobResult_WAITING_WITNESS, // default value
		expiration: time.Now().Add(ttl),
		circuitID:  request.CircuitID,
	}

	// store job, waiting for witness via TCP socket
	s.jobs.Store(job.id, &job)
	s.log.Infow("prove job created", "circuitID", request.CircuitID, "jobID", job.id, "expiration", job.expiration.String())

	// return job id
	return &pb.CreateProveJobResponse{JobID: job.id.String()}, nil
}

// CancelProveJob does what it says it does.
func (s *Server) CancelProveJob(ctx context.Context, request *pb.CancelProveJobRequest) (*pb.CancelProveJobResponse, error) {
	// ensure jobID is valid
	jobID, err := uuid.Parse(request.JobID)
	if err != nil {
		s.log.Errorw("invalid job id", "jobID", request.JobID)
		return nil, status.Errorf(codes.InvalidArgument, "invalid jobID %s", request.JobID)
	}
	_job, ok := s.jobs.Load(jobID)
	if !ok {
		s.log.Errorw("CancelProveJobRequest called with unknown jobID", "jobID", request.JobID)
		return nil, status.Errorf(codes.NotFound, "unknown job %s", request.JobID)
	}

	job := _job.(*proveJob)
	job.Lock()
	defer job.Unlock()
	if job.isFinished() {
		return &pb.CancelProveJobResponse{}, nil
	}

	if job.status == pb.ProveJobResult_RUNNING {
		s.log.Warnw("cancel job called on a running job, doing nothing", "jobID", request.JobID)
		return nil, status.Errorf(codes.OutOfRange, "job %s can't be cancelled -- already RUNNING", request.JobID)
	}

	s.log.Infow("cancelling job", "jobID", request.JobID, "previousStatus", job.status.String())
	job.err = errJobCancelled
	job.status = pb.ProveJobResult_ERRORED
	for _, ch := range job.subscribers {
		ch <- struct{}{}
	}

	return &pb.CancelProveJobResponse{}, nil
}

// ListProveJob does what it says it does
func (s *Server) ListProveJob(ctx context.Context, request *pb.ListProveJobRequest) (*pb.ListProveJobResponse, error) {
	response := &pb.ListProveJobResponse{}
	s.jobs.Range(func(k, v interface{}) bool {
		job := v.(*proveJob)
		job.RLock()
		r := &pb.ProveJobResult{JobID: job.id.String(), Status: job.status}
		if job.err != nil {
			errMsg := job.err.Error()
			r.Err = &errMsg
		}
		job.RUnlock()
		response.Jobs = append(response.Jobs, r)
		return true
	})
	return response, nil
}

// SubscribeToProveJob enables a client to get job status changes from the Server
// at connection start, Server sends current job status
// when job is done (ok or errored), Server closes connection
func (s *Server) SubscribeToProveJob(request *pb.SubscribeToProveJobRequest, stream pb.ZKSnark_SubscribeToProveJobServer) error {
	// ensure jobID is valid
	jobID, err := uuid.Parse(request.JobID)
	if err != nil {
		s.log.Errorw("invalid job id", "jobID", request.JobID)
		return status.Errorf(codes.InvalidArgument, "invalid jobID %s", request.JobID)
	}
	_job, ok := s.jobs.Load(jobID)
	if !ok {
		s.log.Errorw("SubscribeToProveJob called with unknown jobID", "jobID", request.JobID)
		return status.Errorf(codes.NotFound, "unknown job %s", request.JobID)
	}

	// check job status
	job := _job.(*proveJob)
	chJobUpdate := make(chan struct{}, 2)
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
			s.log.Errorw("couldn't send response of finished job", "jobID", request.JobID, "err", err)
			return status.Errorf(codes.Internal, "couldn't send response of finished job")
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

	s.log.Debugw("waiting for updates on job", "jobID", request.JobID)

	// wait for job update or connection being terminated
	for {
		select {
		case <-s.ctx.Done():
			s.log.Warnw("server stopping, closing client connection", "jobID", request.JobID)
			return grpc.ErrServerStopped
		case <-stream.Context().Done():
			s.log.Warnw("connection terminated", "jobID", request.JobID)
			return status.Error(codes.Canceled, "connection terminated")
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
			s.log.Infow("sending job status update", "jobID", request.JobID, "status", result.Status.String())
			if err := stream.Send(result); err != nil {
				s.log.Errorw("couldn't send response of finished job", "jobID", request.JobID, "err", err)
				return status.Errorf(codes.Internal, "couldn't send response of finished job")
			}

			// we are done
			if jobFinished || !ok {
				s.log.Infow("closing job stream channel", "jobID", request.JobID, "status", result.Status.String())
				return nil
			}
		}
	}
}

// Verify takes circuitID, proof and public witness as parameter
// this is a synchronous call
func (s *Server) Verify(ctx context.Context, request *pb.VerifyRequest) (*pb.VerifyResult, error) {
	s.log.Debugw("Verify", "circuitID", request.CircuitID)

	// get circuit
	circuit, ok := s.circuits[request.CircuitID]
	if !ok {
		s.log.Errorw("Verify called with unknown circuitID", "circuitID", request.CircuitID)
		return nil, status.Errorf(codes.NotFound, "unknown circuit %s", request.CircuitID)
	}

	if circuit.backendID == backend.GROTH16 {
		// call groth16.Verify with witness
		proof := groth16.NewProof(circuit.ccs.CurveID())
		if _, err := proof.ReadFrom(bytes.NewReader(request.Proof)); err != nil {
			s.log.Error(err)
			return nil, status.Errorf(codes.InvalidArgument, err.Error())
		}
		err := groth16.ReadAndVerify(proof, circuit.groth16.vk, bytes.NewReader(request.PublicWitness))
		if err != nil {
			s.log.Error(err)
			return nil, status.Errorf(codes.InvalidArgument, err.Error())
		}
	} else if circuit.backendID == backend.PLONK {
		// call plonk.Verify with witness
		proof := plonk.NewProof(circuit.ccs.CurveID())
		if _, err := proof.ReadFrom(bytes.NewReader(request.Proof)); err != nil {
			s.log.Error(err)
			return nil, status.Errorf(codes.InvalidArgument, err.Error())
		}
		err := plonk.ReadAndVerify(proof, circuit.plonk.pk.VerifyingKey().(plonk.VerifyingKey), bytes.NewReader(request.PublicWitness))
		if err != nil {
			s.log.Error(err)
			return nil, status.Errorf(codes.InvalidArgument, err.Error())
		}
	}

	// return proof
	s.log.Infow("successfully verified proof", "circuitID", request.CircuitID)
	return &pb.VerifyResult{Ok: true}, nil
}
