package server

import (
	"bytes"
	context "context"
	"time"

	"github.com/consensys/gnark/backend/groth16"
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

	// call groth16.Prove with witness
	proof, err := groth16.DeserializeAndProve(circuit.r1cs, circuit.pk, request.Witness)
	if err != nil {
		s.log.Error(err)
		return nil, status.Errorf(codes.Internal, err.Error())
	}

	// serialize proof
	var buf bytes.Buffer
	_, err = proof.WriteTo(&buf)
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

	// create job
	job := proveJob{
		id:         uuid.New(),
		status:     pb.ProveJobResult_WAITING_WITNESS, // default value
		expiration: time.Now().Add(defaultTTL),
		circuitID:  request.CircuitID,
	}

	// store job, waiting for witness via TCP socket
	s.jobs.Store(job.id, &job)
	s.log.Infow("prove job created", "circuitID", request.CircuitID, "jobID", job.id)

	// return job id
	return &pb.CreateProveJobResponse{JobID: job.id.String()}, nil
}

// SubscribeToProveJob enables a client to get job status changes from the Server
// at connection start, Server sends current job status
// when job is done (ok or errored), Server closes connection
func (s *Server) SubscribeToProveJob(request *pb.SubscribeToProveJobRequest, stream pb.Groth16_SubscribeToProveJobServer) error {
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

	// call groth16.Verify with witness
	proof := groth16.NewProof(circuit.r1cs.GetCurveID())
	if _, err := proof.ReadFrom(bytes.NewReader(request.Proof)); err != nil {
		s.log.Error(err)
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}
	err := groth16.DeserializeAndVerify(proof, circuit.vk, request.PublicWitness)
	if err != nil {
		s.log.Error(err)
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}

	// return proof
	s.log.Infow("successfully verified proof", "circuitID", request.CircuitID)
	return &pb.VerifyResult{Ok: true}, nil
}
