package server

import (
	"bytes"
	context "context"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/examples/cubic"
	"github.com/consensys/gnark/gnarkd/pb"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

const bufSize = 1024 * 1024

var (
	grpcListener    *bufconn.Listener
	witnessListener *bufconn.Listener
	cancelServer    context.CancelFunc
	gnarkdServer    *Server
)

// -------------------------------------------------------------------------------------------------
// logger
var (
	logger *zap.Logger
	log    *zap.SugaredLogger
)

func init() {
	var err error
	logger, err = zap.NewDevelopment()
	if err != nil {
		fmt.Println("unable to create logger")
		os.Exit(1)
	}
	log = logger.Sugar()
}

func setupServer() {
	grpcListener = bufconn.Listen(bufSize)
	witnessListener = bufconn.Listen(bufSize)
	s := grpc.NewServer()

	var serverCtx context.Context
	var err error
	serverCtx, cancelServer = context.WithCancel(context.Background())
	gnarkdServer, err = NewServer(serverCtx, log, "../circuits")
	if err != nil {
		log.Fatalw("couldn't init gnarkd", "err", err)
	}

	// start witness listener
	go gnarkdServer.StartWitnessListener(witnessListener)
	pb.RegisterZKSnarkServer(s, gnarkdServer)

	go func() {
		if err := s.Serve(grpcListener); err != nil {
			log.Fatalw("Server exited with error", "err", err)
		}
	}()
}

func shutdownServer() {
	grpcListener.Close()
	witnessListener.Close()
	cancelServer()
	cancelServer = nil
	grpcListener = nil
	witnessListener = nil
	gnarkdServer = nil
}

func TestMain(m *testing.M) {
	setupServer()
	code := m.Run()
	shutdownServer()
	os.Exit(code)
}

func TestProveSync(t *testing.T) {
	t.Parallel()
	assert := require.New(t)

	// create grpc client connection
	ctx := context.Background()
	conn, err := grpc.DialContext(ctx, "", grpc.WithContextDialer(
		func(c context.Context, s string) (net.Conn, error) {
			return grpcListener.Dial()
		}), grpc.WithInsecure())

	assert.NoError(err)
	defer conn.Close()

	c := pb.NewZKSnarkClient(conn)

	// 1. serialize a valid witness
	var (
		w        cubic.Circuit
		bWitness bytes.Buffer
	)
	w.X.Assign(3)
	w.Y.Assign(35)

	for circuitID, circuit := range gnarkdServer.circuits {
		t.Log("running test with", circuitID)

		bWitness.Reset()
		_, err = witness.WriteFullTo(&bWitness, circuit.curveID, &w)
		assert.NoError(err)

		// 2. call prove
		proveResult, err := c.Prove(ctx, &pb.ProveRequest{
			CircuitID: circuitID,
			Witness:   bWitness.Bytes(),
		})
		assert.NoError(err, "grpc sync prove failed")

		// 3. ensure returned proof is valid.
		if circuit.backendID == backend.GROTH16 {
			proof := groth16.NewProof(circuit.curveID)
			_, err = proof.ReadFrom(bytes.NewReader(proveResult.Proof))
			assert.NoError(err, "deserializing grpc proof response failed")

			err = groth16.Verify(proof, circuit.groth16.vk, &w)
			assert.NoError(err, "couldn't verify proof returned from grpc server")
		} else if circuit.backendID == backend.PLONK {
			proof := plonk.NewProof(circuit.curveID)
			_, err = proof.ReadFrom(bytes.NewReader(proveResult.Proof))
			assert.NoError(err, "deserializing grpc proof response failed")

			err = plonk.Verify(proof, circuit.plonk.pk.VerifyingKey().(plonk.VerifyingKey), &w)
			assert.NoError(err, "couldn't verify proof returned from grpc server")
		}

		// 4. create invalid proof
		var wBad cubic.Circuit
		wBad.X.Assign(4)
		wBad.Y.Assign(42)
		bWitness.Reset()

		_, err = witness.WriteFullTo(&bWitness, circuit.curveID, &wBad)
		assert.NoError(err)

		_, err = c.Prove(ctx, &pb.ProveRequest{
			CircuitID: circuitID,
			Witness:   bWitness.Bytes(),
		})
		assert.Error(err, "grpc sync false prove failed")

	}

}

func TestProveAsync(t *testing.T) {
	t.Parallel()
	assert := require.New(t)

	// create grpc client connection
	ctx := context.Background()
	conn, err := grpc.DialContext(ctx, "", grpc.WithContextDialer(
		func(c context.Context, s string) (net.Conn, error) {
			return grpcListener.Dial()
		}), grpc.WithInsecure())

	assert.NoError(err)
	defer conn.Close()

	client := pb.NewZKSnarkClient(conn)

	// 1. serialize a valid witness
	var (
		w        cubic.Circuit
		bWitness bytes.Buffer
	)
	w.X.Assign(3)
	w.Y.Assign(35)

	for circuitID, circuit := range gnarkdServer.circuits {
		t.Log("running test with", circuitID)

		bWitness.Reset()
		_, err = witness.WriteFullTo(&bWitness, circuit.curveID, &w)
		assert.NoError(err)

		// 2. call prove
		r, err := client.CreateProveJob(ctx, &pb.CreateProveJobRequest{
			CircuitID: circuitID,
		})
		assert.NoError(err, "grpc sync create prove failed")

		// 3. subscribe to status changes
		stream, err := client.SubscribeToProveJob(ctx, &pb.SubscribeToProveJobRequest{JobID: r.JobID})
		assert.NoError(err, "couldn't subscribe to job")

		done := make(chan struct{})
		var lastStatus pb.ProveJobResult_Status
		var rproof []byte
		go func() {
			for {
				resp, err := stream.Recv()
				if err == io.EOF {
					done <- struct{}{}
					return
				}
				lastStatus = resp.Status
				if lastStatus == pb.ProveJobResult_COMPLETED {
					rproof = resp.Proof
				}
			}
		}()

		// 4. send wtness on the wire
		wc, err := witnessListener.Dial()
		assert.NoError(err, "dialing witness socket")
		defer wc.Close()
		jobID, err := uuid.Parse(r.JobID)
		assert.NoError(err)
		bjobID, err := jobID.MarshalBinary()
		assert.NoError(err)
		_, err = wc.Write(bjobID)
		assert.NoError(err)
		_, err = wc.Write(bWitness.Bytes())
		assert.NoError(err)

		<-done
		assert.Equal(lastStatus, pb.ProveJobResult_COMPLETED)

		// 3. ensure returned proof is valid.
		if circuit.backendID == backend.GROTH16 {
			proof := groth16.NewProof(circuit.curveID)
			_, err = proof.ReadFrom(bytes.NewReader(rproof))
			assert.NoError(err, "deserializing grpc proof response failed")

			err = groth16.Verify(proof, circuit.groth16.vk, &w)
			assert.NoError(err, "couldn't verify proof returned from grpc server")
		} else if circuit.backendID == backend.PLONK {
			proof := plonk.NewProof(circuit.curveID)
			_, err = proof.ReadFrom(bytes.NewReader(rproof))
			assert.NoError(err, "deserializing grpc proof response failed")

			err = plonk.Verify(proof, circuit.plonk.pk.VerifyingKey().(plonk.VerifyingKey), &w)
			assert.NoError(err, "couldn't verify proof returned from grpc server")
		}

	}
}

func TestJobTTL(t *testing.T) {
	t.Parallel()
	assert := require.New(t)

	// create grpc client connection
	ctx := context.Background()
	conn, err := grpc.DialContext(ctx, "", grpc.WithContextDialer(
		func(c context.Context, s string) (net.Conn, error) {
			return grpcListener.Dial()
		}), grpc.WithInsecure())

	assert.NoError(err)
	defer conn.Close()

	client := pb.NewZKSnarkClient(conn)

	// 1. serialize a valid witness
	var (
		w        cubic.Circuit
		bWitness bytes.Buffer
	)
	w.X.Assign(3)
	w.Y.Assign(35)

	for circuitID, circuit := range gnarkdServer.circuits {
		t.Log("running test with", circuitID)
		bWitness.Reset()
		_, err = witness.WriteFullTo(&bWitness, circuit.curveID, &w)
		assert.NoError(err)

		// 2. call prove
		ttl := int64(1) // mark job as expired after 1 second
		r, err := client.CreateProveJob(ctx, &pb.CreateProveJobRequest{
			CircuitID: circuitID,
			TTL:       &ttl,
		})
		assert.NoError(err, "grpc sync create prove failed")

		// 3. subscribe to status changes
		stream, err := client.SubscribeToProveJob(ctx, &pb.SubscribeToProveJobRequest{JobID: r.JobID})
		assert.NoError(err, "couldn't subscribe to job")

		done := make(chan struct{}, 1)
		var lastStatus pb.ProveJobResult_Status
		var errMsg string
		go func() {
			for {
				resp, err := stream.Recv()
				if err == io.EOF {
					done <- struct{}{}
					return
				}
				lastStatus = resp.Status
				if lastStatus == pb.ProveJobResult_ERRORED {
					errMsg = (*resp.Err)
				}
			}
		}()

		// 4. send wtness on the wire
		<-time.After(1030 * time.Millisecond) // wait for TTL to expire
		wc, err := witnessListener.Dial()
		assert.NoError(err, "dialing witness socket")
		defer wc.Close()
		jobID, err := uuid.Parse(r.JobID)
		assert.NoError(err)
		bjobID, err := jobID.MarshalBinary()
		assert.NoError(err)
		_, err = wc.Write(bjobID)
		assert.NoError(err)
		_, err = wc.Write(bWitness.Bytes())
		assert.NoError(err)
		<-done
		assert.Equal(lastStatus, pb.ProveJobResult_ERRORED)
		assert.Equal(errMsg, errJobExpired.Error())
	}
}

func TestCancelAndListJob(t *testing.T) {
	const circuitID = "groth16/bn254/cubic"
	t.Parallel()
	assert := require.New(t)

	// create grpc client connection
	ctx := context.Background()
	conn, err := grpc.DialContext(ctx, "", grpc.WithContextDialer(
		func(c context.Context, s string) (net.Conn, error) {
			return grpcListener.Dial()
		}), grpc.WithInsecure())

	assert.NoError(err)
	defer conn.Close()

	client := pb.NewZKSnarkClient(conn)

	// 2. call prove
	r, err := client.CreateProveJob(ctx, &pb.CreateProveJobRequest{
		CircuitID: circuitID,
	})
	assert.NoError(err, "grpc sync create prove failed")

	// 3. subscribe to status changes
	stream, err := client.SubscribeToProveJob(ctx, &pb.SubscribeToProveJobRequest{JobID: r.JobID})
	assert.NoError(err, "couldn't subscribe to job")

	done := make(chan struct{}, 1)
	var lastStatus pb.ProveJobResult_Status
	var errMsg string
	go func() {
		for {
			resp, err := stream.Recv()
			if err == io.EOF {
				done <- struct{}{}
				return
			}
			lastStatus = resp.Status
			if lastStatus == pb.ProveJobResult_ERRORED {
				errMsg = (*resp.Err)
			}
		}
	}()

	<-time.After(92 * time.Millisecond) // give some time to SubscribeToProveJob to start
	_, err = client.CancelProveJob(ctx, &pb.CancelProveJobRequest{
		JobID: r.JobID,
	})
	assert.NoError(err)
	<-done
	assert.Equal(lastStatus, pb.ProveJobResult_ERRORED)
	assert.Equal(errMsg, errJobCancelled.Error())

	// send another job
	r2, err := client.CreateProveJob(ctx, &pb.CreateProveJobRequest{
		CircuitID: circuitID,
	})
	assert.NoError(err, "grpc sync create prove failed")

	list, err := client.ListProveJob(ctx, &pb.ListProveJobRequest{})
	assert.NoError(err)
	assert.GreaterOrEqual(len(list.Jobs), 2)

	foundR := false
	foundR2 := false
	for _, j := range list.Jobs {
		if j.JobID == r.JobID {
			foundR = true
		}
		if j.JobID == r2.JobID {
			foundR2 = true
		}
	}

	assert.True(foundR)
	assert.True(foundR2)
}

func TestVerifySync(t *testing.T) {
	t.Parallel()
	assert := require.New(t)

	// create grpc client connection
	ctx := context.Background()
	conn, err := grpc.DialContext(ctx, "", grpc.WithContextDialer(
		func(c context.Context, s string) (net.Conn, error) {
			return grpcListener.Dial()
		}), grpc.WithInsecure())

	assert.NoError(err)
	defer conn.Close()

	client := pb.NewZKSnarkClient(conn)

	// 1. serialize a valid witness
	var (
		w        cubic.Circuit
		bWitness bytes.Buffer
	)
	w.X.Assign(3)
	w.Y.Assign(35)
	for circuitID, circuit := range gnarkdServer.circuits {
		t.Log("running test with", circuitID)
		bWitness.Reset()

		_, err = witness.WriteFullTo(&bWitness, circuit.curveID, &w)
		assert.NoError(err)

		proof, err := client.Prove(ctx, &pb.ProveRequest{
			CircuitID: circuitID,
			Witness:   bWitness.Bytes(),
		})
		assert.NoError(err)
		bWitness.Reset()
		_, err = witness.WritePublicTo(&bWitness, circuit.curveID, &w)
		assert.NoError(err)

		// 2. call verify
		vResult, err := client.Verify(ctx, &pb.VerifyRequest{
			CircuitID:     circuitID,
			PublicWitness: bWitness.Bytes(),
			Proof:         proof.Proof,
		})
		assert.NoError(err, "grpc sync verify failed")
		assert.True(vResult.Ok)
	}
}
