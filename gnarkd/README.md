# gnarkd 

`gnarkd` is a `gnark` Proving / Verifying server. 
It offers synchronous gRPC APIs (use when proving time & witness size are short) and asynchronous APIs.

See [`pb/gnardk.proto`](pb/gnardk.proto) for up to date protobuf service description.

gRPC clients can be generated for multiple languages (Go, Rust, ...) see `protoc` doc for more info. 
In go: 

```
protoc --experimental_allow_proto3_optional --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative  pb/gnarkd.proto
```

## WIP
* TLS connection
* Docker image

## Under the hood

When `gnarkd` starts, it loads the circuits defined in `circuits/` folder. Circuits must be stored in a separate folder, under a curve subfolder.
Example: 
* `circuits/bn256/cubic` will contain `cubic.pk`, `cubic.vk` and `cubic.r1cs`.
* CircuitID (as needed in the APIs) is then `bn256/cubic` 

`gnarkd` listens on 2 distinct TCP connections: one for gRPC, one for receiving large witnesses on async calls.

On this second connection, the server expects: `jobID` | `witness` . 
* `jobID` is returned by `CreateProveJob` and is a standard UUID (RFC 4122) on 16 byte (server impl uses `github.com/google/uuid`)
* `gnarkd` knows which witness size to expect (via `r1cs.GetNbPublicWires`, `r1cs.GetNbSecretWires` and `r1cs.SizeFrElement`)


## Example client (Go)

```golang
	// Set up a connection to the server.
	conn, _ := grpc.Dial(address, grpc.WithInsecure(), grpc.WithBlock())
	c := pb.NewGroth16Client(conn)

	ctx := context.Background()

	var buf bytes.Buffer
    var w cubic.Circuit
	w.X.Assign(3)
	w.Y.Assign(35)
	witness.WriteFull(&buf, &w, gurvy.BN256)

    // synchronous call 
	proveRes, _ := c.Prove(ctx, &pb.ProveRequest{
		CircuitID: "bn256/cubic",
		Witness:   buf.Bytes(),
	})

    // async call
	r, err := c.CreateProveJob(ctx, &pb.CreateProveJobRequest{CircuitID: "bn256/cubic"})
	stream, err := c.SubscribeToProveJob(ctx, &pb.SubscribeToProveJobRequest{JobID: r.JobID})

	done := make(chan struct{})
	go func() {
		for {
			resp, err := stream.Recv()
			if err == io.EOF {
				done <- struct{}{}
				return
			}
			log.Printf("new job status: %s", resp.Status.String())
		}
	}()
	go func() {
		// send witness
		conn, err := net.Dial("tcp", "127.0.0.1:9001")
		defer conn.Close()

		jobID, err := uuid.Parse(r.JobID)
		bjobID, err := jobID.MarshalBinary()
		_, err = conn.Write(bjobID)
		_, err = conn.Write(buf.Bytes())
	}()

	<-done 
```