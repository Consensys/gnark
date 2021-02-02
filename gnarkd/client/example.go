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
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"

	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/examples/cubic"
	"github.com/consensys/gnark/gnarkd/pb"
	"github.com/consensys/gurvy"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

//
// /!\ WARNING /!\
// NOTE: this exists for documentation purposes, do not use.
//
//

const address = "127.0.0.1:9002"

func main() {
	config := &tls.Config{
		InsecureSkipVerify: true,
	}
	// Set up a connection to the server.
	conn, err := grpc.Dial(address, grpc.WithTransportCredentials(credentials.NewTLS(config)))
	if err != nil {
		log.Fatal(err)
	}
	c := pb.NewGroth16Client(conn)

	ctx := context.Background()

	var buf bytes.Buffer
	var w cubic.Circuit
	w.X.Assign(3)
	w.Y.Assign(35)
	witness.WriteFull(&buf, &w, gurvy.BN256)

	// synchronous call
	_, _ = c.Prove(ctx, &pb.ProveRequest{
		CircuitID: "bn256/cubic",
		Witness:   buf.Bytes(),
	})

	// async call
	r, _ := c.CreateProveJob(ctx, &pb.CreateProveJobRequest{CircuitID: "bn256/cubic"})
	stream, _ := c.SubscribeToProveJob(ctx, &pb.SubscribeToProveJobRequest{JobID: r.JobID})

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
		conn, _ := net.Dial("tcp", "127.0.0.1:9001")
		defer conn.Close()

		jobID, _ := uuid.Parse(r.JobID)
		bjobID, _ := jobID.MarshalBinary()
		conn.Write(bjobID)
		conn.Write(buf.Bytes())
	}()

	<-done
}
