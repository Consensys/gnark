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

	"github.com/consensys/gnark/gnarkd/pb"
)

// server implements Groth16Server
type server struct {
	pb.UnimplementedGroth16Server
}

// Prove takes circuitID and optional witness as parameter. If optional witness is not specified
// ProveJobStatus will be in a status "awaiting for witness" which must be sent outside gRPC
// through a TCP connection. This ensure that the API can deal with large witnesses.
// For small circuits, ProveResult may contain the proof. For large circuits, must use JobStatus and
// await for async result
func (s *server) Prove(ctx context.Context, request *pb.ProveRequest) (*pb.ProveResult, error) {
	log.Debugw("Prove",
		"circuitID", request.CircuitID,
	)
	return nil, nil
}

// JobStatus is a bidirectional stream enabling clients to regularly poll the server to get their job status
func (s *server) JobStatus(ss pb.Groth16_JobStatusServer) error {
	log.Debugw("JobStatus")
	return errors.New("not implemented")
}
