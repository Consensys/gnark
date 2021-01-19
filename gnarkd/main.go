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
	"fmt"
	"net"
	"os"

	"github.com/consensys/gnark/gnarkd/pb"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

const (
	port = ":50051"
)

// -------------------------------------------------------------------------------------------------
// logger
var (
	logger *zap.Logger
	log    *zap.SugaredLogger
)

// -------------------------------------------------------------------------------------------------
// init logger
func init() {
	var err error
	logger, err = zap.NewDevelopment()
	if err != nil {
		fmt.Println("unable to create logger")
		os.Exit(1)
	}
	log = logger.Sugar()
}

//go:generate protoc --experimental_allow_proto3_optional --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative  pb/gnarkd.proto
func main() {
	log.Info("starting gnarkd")
	defer log.Warn("stopping gnarkd")
	defer logger.Sync() // flushes buffer, if any

	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalw("failed to listen tcp", "err", err)
	}
	s := grpc.NewServer()
	pb.RegisterGroth16Server(s, &server{})
	if err := s.Serve(lis); err != nil {
		log.Fatalw("failed to start server", "err", err)
	}
}
