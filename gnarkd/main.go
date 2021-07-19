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

// Package gnarkd provides experimental gRPC endpoints to create and verify proofs with gnark.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/consensys/gnark/gnarkd/pb"
	"github.com/consensys/gnark/gnarkd/server"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// -------------------------------------------------------------------------------------------------
// flags
var (
	fCircuitDir  = flag.String("circuit_dir", "circuits", "circuits root directory")
	fCertFile    = flag.String("cert_file", "certs/gnarkd.crt", "TLS cert file")
	fKeyFile     = flag.String("key_file", "certs/gnarkd.key", "TLS key file")
	fgRPCPort    = flag.Int("grpc_port", 9002, "gRPC server port")
	fWitnessPort = flag.Int("witness_port", 9001, "witness tcp socket port")
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
	logger, err = newZapConfig().Build()
	if err != nil {
		fmt.Println("unable to create logger")
		os.Exit(1)
	}
	log = logger.Sugar()
}

// TODO @gbotrel ensure CircleCI builds do that.
// protoc --experimental_allow_proto3_optional --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative  pb/gnarkd.proto
func main() {
	log.Info("starting gnarkd")
	defer log.Warn("stopping gnarkd")
	defer logger.Sync() // flushes buffer, if any

	// catch sigterm and sigint.
	chDone := make(chan os.Signal)
	signal.Notify(chDone, syscall.SIGTERM, syscall.SIGINT)

	// Parse flags
	flag.Parse()

	// init the server and load the ciruits
	serverCtx, cancelServer := context.WithCancel(context.Background())
	defer cancelServer()
	gnarkdServer, err := server.NewServer(serverCtx, log, *fCircuitDir)
	if err != nil {
		log.Fatalw("couldn't init gnarkd", "err", err)
	}

	// gnarkd listens on 2 sockets: 1 for the gRPC APIs, and 1 to receive (async) witnesses

	// ---------------------------------------------------------------------------------------------
	// WITNESS LISTENER
	wLis, err := tls.Listen("tcp", fmt.Sprintf(":%d", *fWitnessPort), getTLSConfig())
	if err != nil {
		log.Fatalw("failed to listen tcp", "err", err)
	}
	go gnarkdServer.StartWitnessListener(wLis)

	// ---------------------------------------------------------------------------------------------
	// gRPC endpoint
	grpcLis, err := net.Listen("tcp", fmt.Sprintf(":%d", *fgRPCPort))
	if err != nil {
		log.Fatalw("failed to listen tcp", "err", err)
	}
	creds, err := credentials.NewServerTLSFromFile(*fCertFile, *fKeyFile)
	if err != nil {
		log.Fatalw("failed to setup TLS", "err", err)
	}
	s := grpc.NewServer(grpc.Creds(creds))
	pb.RegisterZKSnarkServer(s, gnarkdServer)

	go func() {
		defer signal.Stop(chDone)
		<-chDone

		// clean up  if SIGINT or SIGTERM is caught.
		cancelServer()
		s.GracefulStop()
		wLis.Close()
	}()

	if err := s.Serve(grpcLis); err != nil {
		log.Fatalw("failed to start server", "err", err)
	}
}

func getTLSConfig() *tls.Config {
	crt, err := ioutil.ReadFile(*fCertFile)
	if err != nil {
		log.Fatal(err)
	}
	key, err := ioutil.ReadFile(*fKeyFile)
	if err != nil {
		log.Fatal(err)
	}

	cer, err := tls.X509KeyPair(crt, key)
	if err != nil {
		log.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cer}}

}

func newZapConfig() zap.Config {
	return zap.Config{
		Level:       zap.NewAtomicLevelAt(zap.DebugLevel),
		Development: false,
		Sampling: &zap.SamplingConfig{
			Initial:    100,
			Thereafter: 100,
		},
		DisableCaller:     true,
		DisableStacktrace: true,
		Encoding:          "console",
		EncoderConfig:     zap.NewDevelopmentEncoderConfig(),
		OutputPaths:       []string{"stderr"},
		ErrorOutputPaths:  []string{"stderr"},
	}
}
