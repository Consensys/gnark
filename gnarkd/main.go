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
	"context"
	"crypto/tls"
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

// TODO @gbotrel add TLS on the sockets

const (
	witnessPort = ":9001"
	grpcPort    = ":9002"
	circuitDir  = "circuits"
	certDir     = "certs"
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
	// flag.Parse()

	// init the server and load the ciruits
	serverCtx, cancelServer := context.WithCancel(context.Background())
	defer cancelServer()
	gnarkdServer, err := server.NewServer(serverCtx, log, circuitDir)
	if err != nil {
		log.Fatalw("couldn't init gnarkd", "err", err)
	}

	// get tls certificates
	config := getTLSConfig()

	wLis, err := tls.Listen("tcp", witnessPort, config)
	if err != nil {
		log.Fatalw("failed to listen tcp", "err", err)
	}

	// start witness listener
	go gnarkdServer.StartWitnessListener(wLis)

	// start gRPC service
	grpcLis, err := net.Listen("tcp", grpcPort)
	if err != nil {
		log.Fatalw("failed to listen tcp", "err", err)
	}
	creds, err := credentials.NewServerTLSFromFile("certs/gnarkd.crt", "certs/gnarkd.key")
	if err != nil {
		log.Fatalw("failed to setup TLS", "err", err)
	}
	s := grpc.NewServer(grpc.Creds(creds))
	pb.RegisterGroth16Server(s, gnarkdServer)

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
	crt, err := ioutil.ReadFile("certs/gnarkd.crt")
	if err != nil {
		log.Fatal(err)
	}
	key, err := ioutil.ReadFile("certs/gnarkd.key")
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
