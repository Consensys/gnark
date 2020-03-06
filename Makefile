# to bump version, git tag -a vX.X.X -m "version description" && git push origin --tags + modify following line
VERSION=v0.1.0-alpha
BUILD=`git rev-parse HEAD`
BUILD_TIME=`date +%FT%T`

LDFLAGS=-ldflags "-s -w -X github.com/consensys/gnark/cmd.Version=${VERSION} -X github.com/consensys/gnark/cmd.Build=${BUILD} -X github.com/consensys/gnark/cmd.BuildTime=${BUILD_TIME}"
#GCFLAGS=-gcflags "-l" # inline level of agressivness by compiler
BLS381=-tags bls381
BLS377=-tags bls377
BN256=-tags bn256
DISPATCHER=-tags dispatcher
GOPATH=$(shell go env GOPATH)

build:
	go vet ${BLS381} -v && go build ${BLS381} ${LDFLAGS} ${GCFLAGS} -o gnark_bls381 && mv gnark_bls381 ${GOPATH}/bin/
	go vet ${BLS377} -v && go build ${BLS377} ${LDFLAGS} ${GCFLAGS} -o gnark_bls377 && mv gnark_bls377 ${GOPATH}/bin/
	go vet ${BN256} -v && go build ${BN256} ${LDFLAGS} ${GCFLAGS} -o gnark_bn256 && mv gnark_bn256 ${GOPATH}/bin/
	go vet ${DISPATCHER} -v && go install ${DISPATCHER} ${LDFLAGS} ${GCFLAGS}