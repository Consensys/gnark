package main

import (
	"sync"
	"time"

	"github.com/consensys/gnark/gnarkd/pb"
)

type jobID string
type proveJob struct {
	sync.RWMutex
	id         jobID
	status     pb.ProveJobResult_Status
	expiration time.Time // TODO @gbotrel add a go routine that periodically wake up and clean up completed tasks
	witness    []byte    // TODO @gbotrel set to nil when executor is done parsing.
	err        error
	proof      []byte

	subscribers []chan struct{}
}

// must be called under lock
func (job *proveJob) subscribe(ch chan struct{}) {
	job.subscribers = append(job.subscribers, ch)
}

// must be called under lock
func (job *proveJob) unsubscribe(ch chan struct{}) {
	for i := 0; i < len(job.subscribers); i++ {
		if job.subscribers[i] == ch {
			job.subscribers[i] = job.subscribers[len(job.subscribers)-1]
			job.subscribers = job.subscribers[:len(job.subscribers)-1]
			return
		}
	}
	log.Warn("unsubscribe from job couldn't find matching channel")
	return
}

// must be called under lock
func (job *proveJob) isFinished() bool {
	return (job.status == pb.ProveJobResult_COMPLETED) || (job.status == pb.ProveJobResult_ERRORED)
}
