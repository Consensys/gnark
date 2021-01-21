package main

import (
	"sync"
	"time"

	"github.com/consensys/gnark/gnarkd/pb"
	"github.com/google/uuid"
)

const jobIDSize = 16

type jobID = uuid.UUID
type proveJob struct {
	sync.RWMutex

	id          jobID
	circuitID   string
	status      pb.ProveJobResult_Status
	expiration  time.Time // TODO @gbotrel add a go routine that periodically wake up and clean up completed tasks
	witness     []byte    // TODO @gbotrel set to nil when executor is done parsing.
	err         error
	proof       []byte
	subscribers []chan struct{}
}

// will call RLock
func (job *proveJob) setStatus(status pb.ProveJobResult_Status) {

	job.Lock()
	// ensure state machine transitions are valid.
	switch status {
	case pb.ProveJobResult_QUEUED:
		if job.status != pb.ProveJobResult_WAITING_WITNESS {
			log.Fatal("setting invalid status on a job", "jobID", job.id, "newStatus", status.String(), "currentStatus", job.status.String())
		}
	case pb.ProveJobResult_RUNNING:
		if job.status != pb.ProveJobResult_QUEUED {
			log.Fatal("setting invalid status on a job", "jobID", job.id, "newStatus", status.String(), "currentStatus", job.status.String())
		}
	case pb.ProveJobResult_ERRORED, pb.ProveJobResult_COMPLETED:
		if job.status != pb.ProveJobResult_RUNNING {
			log.Fatal("setting invalid status on a job", "jobID", job.id, "newStatus", status.String(), "currentStatus", job.status.String())
		}
	default:
		log.Fatal("setting invalid status on a job", "jobID", job.id, "newStatus", status.String(), "currentStatus", job.status.String())
	}
	log.Infow("job status change", "jobID", job.id, "newStatus", status.String(), "oldStatus", job.status.String())
	job.status = status
	job.Unlock()

	job.RLock()
	for _, ch := range job.subscribers {
		ch <- struct{}{}
	}
	job.RUnlock()
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
