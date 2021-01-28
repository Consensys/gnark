package server

import (
	"fmt"
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
	witness     []byte
	err         error
	proof       []byte
	subscribers []chan struct{}
}

// will lock job.
func (job *proveJob) setStatus(status pb.ProveJobResult_Status) error {

	job.Lock()
	// ensure state machine transitions are valid.
	switch status {
	case pb.ProveJobResult_QUEUED:
		if job.status != pb.ProveJobResult_WAITING_WITNESS {
			job.Unlock()
			return fmt.Errorf("invalid status transition from %s to %s on job %s", job.status.String(), status.String(), job.id.String())
		}
	case pb.ProveJobResult_RUNNING:
		if job.status != pb.ProveJobResult_QUEUED {
			job.Unlock()
			return fmt.Errorf("invalid status transition from %s to %s on job %s", job.status.String(), status.String(), job.id.String())
		}
	case pb.ProveJobResult_ERRORED, pb.ProveJobResult_COMPLETED:
		if job.status != pb.ProveJobResult_RUNNING {
			job.Unlock()
			return fmt.Errorf("invalid status transition from %s to %s on job %s", job.status.String(), status.String(), job.id.String())
		}
	default:
		job.Unlock()
		return fmt.Errorf("invalid status transition from %s to %s on job %s", job.status.String(), status.String(), job.id.String())
	}
	job.status = status
	job.Unlock()

	job.RLock()
	for _, ch := range job.subscribers {
		ch <- struct{}{}
	}
	job.RUnlock()
	return nil
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
	return
}

// must be called under lock
func (job *proveJob) isFinished() bool {
	return (job.status == pb.ProveJobResult_COMPLETED) || (job.status == pb.ProveJobResult_ERRORED)
}
