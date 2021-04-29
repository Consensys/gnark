package server

import (
	"errors"
	"sync"
	"time"

	"github.com/consensys/gnark/gnarkd/pb"
	"github.com/google/uuid"
)

const jobIDSize = len(uuid.UUID{})

type jobID = uuid.UUID
type proveJob struct {
	sync.RWMutex

	id          jobID
	circuitID   string
	status      pb.ProveJobResult_Status
	expiration  time.Time
	witness     []byte
	err         error
	proof       []byte
	subscribers []chan struct{}
}

var errInvalidJobStatusTransition = errors.New("invalid job status transition")

// will lock job.
// change status and update TTL
// returns error if status transition is invalid.
func (job *proveJob) setStatus(status pb.ProveJobResult_Status) error {

	job.Lock()
	// ensure state machine transitions are valid
	switch status {
	case pb.ProveJobResult_QUEUED:
		if job.status != pb.ProveJobResult_WAITING_WITNESS {
			job.Unlock()
			return errInvalidJobStatusTransition
		}
	case pb.ProveJobResult_RUNNING:
		if job.status != pb.ProveJobResult_QUEUED {
			job.Unlock()
			return errInvalidJobStatusTransition
		}
	case pb.ProveJobResult_ERRORED, pb.ProveJobResult_COMPLETED:
		if job.status != pb.ProveJobResult_RUNNING {
			job.Unlock()
			return errInvalidJobStatusTransition
		}
	default:
		job.Unlock()
		return errInvalidJobStatusTransition
	}
	job.status = status
	// TODO @gbotrel TTL policy?
	// job.expiration = time.Now().Add(defaultTTL)
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
}

// must be called under lock
func (job *proveJob) isFinished() bool {
	return (job.status == pb.ProveJobResult_COMPLETED) || (job.status == pb.ProveJobResult_ERRORED)
}
