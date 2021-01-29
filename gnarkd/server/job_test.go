package server

import (
	"testing"

	"github.com/consensys/gnark/gnarkd/pb"
	"github.com/stretchr/testify/require"
)

func TestJobStatusChange(t *testing.T) {
	assert := require.New(t)
	const nbStatus = pb.ProveJobResult_ERRORED + 1

	assert.Equal(pb.ProveJobResult_WAITING_WITNESS, proveJob{}.status, "default job status must be WAITING_WITNESS")
	assert.Equal(int(nbStatus), int(len(pb.ProveJobResult_Status_name)), "if statuses values are different, this test need to be updated")

	validTransitions := func(initial pb.ProveJobResult_Status, validStatus ...pb.ProveJobResult_Status) {
		badStatus := make([]pb.ProveJobResult_Status, int(nbStatus)-len(validStatus))
		for k, v := range pb.ProveJobResult_Status_value {
			isMarkedValid := false
			for _, vs := range validStatus {
				if vs.String() == k {
					isMarkedValid = true
					break
				}
			}
			if isMarkedValid {
				continue
			}
			badStatus = append(badStatus, pb.ProveJobResult_Status(v))
		}
		// check that all other transitions than the valid one provided fail
		for _, s := range badStatus {
			job := proveJob{status: initial}
			assert.Error(job.setStatus(s))
		}

		// check that the valid transition succeed
		for _, s := range validStatus {
			job := proveJob{status: initial}
			assert.NoError(job.setStatus(s))
		}
	}

	validTransitions(pb.ProveJobResult_WAITING_WITNESS, pb.ProveJobResult_QUEUED)
	validTransitions(pb.ProveJobResult_QUEUED, pb.ProveJobResult_RUNNING)
	validTransitions(pb.ProveJobResult_RUNNING, []pb.ProveJobResult_Status{pb.ProveJobResult_ERRORED, pb.ProveJobResult_COMPLETED}...)

}
