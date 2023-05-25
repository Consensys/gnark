package ignition

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"golang.org/x/crypto/blake2b"
)

// Contribution is a participant's contribution to the ceremony
type Contribution struct {
	G1 []bn254.G1Affine
	G2 [2]bn254.G2Affine
}

// NewContribution allocates a new contribution
func NewContribution(nbPoints int) Contribution {
	var c Contribution
	c.G1 = make([]bn254.G1Affine, nbPoints)
	return c
}

// Get download or reads a contribution from a participant to the ceremony
// The contribution validity is partially checked;
// The G1 points are powers of Tau.
// TODO we don't actually check the contribution against the signature of a known address (participant).
func (c *Contribution) Get(participant Participant, config Config) error {
	addr := strings.ToLower(participant.Address)

	// read all transcripts
	totalTranscripts := math.MaxInt
	for i := 0; i < totalTranscripts; i++ {
		file := fmt.Sprintf("%03d_%s/transcript%02d.dat", participant.Position, addr, i)

		b, err := readOrDownload(config.ceremonyURL(), file, config)
		if err != nil {
			return err
		}

		// read the actual points from the bytes
		tManifest := newTranscriptManifest(b)
		totalTranscripts = int(tManifest.TotalTranscripts)
		if totalTranscripts > 30 {
			return errors.New("too many transcripts, that's suspicious")
		}

		// read G1 points
		offset := 28
		readG1Points(b[offset:], tManifest.NumG1Points, c.G1[tManifest.StartFrom:tManifest.StartFrom+tManifest.NumG1Points])
		offset += int(tManifest.NumG1Points) * bn254.SizeOfG1AffineUncompressed

		// read G2 point
		if i == 0 {
			readG2Points(b[offset:], &c.G2)
			if !c.G2[0].IsInSubGroup() || !c.G2[1].IsInSubGroup() {
				return errors.New("invalid G2 point: not in subgroup")
			}
			offset += bn254.SizeOfG2AffineUncompressed * 2
		}

		// The 'checksum' - a BLAKE2B hash of the rest of the file's data
		checksum := blake2b.Sum512(b[:offset])
		if !bytes.Equal(b[offset:offset+64], checksum[:]) {
			return errors.New("invalid checksum")
		}
	}

	var nbErrs uint64
	execute(len(c.G1), func(start, end int) {
		for i := start; i < end; i++ {
			// to montgomery form
			c.G1[i].X.Mul(&c.G1[i].X, &rSquare)
			c.G1[i].Y.Mul(&c.G1[i].Y, &rSquare)

			// check if the point is on the curve
			if !c.G1[i].IsInSubGroup() {
				atomic.AddUint64(&nbErrs, 1)
				return
			}
		}
	})
	if nbErrs > 0 {
		return errors.New("invalid point(s): some points are not on the curve or in the correct subgroup")
	}
	if !c.IsValid() {
		return errors.New("invalid point(s): the contribution is not valid")
	}
	return nil
}

// Follows checks that a contribution is based on a known previous contribution.
func (contribution *Contribution) Follows(previous *Contribution) bool {
	// check that e1 = pair(g2gen, contribution.G1) == e2 = pair(contribution.G2, current.G1)
	return sameRatio(contribution.G1[0], previous.G1[0], g2gen, contribution.G2[1])
}

// IsValid checks if the contribution is valid
func (c *Contribution) IsValid() bool {
	l1, l2 := linearCombinationG1(c.G1)
	return sameRatio(l1, l2, c.G2[0], g2gen)
}

// utils functions; from gnark groth16 mpc

// sameRatio checks that e(a₁, a₂) = e(b₁, b₂)
func sameRatio(a1, b1 bn254.G1Affine, a2, b2 bn254.G2Affine) bool {
	// we already know that a1, b1, a2, b2 are in the correct subgroup
	// if !a1.IsInSubGroup() || !b1.IsInSubGroup() || !a2.IsInSubGroup() || !b2.IsInSubGroup() {
	// 	panic("invalid point not in subgroup")
	// }
	var na2 bn254.G2Affine
	na2.Neg(&a2)
	res, err := bn254.PairingCheck(
		[]bn254.G1Affine{a1, b1},
		[]bn254.G2Affine{na2, b2})
	if err != nil {
		panic(err)
	}
	return res
}

// L1 = ∑ rᵢAᵢ, L2 = ∑ rᵢAᵢ₊₁ in G1
func linearCombinationG1(A []bn254.G1Affine) (L1, L2 bn254.G1Affine) {
	nc := runtime.NumCPU()
	n := len(A)
	r := make([]fr.Element, n-1)
	for i := 0; i < n-1; i++ {
		r[i].SetRandom()
	}
	chDone := make(chan struct{})
	go func() {
		L1.MultiExp(A[:n-1], r, ecc.MultiExpConfig{NbTasks: nc / 2})
		close(chDone)
	}()
	L2.MultiExp(A[1:], r, ecc.MultiExpConfig{NbTasks: nc / 2})
	<-chDone
	return
}

// execute process in parallel the work function
func execute(nbIterations int, work func(int, int), maxCpus ...int) {

	nbTasks := runtime.NumCPU()
	if len(maxCpus) == 1 {
		nbTasks = maxCpus[0]
		if nbTasks < 1 {
			nbTasks = 1
		} else if nbTasks > 512 {
			nbTasks = 512
		}
	}

	if nbTasks == 1 {
		// no go routines
		work(0, nbIterations)
		return
	}

	nbIterationsPerCpus := nbIterations / nbTasks

	// more CPUs than tasks: a CPU will work on exactly one iteration
	if nbIterationsPerCpus < 1 {
		nbIterationsPerCpus = 1
		nbTasks = nbIterations
	}

	var wg sync.WaitGroup

	extraTasks := nbIterations - (nbTasks * nbIterationsPerCpus)
	extraTasksOffset := 0

	for i := 0; i < nbTasks; i++ {
		wg.Add(1)
		_start := i*nbIterationsPerCpus + extraTasksOffset
		_end := _start + nbIterationsPerCpus
		if extraTasks > 0 {
			_end++
			extraTasks--
			extraTasksOffset++
		}
		go func() {
			work(_start, _end)
			wg.Done()
		}()
	}

	wg.Wait()
}

var g2gen bn254.G2Affine

func init() {
	_, _, _, g2gen = bn254.Generators()
}
