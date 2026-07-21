//go:build js && wasm

package bls12381

import (
	"fmt"
	"math/big"
	"strconv"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/hash_to_field"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/accelerated/webgpu/groth16/internal/bridge"
	"github.com/consensys/gnark/backend/accelerated/webgpu/groth16/internal/common"
	native "github.com/consensys/gnark/backend/groth16/bls12-381"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bls12-381"
	"github.com/consensys/gnark/constraint/solver"
	fcs "github.com/consensys/gnark/frontend/cs"
)

func Prove(r1cs *cs.R1CS, pk *ProvingKey, fullWitness witness.Witness, opts ...backend.ProverOption) (*native.Proof, error) {
	opt, err := backend.NewProverConfig(opts...)
	if err != nil {
		return nil, fmt.Errorf("new prover config: %w", err)
	}
	if opt.HashToFieldFn == nil {
		opt.HashToFieldFn = hash_to_field.New([]byte(constraint.CommitmentDst))
	}

	commitmentInfo := r1cs.CommitmentInfo.(constraint.Groth16Commitments)

	if err := pk.Prepare(); err != nil {
		return nil, err
	}
	pk.scratchMu.Lock()
	defer pk.scratchMu.Unlock()

	proof := &native.Proof{
		Commitments: make([]bls12381.G1Affine, len(commitmentInfo)),
	}
	privateCommittedValues := make([][]fr.Element, len(commitmentInfo))
	solverOpts := opt.SolverOpts[:len(opt.SolverOpts):len(opt.SolverOpts)]
	bsb22ID := solver.GetHintID(fcs.Bsb22CommitmentComputePlaceholder)
	solverOpts = append(solverOpts, solver.OverrideHint(bsb22ID, func(_ *big.Int, in []*big.Int, out []*big.Int) error {
		i := int(in[0].Int64())
		if i < 0 || i >= len(commitmentInfo) {
			return fmt.Errorf("webgpu groth16 bls12_381: invalid commitment index %d", i)
		}
		in = in[1:]
		hashedCount := len(commitmentInfo[i].PublicAndCommitmentCommitted)
		if len(in) < hashedCount {
			return fmt.Errorf("webgpu groth16 bls12_381: commitment hint %d has %d inputs, expected at least %d", i, len(in), hashedCount)
		}
		hashed := in[:hashedCount]
		committed := in[hashedCount:]

		privateCommittedValues[i] = make([]fr.Element, len(committed))
		for j, inJ := range committed {
			privateCommittedValues[i][j].SetBigInt(inJ)
		}

		scalars := packFrVectorRegularLEInto(nil, privateCommittedValues[i])
		commitmentPacked, err := bridge.Bridge.MSMG1(pk.handle, "commitmentBasis"+strconv.Itoa(i), scalars)
		if err != nil {
			return fmt.Errorf("webgpu groth16 bls12_381: commitment %d MSM: %w", i, err)
		}
		if proof.Commitments[i], err = decodeG1AffineFromPacked(commitmentPacked, nil); err != nil {
			return fmt.Errorf("webgpu groth16 bls12_381: commitment %d decode: %w", i, err)
		}

		if _, err := opt.HashToFieldFn.Write(constraint.SerializeCommitment(proof.Commitments[i].Marshal(), hashed, (fr.Bits-1)/8+1)); err != nil {
			return err
		}
		hashBts := opt.HashToFieldFn.Sum(nil)
		opt.HashToFieldFn.Reset()
		nbBuf := fr.Bytes
		if opt.HashToFieldFn.Size() < fr.Bytes {
			nbBuf = opt.HashToFieldFn.Size()
		}
		var res fr.Element
		res.SetBytes(hashBts[:nbBuf])
		res.BigInt(out[0])
		return nil
	}))

	_solution, err := r1cs.Solve(fullWitness, solverOpts...)
	if err != nil {
		return nil, err
	}
	solution := _solution.(*cs.R1CSSolution)
	wireValues := []fr.Element(solution.W)
	domainSize := int(pk.Domain.Cardinality)

	if len(commitmentInfo) > 0 {
		poks := make([]bls12381.G1Affine, len(commitmentInfo))
		for i := range commitmentInfo {
			if privateCommittedValues[i] == nil {
				return nil, fmt.Errorf("webgpu groth16 bls12_381: commitment hint %d was not evaluated", i)
			}
			scalars := packFrVectorRegularLEInto(nil, privateCommittedValues[i])
			pokPacked, err := bridge.Bridge.MSMG1(pk.handle, "commitmentBasisExpSigma"+strconv.Itoa(i), scalars)
			if err != nil {
				return nil, fmt.Errorf("webgpu groth16 bls12_381: commitment %d pok MSM: %w", i, err)
			}
			if poks[i], err = decodeG1AffineFromPacked(pokPacked, nil); err != nil {
				return nil, fmt.Errorf("webgpu groth16 bls12_381: commitment %d pok decode: %w", i, err)
			}
		}
		commitmentsSerialized := make([]byte, fr.Bytes*len(commitmentInfo))
		for i := range commitmentInfo {
			copy(commitmentsSerialized[fr.Bytes*i:], wireValues[commitmentInfo[i].CommitmentIndex].Marshal())
		}
		challenge, err := fr.Hash(commitmentsSerialized, []byte("G16-BSB22"), 1)
		if err != nil {
			return nil, err
		}
		if _, err = proof.CommitmentPok.Fold(poks, challenge[0], ecc.MultiExpConfig{NbTasks: 1}); err != nil {
			return nil, err
		}
	}

	pk.scratch0 = packFrVectorMontLEPaddedInto(pk.scratch0, solution.A, domainSize)
	pk.scratch1 = packFrVectorMontLEPaddedInto(pk.scratch1, solution.B, domainSize)
	pk.scratch2 = packFrVectorMontLEPaddedInto(pk.scratch2, solution.C, domainSize)
	zPacked, err := bridge.Bridge.ComputeHZMSMG1(pk.handle, pk.scratch0, pk.scratch1, pk.scratch2)
	if err != nil {
		return nil, fmt.Errorf("webgpu groth16 bls12_381: quotient H + msm G1.Z: %w", err)
	}
	publicVariables := r1cs.GetNbPublicVariables()

	pk.scratch0, _ = packFrVectorFilteredInto(pk.scratch0, wireValues, pk.g1AIndices, len(pk.InfinityA))
	pk.scratch1, _ = packFrVectorFilteredInto(pk.scratch1, wireValues, pk.g1BIndices, len(pk.InfinityB))
	pk.scratch2 = packFrVectorRegularLEFilteredOutInto(pk.scratch2, wireValues[publicVariables:], publicVariables, common.CommitmentWireIndexesToRemove(commitmentInfo))
	batchMSM, err := bridge.Bridge.MSMBatch(pk.handle, pk.scratch0, pk.scratch1, pk.scratch2)
	if err != nil {
		return nil, fmt.Errorf("webgpu groth16 bls12_381: batched MSMs: %w", err)
	}
	arBaseAff, err := decodeG1AffineFromPacked(batchMSM.G1ABytes, nil)
	if err != nil {
		return nil, fmt.Errorf("webgpu groth16 bls12_381: msm G1.A: %w", err)
	}
	bs1BaseAff, err := decodeG1AffineFromPacked(batchMSM.G1BBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("webgpu groth16 bls12_381: msm G1.B: %w", err)
	}
	kBaseAff, err := decodeG1AffineFromPacked(batchMSM.G1KBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("webgpu groth16 bls12_381: msm G1.K: %w", err)
	}
	zBaseAff, err := decodeG1AffineFromPacked(zPacked, nil)
	if err != nil {
		return nil, fmt.Errorf("webgpu groth16 bls12_381: msm G1.Z: %w", err)
	}
	bsBaseAff, err := decodeG2AffineFromPacked(batchMSM.G2BBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("webgpu groth16 bls12_381: msm G2.B: %w", err)
	}

	var r, s big.Int
	var _r, _s, _kr fr.Element
	if _, err := _r.SetRandom(); err != nil {
		return nil, err
	}
	if _, err := _s.SetRandom(); err != nil {
		return nil, err
	}
	_kr.Mul(&_r, &_s).Neg(&_kr)
	_r.BigInt(&r)
	_s.BigInt(&s)

	deltas := bls12381.BatchScalarMultiplicationG1(&pk.G1.Delta, []fr.Element{_r, _s, _kr})

	var ar, bs1, krs, krs2, tmp bls12381.G1Jac
	ar.FromAffine(&arBaseAff)
	ar.AddMixed(&pk.G1.Alpha)
	ar.AddMixed(&deltas[0])

	bs1.FromAffine(&bs1BaseAff)
	bs1.AddMixed(&pk.G1.Beta)
	bs1.AddMixed(&deltas[1])

	krs.FromAffine(&kBaseAff)
	krs2.FromAffine(&zBaseAff)
	krs.AddAssign(&krs2)
	krs.AddMixed(&deltas[2])

	tmp.ScalarMultiplication(&ar, &s)
	krs.AddAssign(&tmp)
	tmp.ScalarMultiplication(&bs1, &r)
	krs.AddAssign(&tmp)

	var bs, deltaS bls12381.G2Jac
	bs.FromAffine(&bsBaseAff)
	deltaS.FromAffine(&pk.G2.Delta)
	deltaS.ScalarMultiplication(&deltaS, &s)
	bs.AddAssign(&deltaS)
	bs.AddMixed(&pk.G2.Beta)

	proof.Ar.FromJacobian(&ar)
	proof.Krs.FromJacobian(&krs)
	proof.Bs.FromJacobian(&bs)
	return proof, nil
}
