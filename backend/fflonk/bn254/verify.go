package fflonk

import (
	"errors"
	"fmt"
	"io"
	"math/big"
	"time"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"

	"github.com/consensys/gnark-crypto/ecc/bn254/fflonk"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/hash_to_field"
	"github.com/consensys/gnark-crypto/ecc/bn254/kzg"

	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/logger"
)

var (
	errAlgebraicRelation = errors.New("algebraic relation does not hold")
	errInvalidWitness    = errors.New("witness length is invalid")
)

func Verify(proof *Proof, vk *VerifyingKey, publicWitness fr.Vector, opts ...backend.VerifierOption) error {

	log := logger.Logger().With().Str("curve", "bn254").Str("backend", "plonk").Logger()
	start := time.Now()
	cfg, err := backend.NewVerifierConfig(opts...)
	if err != nil {
		return fmt.Errorf("create backend config: %w", err)
	}

	if len(publicWitness) != int(vk.NbPublicVariables) {
		return errInvalidWitness
	}

	// transcript to derive the challenge
	fs := fiatshamir.NewTranscript(cfg.ChallengeHash, "gamma", "beta", "alpha", "zeta")

	// The first challenge is derived using the public data: the commitments to the permutation,
	// the coefficients of the circuit, and the public inputs.
	// derive gamma from the Comm(blinded cl), Comm(blinded cr), Comm(blinded co)
	if err := bindPublicData(fs, "gamma", vk, publicWitness); err != nil {
		return err
	}
	gamma, err := deriveRandomness(fs, "gamma", &proof.LROEntangled)
	if err != nil {
		return err
	}

	// derive beta from Comm(l), Comm(r), Comm(o)
	beta, err := deriveRandomness(fs, "beta")
	if err != nil {
		return err
	}

	// derive alpha from Com(Z), BsbComEntangled
	alphaDeps := make([]*curve.G1Affine, len(proof.BsbComEntangled)+1)
	for i := range proof.BsbComEntangled {
		alphaDeps[i] = &proof.BsbComEntangled[i]
	}
	alphaDeps[len(alphaDeps)-1] = &proof.ZEntangled
	alpha, err := deriveRandomness(fs, "alpha", alphaDeps...)
	if err != nil {
		return err
	}

	// derive zeta, the point of evaluation
	zeta, err := deriveRandomness(fs, "zeta", &proof.HEntangled)
	if err != nil {
		return err
	}

	fmt.Printf("[VERIFIER] beta = %s\n", beta.String())
	fmt.Printf("[VERIFIER] gamma = %s\n", gamma.String())
	fmt.Printf("[VERIFIER] alpha = %s\n", alpha.String())
	fmt.Printf("[VERIFIER] zeta = %s\n", zeta.String())

	// evaluation of zhZeta=ζⁿ-1
	var zetaPowerM, zhZeta, lagrangeOne fr.Element
	var bExpo big.Int
	one := fr.One()
	bExpo.SetUint64(vk.Size)
	zetaPowerM.Exp(zeta, &bExpo)
	zhZeta.Sub(&zetaPowerM, &one) // ζⁿ-1
	lagrangeOne.Sub(&zeta, &one). // ζ-1
					Inverse(&lagrangeOne).         // 1/(ζ-1)
					Mul(&lagrangeOne, &zhZeta).    // (ζ^n-1)/(ζ-1)
					Mul(&lagrangeOne, &vk.SizeInv) // 1/n * (ζ^n-1)/(ζ-1)

	// compute PI = ∑_{i<n} Lᵢ*wᵢ
	var pi fr.Element
	var accw fr.Element
	{
		// [ζ-1,ζ-ω,ζ-ω²,..]
		dens := make([]fr.Element, len(publicWitness))
		accw.SetOne()
		for i := 0; i < len(publicWitness); i++ {
			dens[i].Sub(&zeta, &accw)
			accw.Mul(&accw, &vk.Generator)
		}

		// [1/(ζ-1),1/(ζ-ω),1/(ζ-ω²),..]
		invDens := fr.BatchInvert(dens)

		accw.SetOne()
		var xiLi fr.Element
		for i := 0; i < len(publicWitness); i++ {
			xiLi.Mul(&zhZeta, &invDens[i]).
				Mul(&xiLi, &vk.SizeInv).
				Mul(&xiLi, &accw).
				Mul(&xiLi, &publicWitness[i]) // Pi[i]*(ωⁱ/n)(ζ^n-1)/(ζ-ω^i)
			accw.Mul(&accw, &vk.Generator)
			pi.Add(&pi, &xiLi)
		}

		if cfg.HashToFieldFn == nil {
			cfg.HashToFieldFn = hash_to_field.New([]byte("BSB22-Plonk"))
		}
		var hashedCmt fr.Element
		nbBuf := fr.Bytes
		if cfg.HashToFieldFn.Size() < fr.Bytes {
			nbBuf = cfg.HashToFieldFn.Size()
		}
		var wPowI, den, lagrange fr.Element
		for i := range vk.CommitmentConstraintIndexes {
			cfg.HashToFieldFn.Write(proof.BsbComEntangled[i].Marshal())
			hashBts := cfg.HashToFieldFn.Sum(nil)
			cfg.HashToFieldFn.Reset()
			hashedCmt.SetBytes(hashBts[:nbBuf])

			// Computing Lᵢ(ζ) where i=CommitmentIndex
			wPowI.Exp(vk.Generator, big.NewInt(int64(vk.NbPublicVariables)+int64(vk.CommitmentConstraintIndexes[i])))
			den.Sub(&zeta, &wPowI) // ζ-wⁱ
			lagrange.SetOne().
				Sub(&zetaPowerM, &lagrange). // ζⁿ-1
				Mul(&lagrange, &wPowI).      // wⁱ(ζⁿ-1)
				Div(&lagrange, &den).        // wⁱ(ζⁿ-1)/(ζ-wⁱ)
				Mul(&lagrange, &vk.SizeInv)  // wⁱ/n (ζⁿ-1)/(ζ-wⁱ)

			xiLi.Mul(&lagrange, &hashedCmt)
			pi.Add(&pi, &xiLi)
		}
	}

	// reconstruct the entangled digest and verify the opening proof
	points := make([][]fr.Element, 2)
	points[0] = make([]fr.Element, 1)
	points[1] = make([]fr.Element, 1)
	// points[0][0].Set(&zeta)
	points[0][0].Set(&zeta)
	t := getNextDivisorRMinusOne(*vk)
	tBigInt := big.NewInt(int64(t))
	var omegaZetaT fr.Element
	omegaZetaT.Exp(zeta, tBigInt).Mul(&omegaZetaT, &vk.Generator)
	var foldedDigests [2]kzg.Digest
	foldedDigests[0].Set(&vk.Qpublic).
		Add(&foldedDigests[0], &proof.LROEntangled).
		Add(&foldedDigests[0], &proof.ZEntangled).
		Add(&foldedDigests[0], &proof.HEntangled)
	for i := 0; i < len(proof.BsbComEntangled); i++ {
		foldedDigests[0].Add(&foldedDigests[0], &proof.BsbComEntangled[i])
	}
	foldedDigests[1].Set(&proof.Z)
	err = fflonk.BatchVerify(proof.BatchOpeningProof, foldedDigests[:], points, cfg.KZGFoldingHash, vk.Kzg)

	log.Debug().Dur("took", time.Since(start)).Msg("verifier done")

	return err
}

func bindPublicData(fs *fiatshamir.Transcript, challenge string, vk *VerifyingKey, publicInputs []fr.Element) error {

	// permutation
	if err := fs.Bind(challenge, vk.S[0].Marshal()); err != nil {
		return err
	}
	if err := fs.Bind(challenge, vk.S[1].Marshal()); err != nil {
		return err
	}
	if err := fs.Bind(challenge, vk.S[2].Marshal()); err != nil {
		return err
	}

	// coefficients
	if err := fs.Bind(challenge, vk.Ql.Marshal()); err != nil {
		return err
	}
	if err := fs.Bind(challenge, vk.Qr.Marshal()); err != nil {
		return err
	}
	if err := fs.Bind(challenge, vk.Qm.Marshal()); err != nil {
		return err
	}
	if err := fs.Bind(challenge, vk.Qo.Marshal()); err != nil {
		return err
	}
	if err := fs.Bind(challenge, vk.Qk.Marshal()); err != nil {
		return err
	}
	for i := range vk.Qcp {
		if err := fs.Bind(challenge, vk.Qcp[i].Marshal()); err != nil {
			return err
		}
	}

	// public inputs
	for i := 0; i < len(publicInputs); i++ {
		if err := fs.Bind(challenge, publicInputs[i].Marshal()); err != nil {
			return err
		}
	}

	return nil

}

func deriveRandomness(fs *fiatshamir.Transcript, challenge string, points ...*curve.G1Affine) (fr.Element, error) {

	var buf [curve.SizeOfG1AffineUncompressed]byte
	var r fr.Element

	for _, p := range points {
		buf = p.RawBytes()
		if err := fs.Bind(challenge, buf[:]); err != nil {
			return r, err
		}
	}

	b, err := fs.ComputeChallenge(challenge)
	if err != nil {
		return r, err
	}
	r.SetBytes(b)
	return r, nil
}

// ExportSolidity exports the verifying key to a solidity smart contract.
//
// See https://github.com/ConsenSys/gnark-tests for example usage.
//
// Code has not been audited and is provided as-is, we make no guarantees or warranties to its safety and reliability.
func (vk *VerifyingKey) ExportSolidity(w io.Writer) error {
	// funcMap := template.FuncMap{
	// 	"hex": func(i int) string {
	// 		return fmt.Sprintf("0x%x", i)
	// 	},
	// 	"mul": func(a, b int) int {
	// 		return a * b
	// 	},
	// 	"inc": func(i int) int {
	// 		return i + 1
	// 	},
	// 	"frstr": func(x fr.Element) string {
	// 		// we use big.Int to always get a positive string.
	// 		// not the most efficient hack, but it works better for .sol generation.
	// 		bv := new(big.Int)
	// 		x.BigInt(bv)
	// 		return bv.String()
	// 	},
	// 	"fpstr": func(x fp.Element) string {
	// 		bv := new(big.Int)
	// 		x.BigInt(bv)
	// 		return bv.String()
	// 	},
	// 	"add": func(i, j int) int {
	// 		return i + j
	// 	},
	// }

	// t, err := template.New("t").Funcs(funcMap).Parse(tmplSolidityVerifier)
	// if err != nil {
	// 	return err
	// }
	// return t.Execute(w, vk)
	return nil
}
