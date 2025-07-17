package evmprecompiles

import (
	"bytes"
	"fmt"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	kzg_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/commitments/kzg"
	"github.com/consensys/gnark/std/conversion"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
)

// fixedKzgSrsVk is the verifying key for the KZG precompile. As it is fixed,
// then we can embed it into the circuit instead of passing as a witness
// argument.
var fixedKzgSrsVk *kzg.VerifyingKey[sw_bls12381.G1Affine, sw_bls12381.G2Affine]

func init() {
	fixedKzgSrsVk = fixedVerificationKey() // initialize the fixed verifying key
}

var (
	// srs contains concatenated G1 and G2 elements of the KZG SRS in compressed form.
	srs = []byte{
		// G1 part
		0x97, 0xf1, 0xd3, 0xa7, 0x31, 0x97, 0xd7, 0x94, 0x26, 0x95, 0x63, 0x8c, 0x4f, 0xa9, 0xac, 0x0f,
		0xc3, 0x68, 0x8c, 0x4f, 0x97, 0x74, 0xb9, 0x05, 0xa1, 0x4e, 0x3a, 0x3f, 0x17, 0x1b, 0xac, 0x58,
		0x6c, 0x55, 0xe8, 0x3f, 0xf9, 0x7a, 0x1a, 0xef, 0xfb, 0x3a, 0xf0, 0x0a, 0xdb, 0x22, 0xc6, 0xbb,
		// G2[0] part
		0x93, 0xe0, 0x2b, 0x60, 0x52, 0x71, 0x9f, 0x60, 0x7d, 0xac, 0xd3, 0xa0, 0x88, 0x27, 0x4f, 0x65,
		0x59, 0x6b, 0xd0, 0xd0, 0x99, 0x20, 0xb6, 0x1a, 0xb5, 0xda, 0x61, 0xbb, 0xdc, 0x7f, 0x50, 0x49,
		0x33, 0x4c, 0xf1, 0x12, 0x13, 0x94, 0x5d, 0x57, 0xe5, 0xac, 0x7d, 0x05, 0x5d, 0x04, 0x2b, 0x7e,
		0x02, 0x4a, 0xa2, 0xb2, 0xf0, 0x8f, 0x0a, 0x91, 0x26, 0x08, 0x05, 0x27, 0x2d, 0xc5, 0x10, 0x51,
		0xc6, 0xe4, 0x7a, 0xd4, 0xfa, 0x40, 0x3b, 0x02, 0xb4, 0x51, 0x0b, 0x64, 0x7a, 0xe3, 0xd1, 0x77,
		0x0b, 0xac, 0x03, 0x26, 0xa8, 0x05, 0xbb, 0xef, 0xd4, 0x80, 0x56, 0xc8, 0xc1, 0x21, 0xbd, 0xb8,
		// G2[1] part
		0xb5, 0xbf, 0xd7, 0xdd, 0x8c, 0xde, 0xb1, 0x28, 0x84, 0x3b, 0xc2, 0x87, 0x23, 0x0a, 0xf3, 0x89,
		0x26, 0x18, 0x70, 0x75, 0xcb, 0xfb, 0xef, 0xa8, 0x10, 0x09, 0xa2, 0xce, 0x61, 0x5a, 0xc5, 0x3d,
		0x29, 0x14, 0xe5, 0x87, 0x0c, 0xb4, 0x52, 0xd2, 0xaf, 0xaa, 0xab, 0x24, 0xf3, 0x49, 0x9f, 0x72,
		0x18, 0x5c, 0xbf, 0xee, 0x53, 0x49, 0x27, 0x14, 0x73, 0x44, 0x29, 0xb7, 0xb3, 0x86, 0x08, 0xe2,
		0x39, 0x26, 0xc9, 0x11, 0xcc, 0xec, 0xea, 0xc9, 0xa3, 0x68, 0x51, 0x47, 0x7b, 0xa4, 0xc6, 0x0b,
		0x08, 0x70, 0x41, 0xde, 0x62, 0x10, 0x00, 0xed, 0xc9, 0x8e, 0xda, 0xda, 0x20, 0xc1, 0xde, 0xf2,
	}
)

func fixedVerificationKey() *kzg.VerifyingKey[sw_bls12381.G1Affine, sw_bls12381.G2Affine] {
	var vk kzg_bls12381.VerifyingKey
	dec := bls12381.NewDecoder(bytes.NewBuffer(srs), bls12381.NoSubgroupChecks())
	err := dec.Decode(&vk.G1)
	if err != nil {
		panic(fmt.Sprintf("failed to set G1 element: %v", err))
	}
	err = dec.Decode(&vk.G2[0])
	if err != nil {
		panic(fmt.Sprintf("failed to set G2[0] element: %v", err))
	}
	err = dec.Decode(&vk.G2[1])
	if err != nil {
		panic(fmt.Sprintf("failed to set G2[1] element: %v", err))
	}
	vk.Lines[0] = bls12381.PrecomputeLines(vk.G2[0])
	vk.Lines[1] = bls12381.PrecomputeLines(vk.G2[1])
	vkw, err := kzg.ValueOfVerifyingKeyFixed[sw_bls12381.G1Affine, sw_bls12381.G2Affine](vk)
	if err != nil {
		panic(fmt.Sprintf("failed to convert verifying key to fixed: %v", err))
	}
	return &vkw
}

const (
	// blobCommitmentVersionKZG is the version byte for the KZG point evaluation precompile.
	blobCommitmentVersionKZG uint8 = 0x01
	// evmBlockSize is the size of the SRS used in the KZG precompile. This
	// defines the polynomial degree and therefore the size of the blob. It is also the expected
	// return value of the POINTEVAL precompile.
	evmBlockSize = 4096
	// evmBlsModulus is the modulus of the BLS12-381 scalar field in hexadecimal
	// format, split into 16-byte high and low parts for the expected values.
	evmBlsModulusHi = "0x73eda753299d7d483339d80809a1d805"
	evmBlsModulusLo = "0x53bda402fffe5bfeffffffff00000001"
)

// KzgPointEvaluation implements the [KZG_POINT_EVALUATION] precompile at
// address 0xa.
//
// The data is encoded as follows:
//
//	[ versioned_hash | point |  claim  | commitment |   proof   ]
//	 <---- 32b -----> <-32b-> <- 32b -> <-- 48b  --> <-- 48b -->
//
// Values point and claim are the evaluation point and the claimed value, they
// are represented as 32-byte scalar field elements. We use [2]frontend.Variable
// as the arithmetization provides them as 16-byte words.
//
// Values commitment and proof are the KZG commitment and proof respectively.
// They are given as compressed points, for which we use 3 native elements to
// represent. The method performs decompression and all necessary checks. The
// encoding is given by Appendix C of [PAIRING_FRIENDLY_CURVES].
//
// [KZG_POINT_EVALUATION]
// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-4844.md
// [PAIRING_FRIENDLY_CURVES]
// https://datatracker.ietf.org/doc/draft-irtf-cfrg-pairing-friendly-curves/
func KzgPointEvaluation(
	api frontend.API,
	versionedHash [2]frontend.Variable, // arithmetization gives us a 2-element array. We convert it ourselves to a byte array.
	evaluationPoint emulated.Element[sw_bls12381.ScalarField],
	claimedValue emulated.Element[sw_bls12381.ScalarField],
	commitmentCompressed [3]frontend.Variable, // commitment is a 48 byte compressed point. Arithmetization uses 16-byte words, so we use a 3-element array.
	proofCompressed [3]frontend.Variable, // proof is a 48 byte compressed point. Arithmetization uses 16-byte words, so we use a 3-element array.
	expectedSuccess frontend.Variable, // expected success is a single byte that is 1 if the proof is valid, 0 otherwise
	expectedBlobSize [2]frontend.Variable, // arithmetization uses 2-element array. It is constant for all purposes, but we check it anyway.
	expectedBlsModulus [2]frontend.Variable, // arithmetization uses 2-element array. It is constant for all purposes, but we check it anyway.
) error { // we don't return a value as the result is a constant value
	// -- perform conversion from 16-byte words to 1-byte words

	// versioned hash
	var versionedHashBytes [32]uints.U8
	for i := range versionedHash {
		res, err := conversion.NativeToBytes(api, versionedHash[len(versionedHash)-1-i])
		if err != nil {
			return fmt.Errorf("convert versioned hash element %d to bytes: %w", i, err)
		}
		copy(versionedHashBytes[i*16:(i+1)*16], res[16:])
	}

	// commitment
	var comSerializedBytes [48]uints.U8
	for i := range commitmentCompressed {
		res, err := conversion.NativeToBytes(api, commitmentCompressed[len(commitmentCompressed)-1-i])
		if err != nil {
			return fmt.Errorf("convert commitment element %d to bytes: %w", i, err)
		}
		copy(comSerializedBytes[i*16:(i+1)*16], res[16:])
	}
	// proof
	var proofSerialisedBytes [48]uints.U8
	for i := range proofCompressed {
		res, err := conversion.NativeToBytes(api, proofCompressed[len(proofCompressed)-1-i])
		if err != nil {
			return fmt.Errorf("convert proof element %d to bytes: %w", i, err)
		}
		copy(proofSerialisedBytes[i*16:(i+1)*16], res[16:])
	}

	// -- unmarshal compressed commitment and proof into uncompressed points
	g1, err := sw_bls12381.NewG1(api)
	if err != nil {
		return fmt.Errorf("new g1: %w", err)
	}
	commitmentUncompressed, err := g1.UnmarshalCompressed(comSerializedBytes[:])
	if err != nil {
		return fmt.Errorf("unmarshal compressed commitment: %w", err)
	}
	proofUncompressed, err := g1.UnmarshalCompressed(proofSerialisedBytes[:])
	if err != nil {
		return fmt.Errorf("unmarshal compressed proof: %w", err)
	}

	// verify commitment matches versioned_hash
	h, err := sha2.New(api)
	if err != nil {
		return fmt.Errorf("new sha2: %w", err)
	}
	h.Write(comSerializedBytes[:])
	hashedKzg := h.Sum()
	bapi, err := uints.NewBytes(api)
	if err != nil {
		return fmt.Errorf("new uints api: %w", err)
	}
	api.AssertIsEqual(bapi.ValueUnchecked(versionedHashBytes[0]), blobCommitmentVersionKZG)
	for i := 1; i < len(hashedKzg); i++ {
		bapi.AssertIsEqual(hashedKzg[i], versionedHashBytes[i])
	}

	v, err := kzg.NewVerifier[emulated.BLS12381Fr, sw_bls12381.G1Affine, sw_bls12381.G2Affine, sw_bls12381.GTEl](api)
	if err != nil {
		return fmt.Errorf("new kzg verifier: %w", err)
	}

	// -- construct the commitment and opening proof what the interface expects
	kzgCommitment := kzg.Commitment[sw_bls12381.G1Affine]{
		G1El: *commitmentUncompressed,
	}
	kzgOpeningProof := kzg.OpeningProof[sw_bls12381.ScalarField, sw_bls12381.G1Affine]{
		Quotient:     *proofUncompressed,
		ClaimedValue: claimedValue,
	}
	err = v.CheckOpeningProof(kzgCommitment, kzgOpeningProof, evaluationPoint, *fixedKzgSrsVk)
	if err != nil {
		return fmt.Errorf("check opening proof: %w", err)
	}

	// -- check expected values. These are constant values, so we just check that they match the expected values.
	api.AssertIsEqual(expectedBlobSize[0], 0)
	api.AssertIsEqual(expectedBlobSize[1], evmBlockSize)
	api.AssertIsEqual(expectedBlsModulus[0], evmBlsModulusHi)
	api.AssertIsEqual(expectedBlsModulus[1], evmBlsModulusLo)

	return nil
}
