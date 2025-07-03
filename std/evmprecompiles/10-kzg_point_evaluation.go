package evmprecompiles

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	kzg_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/commitments/kzg"
	"github.com/consensys/gnark/std/conversion"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
)

var vk *kzg.VerifyingKey[sw_bls12381.G1Affine, sw_bls12381.G2Affine]

func init() {
	var err error
	vk, err = evmMainnetKzgTrustedSetup()
	if err != nil {
		panic(fmt.Sprintf("failed to load KZG trusted setup: %v", err))
	}
}

const (
	// blobCommitmentVersionKZG is the version byte for the KZG point evaluation precompile.
	blobCommitmentVersionKZG uint8 = 0x01
	// locTrustedSetup is the location of the trusted setup file for the KZG precompile.
	locTrustedSetup = "kzg_trusted_setup.json"
	// evmBlockSize is the size of the SRS used in the KZG precompile. This
	// defines the polynomial degree and therefore the size of the blob. It is also the expected
	// return value of the POINTEVAL precompile.
	evmBlockSize = 4096
)

var (
	// evmBlsModulus is the modulus of the BLS12-381 scalar field in hexadecimal
	// format (without the 0x prefix). It is the expected return value of the POINTEVAL precompile.
	evmBlsModulus = fr.Modulus().Text(16)
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
		res, err := conversion.NativeToBytes(api, versionedHash[i])
		if err != nil {
			return fmt.Errorf("convert versioned hash element %d to bytes: %w", i, err)
		}
		copy(versionedHashBytes[i*16:(i+1)*16], res)
	}

	// commitment
	var comSerializedBytes [48]uints.U8
	for i, v := range commitmentCompressed {
		res, err := conversion.NativeToBytes(api, v)
		if err != nil {
			return fmt.Errorf("convert commitment element %d to bytes: %w", i, err)
		}
		copy(comSerializedBytes[i*16:(i+1)*16], res)
	}
	// proof
	var proofSerialisedBytes [48]uints.U8
	for i, v := range proofCompressed {
		res, err := conversion.NativeToBytes(api, v)
		if err != nil {
			return fmt.Errorf("convert proof element %d to bytes: %w", i, err)
		}
		copy(proofSerialisedBytes[i*16:(i+1)*16], res)
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
	sizeCompressedPoint := fp.Bytes
	h, err := sha2.New(api, hash.WithMinimalLength(sizeCompressedPoint))
	if err != nil {
		return fmt.Errorf("new sha2: %w", err)
	}
	h.Write(comSerializedBytes[:])
	hashedKzg := h.FixedLengthSum(sizeCompressedPoint)
	api.AssertIsEqual(versionedHashBytes[0].Val, blobCommitmentVersionKZG)
	for i := 1; i < len(hashedKzg); i++ {
		api.AssertIsEqual(hashedKzg[i].Val, versionedHashBytes[i].Val)
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
	err = v.CheckOpeningProof(kzgCommitment, kzgOpeningProof, evaluationPoint, *vk)
	if err != nil {
		return fmt.Errorf("check opening proof: %w", err)
	}

	// -- check expected values. These are constant values, so we just check that they match the expected values.
	api.AssertIsEqual(expectedBlobSize[0], 0)
	api.AssertIsEqual(expectedBlobSize[1], evmBlockSize)
	api.AssertIsEqual(expectedBlsModulus[0], evmBlsModulus[16:32])
	api.AssertIsEqual(expectedBlsModulus[1], evmBlsModulus[0:16])

	return nil
}

// trustedSetupJSON represents the trusted setup for the KZG precompile. It is
// used to verify the KZG commitments and openings. The setup is available at
// https://github.com/ethereum/go-ethereum/blob/master/crypto/kzg4844/trusted_setup.json.
// It was generated during the KZG Ceremony.
type trustedSetupJSON struct {
	G1         []string `json:"g1_monomial"`
	G1Lagrange []string `json:"g1_lagrange"`
	G2         []string `json:"g2_monomial"`
}

func parseTrustedSetup(r io.Reader) (*trustedSetupJSON, error) {
	var setup trustedSetupJSON
	dec := json.NewDecoder(r)
	if err := dec.Decode(&setup); err != nil {
		return nil, fmt.Errorf("decode trusted setup: %w", err)
	}
	if len(setup.G1) == 0 || len(setup.G2) == 0 || len(setup.G1Lagrange) == 0 {
		return nil, fmt.Errorf("invalid trusted setup: missing G1 or G2 or G1Lagrange")
	}
	if len(setup.G1) != evmBlockSize || len(setup.G1Lagrange) != evmBlockSize {
		return nil, fmt.Errorf("invalid trusted setup: G1 must have %d elements, got %d", evmBlockSize, len(setup.G1))
	}
	return &setup, nil
}

func (t *trustedSetupJSON) toProvingKey() (*kzg_bls12381.ProvingKey, error) {
	pk := kzg_bls12381.ProvingKey{
		G1: make([]bls12381.G1Affine, len(t.G1)),
	}
	for i, g1 := range t.G1 {
		decoded, err := decodePrefixed(g1)
		if err != nil {
			return nil, fmt.Errorf("decode G1 element %d: %w", i, err)
		}
		nbDec, err := pk.G1[i].SetBytes(decoded)
		if err != nil {
			return nil, fmt.Errorf("set G1 element %d: %w", i, err)
		}
		if nbDec != len(decoded) {
			return nil, fmt.Errorf("set G1 element %d: expected %d bytes, got %d", i, len(decoded), nbDec)
		}
	}
	return &pk, nil
}

func (t *trustedSetupJSON) toVerifyingKey() (*kzg_bls12381.VerifyingKey, error) {
	var vk kzg_bls12381.VerifyingKey
	if len(t.G2) < 2 {
		return nil, fmt.Errorf("invalid trusted setup: G2 must have at least 2 elements")
	}
	if len(t.G1) < 1 {
		return nil, fmt.Errorf("invalid trusted setup: G1 must have at least 1 element")
	}
	decoded, err := decodePrefixed(t.G1[0])
	if err != nil {
		return nil, fmt.Errorf("decode G1 element 0: %w", err)
	}
	nbDec, err := vk.G1.SetBytes(decoded)
	if err != nil {
		return nil, fmt.Errorf("set G1 element 0: %w", err)
	}
	if nbDec != len(decoded) {
		return nil, fmt.Errorf("set G1 element 0: expected %d bytes, got %d", len(decoded), nbDec)
	}
	for i := range 2 {
		decoded, err := decodePrefixed(t.G2[i])
		if err != nil {
			return nil, fmt.Errorf("decode G2 element %d: %w", i, err)
		}
		nbDec, err := vk.G2[i].SetBytes(decoded)
		if err != nil {
			return nil, fmt.Errorf("set G2 element %d: %w", i, err)
		}
		if nbDec != len(decoded) {
			return nil, fmt.Errorf("set G2 element %d: expected %d bytes, got %d", i, len(decoded), nbDec)
		}
		vk.Lines[i] = bls12381.PrecomputeLines(vk.G2[i])
	}
	return &vk, nil
}

func decodePrefixed(line string) ([]byte, error) {
	if !strings.HasPrefix(line, "0x") {
		return nil, fmt.Errorf("invalid prefix in line: %s", line)
	}
	decoded, err := hex.DecodeString(line[2:])
	if err != nil {
		return nil, fmt.Errorf("decode hex string: %w", err)
	}
	return decoded, nil
}

func evmMainnetKzgTrustedSetup() (*kzg.VerifyingKey[sw_bls12381.G1Affine, sw_bls12381.G2Affine], error) {
	f, err := os.Open(locTrustedSetup)
	if err != nil {
		return nil, fmt.Errorf("open trusted setup file: %w", err)
	}
	defer f.Close()
	setup, err := parseTrustedSetup(f)
	if err != nil {
		return nil, fmt.Errorf("parse trusted setup: %w", err)
	}
	vk, err := setup.toVerifyingKey()
	if err != nil {
		return nil, fmt.Errorf("convert trusted setup to verifying key: %w", err)
	}
	vkw, err := kzg.ValueOfVerifyingKeyFixed[sw_bls12381.G1Affine, sw_bls12381.G2Affine](*vk)
	if err != nil {
		return nil, fmt.Errorf("convert verifying key to fixed: %w", err)
	}
	return &vkw, nil
}
