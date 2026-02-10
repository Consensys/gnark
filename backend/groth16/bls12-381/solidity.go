package groth16

import (
	"bytes"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// solidityTemplate is the Solidity template for the Groth16 verifier on BLS12-381.
// It uses EIP-2537 precompiles for BLS12-381 operations:
//   - BLS12_G1MSM (0x0c) for multi-scalar multiplication
//   - BLS12_PAIR (0x0f) for pairing checks
//
// BLS12-381 Fp elements are 48 bytes (384 bits), encoded as [hi_uint256 || lo_uint256]
// where hi is the top 16 bytes and lo is the bottom 32 bytes.
// G1 points in EIP-2537 format: 128 bytes (x: 64 bytes padded, y: 64 bytes padded)
// G2 points in EIP-2537 format: 256 bytes (4 × 64 bytes padded coordinates)
const solidityTemplate = `
{{- $numPublic := sub (len .Vk.G1.K) 1 }}
{{- $numCommitments := len .Vk.PublicAndCommitmentCommitted }}
{{- $numWitness := sub $numPublic $numCommitments }}
{{- $PublicAndCommitmentCommitted := .Vk.PublicAndCommitmentCommitted }}
// SPDX-License-Identifier: MIT

pragma solidity {{ .Cfg.PragmaVersion }};
{{- if .Cfg.SortedImports }}
{{ range $imp := .Cfg.SortedImports }}
{{ $imp }}
{{- end }}
{{- end }}

/// @title Groth16 verifier template.
/// @notice Supports verifying Groth16 proofs over BLS12-381 using EIP-2537 precompiles.
/// @notice Proofs are in uncompressed format: Ar (96 bytes G1) + Bs (192 bytes G2) + Krs (96 bytes G1).
contract Verifier{{ .Cfg.InterfaceDeclaration }} {

    /// Some of the provided public input values are larger than the field modulus.
    /// @dev Public input elements are not automatically reduced, as this is can be
    /// a dangerous source of bugs.
    error PublicInputNotInField();

    /// The proof is invalid.
    /// @dev This can mean that provided Groth16 proof points are not on their
    /// curves, that pairing equation fails, or that the proof is not for the
    /// provided public input.
    error ProofInvalid();

    {{- if gt $numCommitments 0 }}
    /// The commitment is invalid
    /// @dev This can mean that provided commitment points and/or proof of knowledge are not on their
    /// curves, that pairing equation fails, or that the commitment and/or proof of knowledge is not for the
    /// commitment key.
    error CommitmentInvalid();
    {{- end }}

    // Addresses of precompiles
    uint256 constant PRECOMPILE_MODEXP = 0x05;
    uint256 constant PRECOMPILE_BLS12_G1MSM = 0x0c;
    uint256 constant PRECOMPILE_BLS12_PAIR = 0x0f;

    // BLS12-381 scalar field Fr order R.
    uint256 constant R = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;

    // Groth16 alpha point in G1
    uint256 constant ALPHA_X_HI = {{ fpstr_hi .Vk.G1.Alpha.X }};
    uint256 constant ALPHA_X_LO = {{ fpstr_lo .Vk.G1.Alpha.X }};
    uint256 constant ALPHA_Y_HI = {{ fpstr_hi .Vk.G1.Alpha.Y }};
    uint256 constant ALPHA_Y_LO = {{ fpstr_lo .Vk.G1.Alpha.Y }};

    // Groth16 beta point in G2 (negated)
    uint256 constant BETA_NEG_X_0_HI = {{ fpstr_hi .Vk.G2.Beta.X.A0 }};
    uint256 constant BETA_NEG_X_0_LO = {{ fpstr_lo .Vk.G2.Beta.X.A0 }};
    uint256 constant BETA_NEG_X_1_HI = {{ fpstr_hi .Vk.G2.Beta.X.A1 }};
    uint256 constant BETA_NEG_X_1_LO = {{ fpstr_lo .Vk.G2.Beta.X.A1 }};
    uint256 constant BETA_NEG_Y_0_HI = {{ fpstr_hi .Vk.G2.Beta.Y.A0 }};
    uint256 constant BETA_NEG_Y_0_LO = {{ fpstr_lo .Vk.G2.Beta.Y.A0 }};
    uint256 constant BETA_NEG_Y_1_HI = {{ fpstr_hi .Vk.G2.Beta.Y.A1 }};
    uint256 constant BETA_NEG_Y_1_LO = {{ fpstr_lo .Vk.G2.Beta.Y.A1 }};

    // Groth16 gamma point in G2 (negated)
    uint256 constant GAMMA_NEG_X_0_HI = {{ fpstr_hi .Vk.G2.Gamma.X.A0 }};
    uint256 constant GAMMA_NEG_X_0_LO = {{ fpstr_lo .Vk.G2.Gamma.X.A0 }};
    uint256 constant GAMMA_NEG_X_1_HI = {{ fpstr_hi .Vk.G2.Gamma.X.A1 }};
    uint256 constant GAMMA_NEG_X_1_LO = {{ fpstr_lo .Vk.G2.Gamma.X.A1 }};
    uint256 constant GAMMA_NEG_Y_0_HI = {{ fpstr_hi .Vk.G2.Gamma.Y.A0 }};
    uint256 constant GAMMA_NEG_Y_0_LO = {{ fpstr_lo .Vk.G2.Gamma.Y.A0 }};
    uint256 constant GAMMA_NEG_Y_1_HI = {{ fpstr_hi .Vk.G2.Gamma.Y.A1 }};
    uint256 constant GAMMA_NEG_Y_1_LO = {{ fpstr_lo .Vk.G2.Gamma.Y.A1 }};

    // Groth16 delta point in G2 (negated)
    uint256 constant DELTA_NEG_X_0_HI = {{ fpstr_hi .Vk.G2.Delta.X.A0 }};
    uint256 constant DELTA_NEG_X_0_LO = {{ fpstr_lo .Vk.G2.Delta.X.A0 }};
    uint256 constant DELTA_NEG_X_1_HI = {{ fpstr_hi .Vk.G2.Delta.X.A1 }};
    uint256 constant DELTA_NEG_X_1_LO = {{ fpstr_lo .Vk.G2.Delta.X.A1 }};
    uint256 constant DELTA_NEG_Y_0_HI = {{ fpstr_hi .Vk.G2.Delta.Y.A0 }};
    uint256 constant DELTA_NEG_Y_0_LO = {{ fpstr_lo .Vk.G2.Delta.Y.A0 }};
    uint256 constant DELTA_NEG_Y_1_HI = {{ fpstr_hi .Vk.G2.Delta.Y.A1 }};
    uint256 constant DELTA_NEG_Y_1_LO = {{ fpstr_lo .Vk.G2.Delta.Y.A1 }};

    {{- if gt $numCommitments 0 }}
    // Pedersen G point in G2
    {{- $cmtVk0 := index .Vk.CommitmentKeys 0 }}
    uint256 constant PEDERSEN_G_X_0_HI = {{ fpstr_hi $cmtVk0.G.X.A0 }};
    uint256 constant PEDERSEN_G_X_0_LO = {{ fpstr_lo $cmtVk0.G.X.A0 }};
    uint256 constant PEDERSEN_G_X_1_HI = {{ fpstr_hi $cmtVk0.G.X.A1 }};
    uint256 constant PEDERSEN_G_X_1_LO = {{ fpstr_lo $cmtVk0.G.X.A1 }};
    uint256 constant PEDERSEN_G_Y_0_HI = {{ fpstr_hi $cmtVk0.G.Y.A0 }};
    uint256 constant PEDERSEN_G_Y_0_LO = {{ fpstr_lo $cmtVk0.G.Y.A0 }};
    uint256 constant PEDERSEN_G_Y_1_HI = {{ fpstr_hi $cmtVk0.G.Y.A1 }};
    uint256 constant PEDERSEN_G_Y_1_LO = {{ fpstr_lo $cmtVk0.G.Y.A1 }};

    // Pedersen GSigmaNeg point in G2
    uint256 constant PEDERSEN_GSIGMANEG_X_0_HI = {{ fpstr_hi $cmtVk0.GSigmaNeg.X.A0 }};
    uint256 constant PEDERSEN_GSIGMANEG_X_0_LO = {{ fpstr_lo $cmtVk0.GSigmaNeg.X.A0 }};
    uint256 constant PEDERSEN_GSIGMANEG_X_1_HI = {{ fpstr_hi $cmtVk0.GSigmaNeg.X.A1 }};
    uint256 constant PEDERSEN_GSIGMANEG_X_1_LO = {{ fpstr_lo $cmtVk0.GSigmaNeg.X.A1 }};
    uint256 constant PEDERSEN_GSIGMANEG_Y_0_HI = {{ fpstr_hi $cmtVk0.GSigmaNeg.Y.A0 }};
    uint256 constant PEDERSEN_GSIGMANEG_Y_0_LO = {{ fpstr_lo $cmtVk0.GSigmaNeg.Y.A0 }};
    uint256 constant PEDERSEN_GSIGMANEG_Y_1_HI = {{ fpstr_hi $cmtVk0.GSigmaNeg.Y.A1 }};
    uint256 constant PEDERSEN_GSIGMANEG_Y_1_LO = {{ fpstr_lo $cmtVk0.GSigmaNeg.Y.A1 }};
    {{- end }}

    // Constant and public input points
    {{- $k0 := index .Vk.G1.K 0}}
    uint256 constant CONSTANT_X_HI = {{ fpstr_hi $k0.X }};
    uint256 constant CONSTANT_X_LO = {{ fpstr_lo $k0.X }};
    uint256 constant CONSTANT_Y_HI = {{ fpstr_hi $k0.Y }};
    uint256 constant CONSTANT_Y_LO = {{ fpstr_lo $k0.Y }};
    {{- range $i, $ki := .Vk.G1.K }}
        {{- if gt $i 0 }}
    uint256 constant PUB_{{sub $i 1}}_X_HI = {{ fpstr_hi $ki.X }};
    uint256 constant PUB_{{sub $i 1}}_X_LO = {{ fpstr_lo $ki.X }};
    uint256 constant PUB_{{sub $i 1}}_Y_HI = {{ fpstr_hi $ki.Y }};
    uint256 constant PUB_{{sub $i 1}}_Y_LO = {{ fpstr_lo $ki.Y }};
        {{- end }}
    {{- end }}
{{- if .Cfg.Constants }}

{{ .Cfg.Constants }}
{{- end }}
{{- if .Cfg.Constructor }}

{{ .Cfg.Constructor }}
{{- end }}

    /// Compute the public input linear combination.
    /// @notice Uses BLS12-381 G1 MSM precompile (EIP-2537) for efficient computation.
    /// @notice Computes the multi-scalar-multiplication of the public input
    /// elements and the verification key including the constant term.
    /// @param input The public inputs. These are elements of the scalar field Fr.
    {{- if gt $numCommitments 0 }}
    /// @param publicCommitments public inputs generated from pedersen commitments.
    /// @param commitments The Pedersen commitments from the proof (padded to 128 bytes each).
    {{- end }}
    /// @return x_hi The high part of the X coordinate of the resulting G1 point.
    /// @return x_lo The low part of the X coordinate.
    /// @return y_hi The high part of the Y coordinate.
    /// @return y_lo The low part of the Y coordinate.
    {{- if eq $numCommitments 0 }}
    function publicInputMSM(uint256[{{$numWitness}}] calldata input)
    {{- else }}
    function publicInputMSM(
        uint256[{{$numWitness}}] calldata input,
        uint256[{{$numCommitments}}] memory publicCommitments,
        uint256[{{mul $numCommitments 4}}] memory commitments
    )
    {{- end }}
    internal view returns (uint256 x_hi, uint256 x_lo, uint256 y_hi, uint256 y_lo) {
        // BLS12_G1MSM input: k elements of (G1_point[128 bytes] + scalar[32 bytes]) = k * 160 bytes
        // Output: one G1 point (128 bytes)
        bool success = true;
        assembly ("memory-safe") {
            let f := mload(0x40)
            let s
            // Element 0: CONSTANT with scalar 1
            mstore(f, CONSTANT_X_HI)
            mstore(add(f, 0x20), CONSTANT_X_LO)
            mstore(add(f, 0x40), CONSTANT_Y_HI)
            mstore(add(f, 0x60), CONSTANT_Y_LO)
            mstore(add(f, 0x80), 1)
            {{- range $i := intRange $numPublic }}
            // Element {{ sum $i 1 }}: PUB_{{$i}}
            mstore(add(f, {{ hex (mul (sum $i 1) 0xa0) }}), PUB_{{$i}}_X_HI)
            mstore(add(f, {{ hex (sum (mul (sum $i 1) 0xa0) 0x20) }}), PUB_{{$i}}_X_LO)
            mstore(add(f, {{ hex (sum (mul (sum $i 1) 0xa0) 0x40) }}), PUB_{{$i}}_Y_HI)
            mstore(add(f, {{ hex (sum (mul (sum $i 1) 0xa0) 0x60) }}), PUB_{{$i}}_Y_LO)
            {{- if lt $i $numWitness }}
            {{- if eq $i 0 }}
            s := calldataload(input)
            {{- else }}
            s := calldataload(add(input, {{ hex (mul $i 0x20) }}))
            {{- end }}
            {{- else }}
            {{- if eq (sub $i $numWitness) 0 }}
            s := mload(publicCommitments)
            {{- else }}
            s := mload(add(publicCommitments, {{ hex (mul 0x20 (sub $i $numWitness)) }}))
            {{- end }}
            {{- end }}
            mstore(add(f, {{ hex (sum (mul (sum $i 1) 0xa0) 0x80) }}), s)
            success := and(success, lt(s, R))
            {{- end }}

            {{- if gt $numCommitments 0 }}
            // Add commitment G1 points with scalar 1
            // Commitments are stored in memory as padded 128-byte G1 points (4 uint256 each)
            {{- range $i := intRange $numCommitments }}
            mstore(add(f, {{ hex (mul (sum $numPublic (sum $i 1)) 0xa0) }}), mload(add(commitments, {{ hex (mul $i 0x80) }})))
            mstore(add(f, {{ hex (sum (mul (sum $numPublic (sum $i 1)) 0xa0) 0x20) }}), mload(add(commitments, {{ hex (sum (mul $i 0x80) 0x20) }})))
            mstore(add(f, {{ hex (sum (mul (sum $numPublic (sum $i 1)) 0xa0) 0x40) }}), mload(add(commitments, {{ hex (sum (mul $i 0x80) 0x40) }})))
            mstore(add(f, {{ hex (sum (mul (sum $numPublic (sum $i 1)) 0xa0) 0x60) }}), mload(add(commitments, {{ hex (sum (mul $i 0x80) 0x60) }})))
            mstore(add(f, {{ hex (sum (mul (sum $numPublic (sum $i 1)) 0xa0) 0x80) }}), 1)
            {{- end }}
            {{- end }}

            success := and(success, staticcall(gas(), PRECOMPILE_BLS12_G1MSM, f, {{ hex (mul (sum (sum $numPublic 1) $numCommitments) 0xa0) }}, f, 0x80))

            x_hi := mload(f)
            x_lo := mload(add(f, 0x20))
            y_hi := mload(add(f, 0x40))
            y_lo := mload(add(f, 0x60))
        }
        if (!success) {
            // Either Public input not in field, or verification key invalid.
            // We assume the contract is correctly generated, so the verification key is valid.
            revert PublicInputNotInField();
        }
    }

    /// Verify an uncompressed Groth16 proof.
    /// @notice Reverts with InvalidProof if the proof is invalid or
    /// with PublicInputNotInField the public input is not reduced.
    /// @notice There is no return value. If the function does not revert, the
    /// proof was successfully verified.
    /// @param proof the serialized proof, containing Ar (96 bytes G1), Bs (192 bytes G2),
    /// Krs (96 bytes G1) = 384 bytes total.
    {{- if gt $numCommitments 0 }}
    /// Followed by commitments ({{$numCommitments}} × 96 bytes G1) and commitmentPok (96 bytes G1).
    {{- end }}
    /// @param input the public input field elements in the scalar field Fr.
    /// Elements must be reduced.
    function verifyProof(
        bytes calldata proof,
        uint256[{{$numWitness}}] calldata input
    ) public view {
        {{- if gt $numCommitments 0 }}
        require(proof.length == {{ sum 384 (mul (sum $numCommitments 1) 96) }}, "invalid proof length");
        {{- else }}
        require(proof.length == 384, "invalid proof length");
        {{- end }}

        {{- if gt $numCommitments 0 }}
        // Load commitment points and compute public commitment hashes
        uint256[{{$numCommitments}}] memory publicCommitments;
        uint256[{{mul $numCommitments 4}}] memory commitments;

        // Load commitment points from proof (padded to 128 bytes each in memory)
        assembly ("memory-safe") {
            {{- range $i := intRange $numCommitments }}
            // Commitment {{$i}}: load raw 96-byte G1 from calldata, pad to 128 bytes
            mstore(add(commitments, {{ hex (mul $i 0x80) }}), 0)
            calldatacopy(add(commitments, {{ hex (sum (mul $i 0x80) 0x10) }}), add(proof.offset, {{ hex (sum 0x180 (mul $i 0x60)) }}), 0x30)
            mstore(add(commitments, {{ hex (sum (mul $i 0x80) 0x40) }}), 0)
            calldatacopy(add(commitments, {{ hex (sum (mul $i 0x80) 0x50) }}), add(proof.offset, {{ hex (sum 0x1b0 (mul $i 0x60)) }}), 0x30)
            {{- end }}
        }

        // Compute public commitment hashes
        uint256[] memory publicAndCommitmentCommitted;
        {{- range $i := intRange $numCommitments }}
        {{- $pcIndex := index $PublicAndCommitmentCommitted $i }}
        {{- if gt (len $pcIndex) 0 }}
        publicAndCommitmentCommitted = new uint256[]({{ len $pcIndex }});
        assembly ("memory-safe") {
            let publicAndCommitmentCommittedOffset := add(publicAndCommitmentCommitted, 0x20)
            {{- $segment_start := index $pcIndex 0 }}
            {{- $segment_end := index $pcIndex 0 }}
            {{- $l := 0 }}
            {{- range $k := intRange (sub (len $pcIndex) 1) }}
                {{- $next := index $pcIndex (sum $k 1) }}
                {{- if ne $next (sum $segment_end 1) }}
            calldatacopy(add(publicAndCommitmentCommittedOffset, {{ mul $l 0x20 }}), add(input, {{ mul 0x20 (sub $segment_start 1) }}), {{ mul 0x20 (sum 1 (sub $segment_end $segment_start)) }})
                    {{- $segment_start = $next }}
                    {{- $l = (sum $k 1) }}
                {{- end }}
                {{- $segment_end = $next }}
            {{- end }}
            calldatacopy(add(publicAndCommitmentCommittedOffset, {{ mul $l 0x20 }}), add(input, {{ mul 0x20 (sub $segment_start 1) }}), {{ mul 0x20 (sum 1 (sub $segment_end $segment_start)) }})
        }
        {{- end }}

        // Hash: keccak256(commitment_raw_bytes || publicAndCommitmentCommitted) % R
        // The commitment raw bytes are 96 bytes from calldata
        {
            bytes memory hashInput = abi.encodePacked(
                proof[{{ sum 0x180 (mul $i 0x60) }}:{{ sum 0x1e0 (mul $i 0x60) }}],
                publicAndCommitmentCommitted
            );
            publicCommitments[{{$i}}] = uint256({{ hashFnName }}(hashInput)) % R;
        }
        {{- end }}

        // Verify Pedersen commitments
        {
            bool commitSuccess;
            assembly ("memory-safe") {
                let f := mload(0x40)

                // Pair 0: e(commitment, GSigmaNeg)
                // Load commitment G1 point (already padded in commitments memory)
                mcopy(f, commitments, 0x80)
                // GSigmaNeg G2 point
                mstore(add(f, 0x80), PEDERSEN_GSIGMANEG_X_0_HI)
                mstore(add(f, 0xa0), PEDERSEN_GSIGMANEG_X_0_LO)
                mstore(add(f, 0xc0), PEDERSEN_GSIGMANEG_X_1_HI)
                mstore(add(f, 0xe0), PEDERSEN_GSIGMANEG_X_1_LO)
                mstore(add(f, 0x100), PEDERSEN_GSIGMANEG_Y_0_HI)
                mstore(add(f, 0x120), PEDERSEN_GSIGMANEG_Y_0_LO)
                mstore(add(f, 0x140), PEDERSEN_GSIGMANEG_Y_1_HI)
                mstore(add(f, 0x160), PEDERSEN_GSIGMANEG_Y_1_LO)

                // Pair 1: e(Pok, G)
                // Load PoK from proof calldata (96 bytes at offset after commitments)
                mstore(add(f, 0x180), 0)
                calldatacopy(add(f, 0x190), add(proof.offset, {{ hex (sum 0x180 (mul $numCommitments 0x60)) }}), 0x30)
                mstore(add(f, 0x1c0), 0)
                calldatacopy(add(f, 0x1d0), add(proof.offset, {{ hex (sum 0x1b0 (mul $numCommitments 0x60)) }}), 0x30)
                // G point
                mstore(add(f, 0x200), PEDERSEN_G_X_0_HI)
                mstore(add(f, 0x220), PEDERSEN_G_X_0_LO)
                mstore(add(f, 0x240), PEDERSEN_G_X_1_HI)
                mstore(add(f, 0x260), PEDERSEN_G_X_1_LO)
                mstore(add(f, 0x280), PEDERSEN_G_Y_0_HI)
                mstore(add(f, 0x2a0), PEDERSEN_G_Y_0_LO)
                mstore(add(f, 0x2c0), PEDERSEN_G_Y_1_HI)
                mstore(add(f, 0x2e0), PEDERSEN_G_Y_1_LO)

                // BLS12_PAIR: 2 pairs × 384 bytes = 768 bytes
                commitSuccess := staticcall(gas(), PRECOMPILE_BLS12_PAIR, f, 0x300, f, 0x20)
                commitSuccess := and(commitSuccess, mload(f))
            }
            if (!commitSuccess) {
                revert CommitmentInvalid();
            }
        }

        (uint256 Lx_hi, uint256 Lx_lo, uint256 Ly_hi, uint256 Ly_lo) = publicInputMSM(
            input,
            publicCommitments,
            commitments
        );
        {{- else }}
        (uint256 Lx_hi, uint256 Lx_lo, uint256 Ly_hi, uint256 Ly_lo) = publicInputMSM(input);
        {{- end }}

        // Verify the Groth16 pairing equation:
        // e(A, B) · e(C, -δ) · e(α, -β) · e(L_pub, -γ) = 1
        //
        // Pairing input: 4 pairs × (G1[128] + G2[256]) = 4 × 384 = 1536 bytes
        {{- if eq $numCommitments 0 }}
        bool success;
        {{- end }}
        assembly ("memory-safe") {
            let f := mload(0x40)

            // Pair 0: e(A, B)
            // A (G1): 96 bytes at proof offset 0x00
            mstore(f, 0)
            calldatacopy(add(f, 0x10), proof.offset, 0x30)
            mstore(add(f, 0x40), 0)
            calldatacopy(add(f, 0x50), add(proof.offset, 0x30), 0x30)
            // B (G2): 192 bytes at proof offset 0x60
            // X.A0
            mstore(add(f, 0x80), 0)
            calldatacopy(add(f, 0x90), add(proof.offset, 0x60), 0x30)
            // X.A1
            mstore(add(f, 0xc0), 0)
            calldatacopy(add(f, 0xd0), add(proof.offset, 0x90), 0x30)
            // Y.A0
            mstore(add(f, 0x100), 0)
            calldatacopy(add(f, 0x110), add(proof.offset, 0xc0), 0x30)
            // Y.A1
            mstore(add(f, 0x140), 0)
            calldatacopy(add(f, 0x150), add(proof.offset, 0xf0), 0x30)

            // Pair 1: e(C, -δ)
            // C (G1): 96 bytes at proof offset 0x120
            mstore(add(f, 0x180), 0)
            calldatacopy(add(f, 0x190), add(proof.offset, 0x120), 0x30)
            mstore(add(f, 0x1c0), 0)
            calldatacopy(add(f, 0x1d0), add(proof.offset, 0x150), 0x30)
            // -δ (constant G2)
            mstore(add(f, 0x200), DELTA_NEG_X_0_HI)
            mstore(add(f, 0x220), DELTA_NEG_X_0_LO)
            mstore(add(f, 0x240), DELTA_NEG_X_1_HI)
            mstore(add(f, 0x260), DELTA_NEG_X_1_LO)
            mstore(add(f, 0x280), DELTA_NEG_Y_0_HI)
            mstore(add(f, 0x2a0), DELTA_NEG_Y_0_LO)
            mstore(add(f, 0x2c0), DELTA_NEG_Y_1_HI)
            mstore(add(f, 0x2e0), DELTA_NEG_Y_1_LO)

            // Pair 2: e(α, -β)
            mstore(add(f, 0x300), ALPHA_X_HI)
            mstore(add(f, 0x320), ALPHA_X_LO)
            mstore(add(f, 0x340), ALPHA_Y_HI)
            mstore(add(f, 0x360), ALPHA_Y_LO)
            mstore(add(f, 0x380), BETA_NEG_X_0_HI)
            mstore(add(f, 0x3a0), BETA_NEG_X_0_LO)
            mstore(add(f, 0x3c0), BETA_NEG_X_1_HI)
            mstore(add(f, 0x3e0), BETA_NEG_X_1_LO)
            mstore(add(f, 0x400), BETA_NEG_Y_0_HI)
            mstore(add(f, 0x420), BETA_NEG_Y_0_LO)
            mstore(add(f, 0x440), BETA_NEG_Y_1_HI)
            mstore(add(f, 0x460), BETA_NEG_Y_1_LO)

            // Pair 3: e(L_pub, -γ)
            mstore(add(f, 0x480), Lx_hi)
            mstore(add(f, 0x4a0), Lx_lo)
            mstore(add(f, 0x4c0), Ly_hi)
            mstore(add(f, 0x4e0), Ly_lo)
            mstore(add(f, 0x500), GAMMA_NEG_X_0_HI)
            mstore(add(f, 0x520), GAMMA_NEG_X_0_LO)
            mstore(add(f, 0x540), GAMMA_NEG_X_1_HI)
            mstore(add(f, 0x560), GAMMA_NEG_X_1_LO)
            mstore(add(f, 0x580), GAMMA_NEG_Y_0_HI)
            mstore(add(f, 0x5a0), GAMMA_NEG_Y_0_LO)
            mstore(add(f, 0x5c0), GAMMA_NEG_Y_1_HI)
            mstore(add(f, 0x5e0), GAMMA_NEG_Y_1_LO)

            // BLS12_PAIR: 4 pairs × 384 bytes = 1536 bytes
            {{- if gt $numCommitments 0 }}
            let success
            {{- end }}
            success := staticcall(gas(), PRECOMPILE_BLS12_PAIR, f, 0x600, f, 0x20)
            success := and(success, mload(f))
        }
        if (!success) {
            // Either proof or verification key invalid.
            // We assume the contract is correctly generated, so the verification key is valid.
            revert ProofInvalid();
        }
    }
{{- if .Cfg.Functions }}

{{ .Cfg.Functions }}
{{- end }}
}
`

// MarshalSolidity converts a proof to a byte array that can be used in a
// Solidity contract.
// The proof is encoded as:
//   - Ar (G1): 96 bytes (uncompressed)
//   - Bs (G2): 192 bytes (uncompressed)
//   - Krs (G1): 96 bytes (uncompressed)
//
// Total: 384 bytes without commitments.
// If commitments are present, they are appended as:
//   - Commitments: numCommitments × 96 bytes (G1 points)
//   - CommitmentPok: 96 bytes (G1 point)
func (proof *Proof) MarshalSolidity() []byte {
	var buf bytes.Buffer
	_, err := proof.WriteRawTo(&buf)
	if err != nil {
		panic(err)
	}

	// If there are no commitments, we can return only Ar | Bs | Krs
	if len(proof.Commitments) > 0 {
		return buf.Bytes()
	} else {
		return buf.Bytes()[:8*fr.Bytes]
	}
}
