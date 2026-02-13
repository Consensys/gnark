
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import { A } from "a.sol";
import { B } from "b.sol";

/// @title Groth16 verifier template.
/// @notice Supports verifying Groth16 proofs over BLS12-381 using EIP-2537 precompiles.
contract Verifier is IVerifier {

    /// Some of the provided public input values are larger than the field modulus.
    /// @dev Public input elements are not automatically reduced, as this is can be
    /// a dangerous source of bugs.
    error PublicInputNotInField();

    /// The proof is invalid.
    /// @dev This can mean that provided Groth16 proof points are not on their
    /// curves, that pairing equation fails, or that the proof is not for the
    /// provided public input.
    error ProofInvalid();

    // Addresses of precompiles
    uint256 constant PRECOMPILE_MODEXP = 0x05;
    uint256 constant PRECOMPILE_BLS12_G1MSM = 0x0c;
    uint256 constant PRECOMPILE_BLS12_PAIR = 0x0f;

    // BLS12-381 scalar field Fr order R.
    uint256 constant R = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;

    // Groth16 alpha point in G1
    uint256 constant ALPHA_X_HI = 27399597415599139222265716943501986626;
    uint256 constant ALPHA_X_LO = 21840204988570938179276088081736585746653447506680684549479475294151396562560;
    uint256 constant ALPHA_Y_HI = 13647105137113402895638268308043829319;
    uint256 constant ALPHA_Y_LO = 8576233213221359795704271773817683091708190231546913214197825027330623552857;

    // Groth16 beta point in G2 (negated)
    uint256 constant BETA_NEG_X_0_HI = 21176492521066687174093633785945449048;
    uint256 constant BETA_NEG_X_0_LO = 89308220853813031337988562585715682134787103215612740552340794367318940899185;
    uint256 constant BETA_NEG_X_1_HI = 21535505615600875561635447436833706981;
    uint256 constant BETA_NEG_X_1_LO = 65135314412085119825798110283644208296473404033439753199001690302878165006035;
    uint256 constant BETA_NEG_Y_0_HI = 5322847000204968343461937210703451351;
    uint256 constant BETA_NEG_Y_0_LO = 62726679064666789846214930633279096489624151337173270621704170029838075131412;
    uint256 constant BETA_NEG_Y_1_HI = 21531769701000364706693358390636610333;
    uint256 constant BETA_NEG_Y_1_LO = 113276196147916759544647635228501353430032818801370037958603640833387309804438;

    // Groth16 gamma point in G2 (negated)
    uint256 constant GAMMA_NEG_X_0_HI = 15691743282062795678291212462581982038;
    uint256 constant GAMMA_NEG_X_0_LO = 78406370402794264703700096014141232923429208952020825846561391571850474622631;
    uint256 constant GAMMA_NEG_X_1_HI = 26386816130211068692613710407014182969;
    uint256 constant GAMMA_NEG_X_1_LO = 81825238744911498302533841720724364686136265842245361884072085208326207785221;
    uint256 constant GAMMA_NEG_Y_0_HI = 19006756041595244675812163007341429882;
    uint256 constant GAMMA_NEG_Y_0_LO = 88484298211376231685937990093415896272603433310561187199501456035622418310470;
    uint256 constant GAMMA_NEG_Y_1_HI = 13921934068873752033498814886162968540;
    uint256 constant GAMMA_NEG_Y_1_LO = 87147202926914561464132708031781684292625673777783257186957654296810877004185;

    // Groth16 delta point in G2 (negated)
    uint256 constant DELTA_NEG_X_0_HI = 5578741709695646460818358175065091015;
    uint256 constant DELTA_NEG_X_0_LO = 90890307234905994291377350406845400078191838720099297629111430553854709270790;
    uint256 constant DELTA_NEG_X_1_HI = 7254602656137723697259668811362004166;
    uint256 constant DELTA_NEG_X_1_LO = 56873811644193479126503411166715285166090795252571159036196032424645414316322;
    uint256 constant DELTA_NEG_Y_0_HI = 4339529964016388346962384533554656931;
    uint256 constant DELTA_NEG_Y_0_LO = 102959523961430152551257752072757898838363922510002189405105133832280063837672;
    uint256 constant DELTA_NEG_Y_1_HI = 23319075121367817173188337364929092914;
    uint256 constant DELTA_NEG_Y_1_LO = 47823448419070076592312106321382892929804180427701293216254436945258557226288;

    // Constant and public input points
    uint256 constant CONSTANT_X_HI = 5167547184992764185430688182851701364;
    uint256 constant CONSTANT_X_LO = 108510494252674454935693793934999330962171771168629726516074368512474162376667;
    uint256 constant CONSTANT_Y_HI = 10628998235745956785428727811203784883;
    uint256 constant CONSTANT_Y_LO = 61524672944616699122179166245848088498983746368546304255268823967049966422442;
    uint256 constant PUB_0_X_HI = 19069357752092324720775534838071056204;
    uint256 constant PUB_0_X_LO = 113749710162705347840303023515865049264164849703396952692739015377165452676853;
    uint256 constant PUB_0_Y_HI = 21643484938872811192100647134629705092;
    uint256 constant PUB_0_Y_LO = 103915132165891129209469504001447457023403949647045766090858918835010275522684;
    uint256 constant PUB_1_X_HI = 23100447096131408914978900890356819753;
    uint256 constant PUB_1_X_LO = 28668788388325538026963706682129425803954236815454888003800591335811216065116;
    uint256 constant PUB_1_Y_HI = 3373954764315829698751391886975852502;
    uint256 constant PUB_1_Y_LO = 56262661873946771626517173779762108504128688207591429072797307631784943712182;
    uint256 constant PUB_2_X_HI = 6094493824866067791434926244074674652;
    uint256 constant PUB_2_X_LO = 19465125906425762677544727548378761449712023730281169981322054326599165199476;
    uint256 constant PUB_2_Y_HI = 13045602816432349018138395743726550953;
    uint256 constant PUB_2_Y_LO = 59525605003050552012205423997360099305464117690285323730966147862510228770354;

	bytes32 private immutable CHAIN_CONFIG;

	constructor(bytes32 config) {
		CHAIN_CONFIG = config;
  }

    /// Compute the public input linear combination.
    /// @notice Uses BLS12-381 G1 MSM precompile (EIP-2537) for efficient computation.
    /// @notice Computes the multi-scalar-multiplication of the public input
    /// elements and the verification key including the constant term.
    /// @param input The public inputs. These are elements of the scalar field Fr.
    /// @return x_hi The high part of the X coordinate of the resulting G1 point.
    /// @return x_lo The low part of the X coordinate.
    /// @return y_hi The high part of the Y coordinate.
    /// @return y_lo The low part of the Y coordinate.
    function publicInputMSM(uint256[3] calldata input)
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
            // Element 1: PUB_0
            mstore(add(f, 0xa0), PUB_0_X_HI)
            mstore(add(f, 0xc0), PUB_0_X_LO)
            mstore(add(f, 0xe0), PUB_0_Y_HI)
            mstore(add(f, 0x100), PUB_0_Y_LO)
            s := calldataload(input)
            mstore(add(f, 0x120), s)
            success := and(success, lt(s, R))
            // Element 2: PUB_1
            mstore(add(f, 0x140), PUB_1_X_HI)
            mstore(add(f, 0x160), PUB_1_X_LO)
            mstore(add(f, 0x180), PUB_1_Y_HI)
            mstore(add(f, 0x1a0), PUB_1_Y_LO)
            s := calldataload(add(input, 0x20))
            mstore(add(f, 0x1c0), s)
            success := and(success, lt(s, R))
            // Element 3: PUB_2
            mstore(add(f, 0x1e0), PUB_2_X_HI)
            mstore(add(f, 0x200), PUB_2_X_LO)
            mstore(add(f, 0x220), PUB_2_Y_HI)
            mstore(add(f, 0x240), PUB_2_Y_LO)
            s := calldataload(add(input, 0x40))
            mstore(add(f, 0x260), s)
            success := and(success, lt(s, R))

            success := and(success, staticcall(gas(), PRECOMPILE_BLS12_G1MSM, f, 0x280, f, 0x80))

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
    /// @param input the public input field elements in the scalar field Fr.
    /// Elements must be reduced.
    function verifyProof(
        bytes calldata proof,
        uint256[3] calldata input
    ) public view {
        require(proof.length == 384, "invalid proof length");
        (uint256 Lx_hi, uint256 Lx_lo, uint256 Ly_hi, uint256 Ly_lo) = publicInputMSM(input);

        // Verify the Groth16 pairing equation:
        // e(A, B) · e(C, -δ) · e(α, -β) · e(L_pub, -γ) = 1
        //
        // Pairing input: 4 pairs × (G1[128] + G2[256]) = 4 × 384 = 1536 bytes
        bool success;
        assembly ("memory-safe") {
            let f := mload(0x40)

            // Pair 0: e(A, B)
            // A (G1): 96 bytes at proof offset 0x00
            mstore(f, 0)
            calldatacopy(add(f, 0x10), proof.offset, 0x30)
            mstore(add(f, 0x40), 0)
            calldatacopy(add(f, 0x50), add(proof.offset, 0x30), 0x30)
            // B (G2): 192 bytes at proof offset 0x60
            // gnark-crypto serializes G2 as (A1, A0, A1, A0) but EIP-2537 expects (A0, A1, A0, A1)
            // X.A0 (at proof offset 0x90, 2nd component in gnark-crypto serialization)
            mstore(add(f, 0x80), 0)
            calldatacopy(add(f, 0x90), add(proof.offset, 0x90), 0x30)
            // X.A1 (at proof offset 0x60, 1st component in gnark-crypto serialization)
            mstore(add(f, 0xc0), 0)
            calldatacopy(add(f, 0xd0), add(proof.offset, 0x60), 0x30)
            // Y.A0 (at proof offset 0xf0, 4th component in gnark-crypto serialization)
            mstore(add(f, 0x100), 0)
            calldatacopy(add(f, 0x110), add(proof.offset, 0xf0), 0x30)
            // Y.A1 (at proof offset 0xc0, 3rd component in gnark-crypto serialization)
            mstore(add(f, 0x140), 0)
            calldatacopy(add(f, 0x150), add(proof.offset, 0xc0), 0x30)

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
            success := staticcall(gas(), PRECOMPILE_BLS12_PAIR, f, 0x600, f, 0x20)
            success := and(success, mload(f))
        }
        if (!success) {
            // Either proof or verification key invalid.
            // We assume the contract is correctly generated, so the verification key is valid.
            revert ProofInvalid();
        }
    }

	function getConfig() external view returns (bytes32) {
		return CHAIN_CONFIG;
  }
}
