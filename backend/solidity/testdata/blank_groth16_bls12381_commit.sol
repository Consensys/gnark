
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/// @title Groth16 verifier template.
/// @notice Supports verifying Groth16 proofs over BLS12-381 using EIP-2537 precompiles.
contract Verifier {

    /// Some of the provided public input values are larger than the field modulus.
    /// @dev Public input elements are not automatically reduced, as this is can be
    /// a dangerous source of bugs.
    error PublicInputNotInField();

    /// The proof is invalid.
    /// @dev This can mean that provided Groth16 proof points are not on their
    /// curves, that pairing equation fails, or that the proof is not for the
    /// provided public input.
    error ProofInvalid();
    /// The commitment is invalid
    /// @dev This can mean that provided commitment points and/or proof of knowledge are not on their
    /// curves, that pairing equation fails, or that the commitment and/or proof of knowledge is not for the
    /// commitment key.
    error CommitmentInvalid();

    // Addresses of precompiles
    uint256 constant PRECOMPILE_MODEXP = 0x05;
    uint256 constant PRECOMPILE_BLS12_G1MSM = 0x0c;
    uint256 constant PRECOMPILE_BLS12_PAIR = 0x0f;

    // BLS12-381 scalar field Fr order R.
    uint256 constant R = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;

    // Groth16 alpha point in G1
    uint256 constant ALPHA_X_HI = 1680533512927730731411175959098290342;
    uint256 constant ALPHA_X_LO = 18239450089451482012012210240804115427288496596419644960582239678905481504648;
    uint256 constant ALPHA_Y_HI = 17146542094077956706109679955897042875;
    uint256 constant ALPHA_Y_LO = 102126969141789293857115551512473922767030226340968551581956969459999094482488;

    // Groth16 beta point in G2 (negated)
    uint256 constant BETA_NEG_X_0_HI = 9745259689454909520408762138274665555;
    uint256 constant BETA_NEG_X_0_LO = 50111537185101392082366065241727525570554114521018148686282600720297107770628;
    uint256 constant BETA_NEG_X_1_HI = 29907351326996648740409347592984715916;
    uint256 constant BETA_NEG_X_1_LO = 106381970096556002976201629876569491037407140154679205662877789502034523335568;
    uint256 constant BETA_NEG_Y_0_HI = 16078198276019425533297081308032552444;
    uint256 constant BETA_NEG_Y_0_LO = 52064812306631243591034499579185911214519777657632869200404105007620778840807;
    uint256 constant BETA_NEG_Y_1_HI = 11803166487366906202433583363204424712;
    uint256 constant BETA_NEG_Y_1_LO = 54349887174301543788496322179153670290380757745087519667393043714150897717929;

    // Groth16 gamma point in G2 (negated)
    uint256 constant GAMMA_NEG_X_0_HI = 32136062683610919110092092471629517032;
    uint256 constant GAMMA_NEG_X_0_LO = 72926460214580295496233737164253220801048229619146046299535786952572916645796;
    uint256 constant GAMMA_NEG_X_1_HI = 9932366286904363872885375364160941782;
    uint256 constant GAMMA_NEG_X_1_LO = 97494299935308557064475975958224954959226026916999615565945950429042887322004;
    uint256 constant GAMMA_NEG_Y_0_HI = 16893482060892086089972260447927264381;
    uint256 constant GAMMA_NEG_Y_0_LO = 73849979467794887719976092967593501814450630311305102360927790531795380627391;
    uint256 constant GAMMA_NEG_Y_1_HI = 30418506672503874210304059786317682897;
    uint256 constant GAMMA_NEG_Y_1_LO = 12270932289367620956700987920394833369305939681664908386600973675150110589090;

    // Groth16 delta point in G2 (negated)
    uint256 constant DELTA_NEG_X_0_HI = 20253408931078010569772627351719233090;
    uint256 constant DELTA_NEG_X_0_LO = 11509856876545254155170429917505656161757789334122610213139510434733805641188;
    uint256 constant DELTA_NEG_X_1_HI = 29585041568530586290733506486223193941;
    uint256 constant DELTA_NEG_X_1_LO = 27899073693949213029768735357972449673682597353807889766784029466798646799494;
    uint256 constant DELTA_NEG_Y_0_HI = 4331142530994641213228799440893283596;
    uint256 constant DELTA_NEG_Y_0_LO = 115375050532412546659808045650290662439004063894766471595690812360129949877538;
    uint256 constant DELTA_NEG_Y_1_HI = 2676151160118258826077306977083973497;
    uint256 constant DELTA_NEG_Y_1_LO = 74190344560897801569498432771547761905297159773534027331745104258384492647627;
    // Pedersen G point in G2
    uint256 constant PEDERSEN_G_X_0_HI = 3050427109069259830175956041553059308;
    uint256 constant PEDERSEN_G_X_0_LO = 46175470030813298530901485867923890998742090134610351980585330809881300602382;
    uint256 constant PEDERSEN_G_X_1_HI = 10889265119565576125690589675739228605;
    uint256 constant PEDERSEN_G_X_1_LO = 70735640352580884754615749329781568005194036530949309334996771201738572323087;
    uint256 constant PEDERSEN_G_Y_0_HI = 8745313415388601731853659578047343098;
    uint256 constant PEDERSEN_G_Y_0_LO = 7044315734615500874957700930010873128083998036465917476260548340336548638188;
    uint256 constant PEDERSEN_G_Y_1_HI = 26357572651715733673484379197746304614;
    uint256 constant PEDERSEN_G_Y_1_LO = 87647846252615934449734938037212133843784684919441321051395935837614351244916;

    // Pedersen GSigmaNeg point in G2
    uint256 constant PEDERSEN_GSIGMANEG_X_0_HI = 1830317195010557919546768748021128203;
    uint256 constant PEDERSEN_GSIGMANEG_X_0_LO = 8703544788349682509008293719898009413196580884915576321397161713026972212141;
    uint256 constant PEDERSEN_GSIGMANEG_X_1_HI = 21553251166511326413548034269975382412;
    uint256 constant PEDERSEN_GSIGMANEG_X_1_LO = 51754563716557278403353191068973620703964071294473472198570713777872775830843;
    uint256 constant PEDERSEN_GSIGMANEG_Y_0_HI = 19360927747982923948476879458696020866;
    uint256 constant PEDERSEN_GSIGMANEG_Y_0_LO = 66508884173064261492904694466754801692868988566159186214734274713450576592098;
    uint256 constant PEDERSEN_GSIGMANEG_Y_1_HI = 8338176877122441581599741696928128575;
    uint256 constant PEDERSEN_GSIGMANEG_Y_1_LO = 103131764313006684492133980167041753933200100719061008520313111325193511217303;

    // Constant and public input points
    uint256 constant CONSTANT_X_HI = 3255106553146612268630998369629940886;
    uint256 constant CONSTANT_X_LO = 20568233056946217673840711028385521737513585103336668061131455589726461395725;
    uint256 constant CONSTANT_Y_HI = 16629789276462984357953700415960812583;
    uint256 constant CONSTANT_Y_LO = 77356845875414494809999901187949179453086817382767977724607953199681228005313;
    uint256 constant PUB_0_X_HI = 8333684776353816034901931712937154584;
    uint256 constant PUB_0_X_LO = 53470156239714231459442677274442017030318309967112521150774989833355109688669;
    uint256 constant PUB_0_Y_HI = 13567524703101523276671035076044922218;
    uint256 constant PUB_0_Y_LO = 10642886304909988827210972752820706625415942160529405787695727072731546110677;
    uint256 constant PUB_1_X_HI = 18556745771070486656502523677402438380;
    uint256 constant PUB_1_X_LO = 18107927511161805518660767974035151753157569290630484467364000657109283990933;
    uint256 constant PUB_1_Y_HI = 16405488654053522548788848199813136450;
    uint256 constant PUB_1_Y_LO = 38111669932556631059427987484068288401004046794855323127717296667302661386447;
    uint256 constant PUB_2_X_HI = 18789033534054586930234893626741620046;
    uint256 constant PUB_2_X_LO = 51884418575326422443595934070538867193751569452797545255407709298366664306060;
    uint256 constant PUB_2_Y_HI = 3669731434187448574114421598821393886;
    uint256 constant PUB_2_Y_LO = 13958793287340944914054399936271121861553689989720576976831353250343128765014;
    uint256 constant PUB_3_X_HI = 14129118152013300270056356374912591439;
    uint256 constant PUB_3_X_LO = 80401289521800672993370317668718050200752778540159558595675925344897044083829;
    uint256 constant PUB_3_Y_HI = 33132529192783134861072445944452522396;
    uint256 constant PUB_3_Y_LO = 40813229779836196324762177947000943661085672264457404407752765470715769940147;

    /// Compute the public input linear combination.
    /// @notice Uses BLS12-381 G1 MSM precompile (EIP-2537) for efficient computation.
    /// @notice Computes the multi-scalar-multiplication of the public input
    /// elements and the verification key including the constant term.
    /// @param input The public inputs. These are elements of the scalar field Fr.
    /// @param publicCommitments public inputs generated from pedersen commitments.
    /// @param commitments The Pedersen commitments from the proof (padded to 128 bytes each).
    /// @return x_hi The high part of the X coordinate of the resulting G1 point.
    /// @return x_lo The low part of the X coordinate.
    /// @return y_hi The high part of the Y coordinate.
    /// @return y_lo The low part of the Y coordinate.
    function publicInputMSM(
        uint256[3] calldata input,
        uint256[1] memory publicCommitments,
        uint256[4] memory commitments
    )
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
            // Element 4: PUB_3
            mstore(add(f, 0x280), PUB_3_X_HI)
            mstore(add(f, 0x2a0), PUB_3_X_LO)
            mstore(add(f, 0x2c0), PUB_3_Y_HI)
            mstore(add(f, 0x2e0), PUB_3_Y_LO)
            s := mload(publicCommitments)
            mstore(add(f, 0x300), s)
            success := and(success, lt(s, R))
            // Add commitment G1 points with scalar 1
            // Commitments are stored in memory as padded 128-byte G1 points (4 uint256 each)
            mstore(add(f, 0x320), mload(add(commitments, 0x0)))
            mstore(add(f, 0x340), mload(add(commitments, 0x20)))
            mstore(add(f, 0x360), mload(add(commitments, 0x40)))
            mstore(add(f, 0x380), mload(add(commitments, 0x60)))
            mstore(add(f, 0x3a0), 1)

            success := and(success, staticcall(gas(), PRECOMPILE_BLS12_G1MSM, f, 0x3c0, f, 0x80))

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
    /// Followed by commitments (1 × 96 bytes G1) and commitmentPok (96 bytes G1).
    /// @param input the public input field elements in the scalar field Fr.
    /// Elements must be reduced.
    function verifyProof(
        bytes calldata proof,
        uint256[3] calldata input
    ) public view {
        require(proof.length == 576, "invalid proof length");
        // Load commitment points and compute public commitment hashes
        uint256[1] memory publicCommitments;
        uint256[4] memory commitments;

        // Load commitment points from proof (padded to 128 bytes each in memory)
        assembly ("memory-safe") {
            // Commitment 0: load raw 96-byte G1 from calldata, pad to 128 bytes
            mstore(add(commitments, 0x0), 0)
            calldatacopy(add(commitments, 0x10), add(proof.offset, 0x180), 0x30)
            mstore(add(commitments, 0x40), 0)
            calldatacopy(add(commitments, 0x50), add(proof.offset, 0x1b0), 0x30)
        }

        // Compute public commitment hashes
        uint256[] memory publicAndCommitmentCommitted;

        // Hash: keccak256(commitment_raw_bytes || publicAndCommitmentCommitted) % R
        // The commitment raw bytes are 96 bytes from calldata
        {
            bytes memory hashInput = abi.encodePacked(
                proof[384:480],
                publicAndCommitmentCommitted
            );
            publicCommitments[0] = uint256(keccak256(hashInput)) % R;
        }

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
                calldatacopy(add(f, 0x190), add(proof.offset, 0x1e0), 0x30)
                mstore(add(f, 0x1c0), 0)
                calldatacopy(add(f, 0x1d0), add(proof.offset, 0x210), 0x30)
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

        // Verify the Groth16 pairing equation:
        // e(A, B) · e(C, -δ) · e(α, -β) · e(L_pub, -γ) = 1
        //
        // Pairing input: 4 pairs × (G1[128] + G2[256]) = 4 × 384 = 1536 bytes
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
            let success
            success := staticcall(gas(), PRECOMPILE_BLS12_PAIR, f, 0x600, f, 0x20)
            success := and(success, mload(f))
        }
        if (!success) {
            // Either proof or verification key invalid.
            // We assume the contract is correctly generated, so the verification key is valid.
            revert ProofInvalid();
        }
    }
}
