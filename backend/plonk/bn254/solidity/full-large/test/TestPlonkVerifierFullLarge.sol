

pragma solidity ^0.8.0;
    
import {PlonkVerifier} from '../Verifier.sol';


contract TestPlonkVerifier is PlonkVerifier {

    event PrintBool(bool a);

    struct Proof {
        uint256 proof_l_com_x;
        uint256 proof_l_com_y;
        uint256 proof_r_com_x;
        uint256 proof_r_com_y;
        uint256 proof_o_com_x;
        uint256 proof_o_com_y;

        // h = h_0 + x^{n+2}h_1 + x^{2(n+2)}h_2
        uint256 proof_h_0_x;
        uint256 proof_h_0_y;
        uint256 proof_h_1_x;
        uint256 proof_h_1_y;
        uint256 proof_h_2_x;
        uint256 proof_h_2_y;

        // wire values at zeta
        uint256 proof_l_at_zeta;
        uint256 proof_r_at_zeta;
        uint256 proof_o_at_zeta;

        //uint256[STATE_WIDTH-1] permutation_polynomials_at_zeta; // Sσ1(zeta),Sσ2(zeta)
        uint256 proof_s1_at_zeta; // Sσ1(zeta)
        uint256 proof_s2_at_zeta; // Sσ2(zeta)

        //Bn254.G1Point grand_product_commitment;                 // [z(x)]
        uint256 proof_grand_product_commitment_x;
        uint256 proof_grand_product_commitment_y;

        uint256 proof_grand_product_at_zeta_omega;                    // z(w*zeta)
        uint256 proof_quotient_polynomial_at_zeta;                    // t(zeta)
        uint256 proof_linearised_polynomial_at_zeta;               // r(zeta)

        // Folded proof for the opening of H, linearised poly, l, r, o, s_1, s_2, qcp
        uint256 proof_batch_opening_at_zeta_x;            // [Wzeta]
        uint256 proof_batch_opening_at_zeta_y;

        //Bn254.G1Point opening_at_zeta_omega_proof;      // [Wzeta*omega]
        uint256 proof_opening_at_zeta_omega_x;
        uint256 proof_opening_at_zeta_omega_y;
        
        
        uint256 proof_openings_selector_0_commit_api_at_zeta;
        

        
        uint256 proof_selector_0_commit_api_commitment_x;
        uint256 proof_selector_0_commit_api_commitment_y;
        
    }

    function get_proof() internal view
    returns (bytes memory)
    {

        Proof memory proof;

        proof.proof_l_com_x = 21316131943438787451349684055154878394501594242140043371364538509136823862197;
        proof.proof_l_com_y = 6555787162349565122844134317179131325874683044680504318662497024035059733423;
        proof.proof_r_com_x = 974667143149418995023101549181648024245575428212409989716857648608575807983;
        proof.proof_r_com_y = 3275300354372129726951143363478178185568069237968877609713249517616155077671;
        proof.proof_o_com_x = 17912244904401762318264807033496970073377639791188836254067276203091540946036;
        proof.proof_o_com_y = 9478298547072582399703086782590289747351639418485025418971835102406822775044;
        proof.proof_h_0_x = 14830658960136557441644633172381324604651773805359043555873943459608560950903;
        proof.proof_h_0_y = 14869916672628985119350472466451617352081510863353842158268351953253375016933;
        proof.proof_h_1_x = 17094297652048304294510446150015771573165959123780628856506034837579017314785;
        proof.proof_h_1_y = 20081609310305994977644635710648136643280430285080066651370644174997157583247;
        proof.proof_h_2_x = 10946007819595486412235515861903750242376139900714851750633216438137616579205;
        proof.proof_h_2_y = 10481600699716963935868668676371343154051619033585029771288266221843657427606;
        proof.proof_l_at_zeta = 15360826751419198080487999473308498223980509232911017736024301856370837298436;
        proof.proof_r_at_zeta = 8480221501319256809093949868202017870807604998744483853138022130769994503561;
        proof.proof_o_at_zeta = 11407480075865701097539352597758172327641752141057709347968889415158417707579;
        proof.proof_s1_at_zeta = 8544002467616736519914513260437160652387306311066661503200974321431304381763;
        proof.proof_s2_at_zeta = 20664525363168299795484575702273585236286590450710623376443751985441994463190;
        proof.proof_grand_product_commitment_x = 2158341227243622599845461803306171703267015941582730303586137205978014791540;
        proof.proof_grand_product_commitment_y = 634085286698574217533778139064951672665849873842916626655197526210629838262;
        proof.proof_grand_product_at_zeta_omega = 7932289214723127959674898124933373179800894504559103441503270189229919053231;
        proof.proof_quotient_polynomial_at_zeta = 13748044350757018535697566433488775447861028562769101745443887953366474872661;
        proof.proof_linearised_polynomial_at_zeta = 14591651191977544555057811691728384893710717513084039230393863545576516543645;
        proof.proof_batch_opening_at_zeta_x = 19477915266960222064933979623158634498621847775005946733185619385347696108516;
        proof.proof_batch_opening_at_zeta_y = 16794827137592805570651560819317953378719109311580949771064071228569950511461;
        proof.proof_opening_at_zeta_omega_x = 18201238612527109785776421922259618559244403431337928311312126185452021606568;
		proof.proof_opening_at_zeta_omega_y = 8831999806702580223908246963793297117249216885658683564528749900325234069513;
      
        
        proof.proof_openings_selector_0_commit_api_at_zeta = 6785683599871521968586113342209514933400918931020199021980037361850812919839;
        

        
        proof.proof_selector_0_commit_api_commitment_x = 18939971652189459098029731272537976551244775064725306726377830661300575485632;
        proof.proof_selector_0_commit_api_commitment_y = 732015985071000146114203545925168718101809185874932065534444480027957346472;
        

        bytes memory res;
        res = abi.encodePacked(
            proof.proof_l_com_x,
            proof.proof_l_com_y,
            proof.proof_r_com_x,
            proof.proof_r_com_y,
            proof.proof_o_com_x,
            proof.proof_o_com_y,
            proof.proof_h_0_x,
            proof.proof_h_0_y,
            proof.proof_h_1_x,
            proof.proof_h_1_y,
            proof.proof_h_2_x,
            proof.proof_h_2_y
        );
        res = abi.encodePacked(
            res,
            proof.proof_l_at_zeta,
            proof.proof_r_at_zeta,
            proof.proof_o_at_zeta
        );
        res = abi.encodePacked(
            res,
            proof.proof_s1_at_zeta,
            proof.proof_s2_at_zeta,
            proof.proof_grand_product_commitment_x,
            proof.proof_grand_product_commitment_y,
            proof.proof_grand_product_at_zeta_omega,
            proof.proof_quotient_polynomial_at_zeta,
            proof.proof_linearised_polynomial_at_zeta
        );
        res = abi.encodePacked(
            res,
            proof.proof_batch_opening_at_zeta_x,
            proof.proof_batch_opening_at_zeta_y,
            proof.proof_opening_at_zeta_omega_x,
            proof.proof_opening_at_zeta_omega_y
        );

        
        res = abi.encodePacked(res,proof.proof_openings_selector_0_commit_api_at_zeta);
        

        
        res = abi.encodePacked(res,
            proof.proof_selector_0_commit_api_commitment_x,
            proof.proof_selector_0_commit_api_commitment_y
        );
        

        return res;
    }

    function test_verifier() public view {

        uint256[] memory pi = new uint256[](1);
        
        pi[0] = 1664060883222786818042716784912419350393935206186747248579850086637101121681;
        

        bytes memory proof = get_proof();

        bool check_proof = PlonkVerifier.Verify(proof, pi);
        
        require(check_proof, "verification failed!");
    }

}
