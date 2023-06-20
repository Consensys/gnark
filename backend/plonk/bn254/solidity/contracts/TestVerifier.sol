

pragma solidity ^0.8.0;
    
import {PlonkVerifier} from './Verifier.sol';


contract TestVerifier {

    using PlonkVerifier for *;

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
        
        uint256 proof_openings_selector_1_commit_api_at_zeta;
        

        
        uint256 proof_selector_0_commit_api_commitment_x;
        uint256 proof_selector_0_commit_api_commitment_y;
        
        uint256 proof_selector_1_commit_api_commitment_x;
        uint256 proof_selector_1_commit_api_commitment_y;
        
    }

    function get_proof() internal view
    returns (bytes memory)
    {

        Proof memory proof;

        proof.proof_l_com_x = 21253308373531120892771008608936632223314340944514232304464950787752900356290;
        proof.proof_l_com_y = 10535998046011754535590878265155274710576321384603563160369287610538540542930;
        proof.proof_r_com_x = 11064690958509538594513859914357333379950817973176183815555633868299248270967;
        proof.proof_r_com_y = 15532293309481831919098895462081136877037217645928922936402904770189620947510;
        proof.proof_o_com_x = 19219663745118035665220668735857826694187182931229873622562132158490832230177;
        proof.proof_o_com_y = 8687485892746541293752084969380975557007684160899397076828919167184086602169;
        proof.proof_h_0_x = 9571153184019024284647696257360800486149725109249925965893487719225856074910;
        proof.proof_h_0_y = 12401681243884877057500341879667975548579801519265738003000120242910930561097;
        proof.proof_h_1_x = 1953744091268515074237243771135552516306356258654583599472451887542944524459;
        proof.proof_h_1_y = 1868901506937098098188084600188150165092557688034036930844318797590179581178;
        proof.proof_h_2_x = 20238425102086496573064494177404632722612415556299548086404680163274547259313;
        proof.proof_h_2_y = 10335519316610746198326915597689655140735080473640902540072712043328490711506;
        proof.proof_l_at_zeta = 14104053505050155751803097044732606350227504461184766721426436629306239463872;
        proof.proof_r_at_zeta = 10433005157014770460151878907166189981906766104165644460201314288497966596566;
        proof.proof_o_at_zeta = 9846744684843831072802083958094755252954443990357838001360593193260831808596;
        proof.proof_s1_at_zeta = 15555012095955943083537681548331201403577767109241162811693525393913306682079;
        proof.proof_s2_at_zeta = 14951705153113614778000628592552324841511262507088228966974409804521043475274;
        proof.proof_grand_product_commitment_x = 2323517602805470284794287464853042634145441093806571236551218201687778608752;
        proof.proof_grand_product_commitment_y = 15298605171424632323491491638485712884821662883255542695832932544361707049427;
        proof.proof_grand_product_at_zeta_omega = 12504478826209308590948652686752977527674055724289356965273655095952263069039;
        proof.proof_quotient_polynomial_at_zeta = 7208405667065829530015084346586210565618311077471981089158838565679099581440;
        proof.proof_linearised_polynomial_at_zeta = 2063622507152319136964691917609727771634244596691551665308346951670060551896;
        proof.proof_batch_opening_at_zeta_x = 7927355479607269873059506455764382467985205379062485126426595350812755775575;
        proof.proof_batch_opening_at_zeta_y = 3215275782170130624814039928749805394182819807041249080655810793664583001136;
        proof.proof_opening_at_zeta_omega_x = 4628230158304379242204022046670683735586133613219251354946468755297561779616;
		proof.proof_opening_at_zeta_omega_y = 18811488058576223930903249922798186323306445096866042531881990919789073128450;
      
        
        proof.proof_openings_selector_0_commit_api_at_zeta = 10496809863858258816525797281761026096852390146653276946533535749066163960103;
        
        proof.proof_openings_selector_1_commit_api_at_zeta = 309290459819868930148490893519542499370632666157314464487161490935606776195;
        

        
        proof.proof_selector_0_commit_api_commitment_x = 19492865698036112114775502983476158019950305551606979194964416960132605056733;
        proof.proof_selector_0_commit_api_commitment_y = 5862105632233705616920628400256634503201489947391484321943175721779867490621;
        
        proof.proof_selector_1_commit_api_commitment_x = 17249337471609904820705426563973411537474604750554421818424471715993839149988;
        proof.proof_selector_1_commit_api_commitment_y = 10275258083954472932844466742501248307743808796368487043367540098928130390406;
        

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
        
        res = abi.encodePacked(res,proof.proof_openings_selector_1_commit_api_at_zeta);
        

        
        res = abi.encodePacked(res,
            proof.proof_selector_0_commit_api_commitment_x,
            proof.proof_selector_0_commit_api_commitment_y
        );
        
        res = abi.encodePacked(res,
            proof.proof_selector_1_commit_api_commitment_x,
            proof.proof_selector_1_commit_api_commitment_y
        );
        

        return res;
    }

    function test_verifier_go(bytes memory proof, uint256[] memory public_inputs) public {
        bool check_proof = PlonkVerifier.Verify(proof, public_inputs);
        require(check_proof, "verification failed!");
    }

    function test_verifier() public {

        uint256[] memory pi = new uint256[](1);
        
        pi[0] = 32;
        

        bytes memory proof = get_proof();

        bool check_proof = PlonkVerifier.Verify(proof, pi);
        emit PrintBool(check_proof);
        require(check_proof, "verification failed!");
    }

}
