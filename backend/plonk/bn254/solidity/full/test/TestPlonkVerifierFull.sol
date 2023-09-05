

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

        proof.proof_l_com_x = 16809003152472908539366366472110862815908064100394334593553909594358495270251;
        proof.proof_l_com_y = 15096139330736090768564216961986475960297783720885382175702955991380182184620;
        proof.proof_r_com_x = 21796354740759555056977306743994675418872494453071850341619923152373557041885;
        proof.proof_r_com_y = 20211564230399964124969819299851467049685332113171616097432519121259276804134;
        proof.proof_o_com_x = 7749651839026797670912417555114334377103590574852067932113764319936292777772;
        proof.proof_o_com_y = 17008572716103700018236996769499465811342269985445596006986468386352544474606;
        proof.proof_h_0_x = 11306762625496444029517062401085927459076181013435861172640850049263110623349;
        proof.proof_h_0_y = 19638976565138944821469569870266452306224394011966617819541599962361201456937;
        proof.proof_h_1_x = 10581120357930445171036943706151508840952432122281856821331231542058180166285;
        proof.proof_h_1_y = 13116551497123107422849061443153459893121961241938821608867067723297394677855;
        proof.proof_h_2_x = 6176003604824139896525963346099784447778520895652608738816885699873720245502;
        proof.proof_h_2_y = 2575732174046568156325590924157515074365660960531688770241196334899953243513;
        proof.proof_l_at_zeta = 11774818462752523173673112601698893324294455251366253863191321931502273529786;
        proof.proof_r_at_zeta = 21348089790410543988694507660292858218023355517538234582691822777894262777382;
        proof.proof_o_at_zeta = 17232954402379153120008945444490594766734805094742217536351055883751931526798;
        proof.proof_s1_at_zeta = 21718227249506195079206644059765440113781142520812876217924273084518083857175;
        proof.proof_s2_at_zeta = 15991235768498711465105030313006897011344142090170549476004760149989722012579;
        proof.proof_grand_product_commitment_x = 2071389742085363562986965150516921422110573742621576699272561535169043007890;
        proof.proof_grand_product_commitment_y = 9561192641727079661329796388380220261464083695660574750562812197316028509619;
        proof.proof_grand_product_at_zeta_omega = 20541867731332852134757520484681794779487855164886119577416173999137697831287;
        proof.proof_quotient_polynomial_at_zeta = 12459300780197780384026590238365283437368363613547391357852424792568159477487;
        proof.proof_linearised_polynomial_at_zeta = 19627554433299120285331671363456243756640419203648894431889907812905444294907;
        proof.proof_batch_opening_at_zeta_x = 20273667862178264500854284547588574748856787351166150791714415777903502104106;
        proof.proof_batch_opening_at_zeta_y = 17565176546997306420994025434245700193255917968451818704044294120320612661336;
        proof.proof_opening_at_zeta_omega_x = 21716485425503605728446852366587181144043741347109772443289458570117210252949;
		proof.proof_opening_at_zeta_omega_y = 12188901785809459620571862643575559320674213820597223605903812144000263113522;
      
        
        proof.proof_openings_selector_0_commit_api_at_zeta = 6448190182597352327777688215096695621141556247410477751590784279494104998718;
        

        
        proof.proof_selector_0_commit_api_commitment_x = 1151222597878820088269126206620792462034537852573476775956124424495643872260;
        proof.proof_selector_0_commit_api_commitment_y = 19128472981859132424902629268314238336269190964815065770676058985385049684817;
        

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
