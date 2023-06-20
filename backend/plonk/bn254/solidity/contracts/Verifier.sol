pragma solidity ^0.8.0;

pragma experimental ABIEncoderV2;

import {Utils} from './Utils.sol';

library PlonkVerifier {

  using Utils for *;
  uint256 constant r_mod = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
  uint256 constant p_mod = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
  
  uint256 constant g2_srs_0_x_0 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
  uint256 constant g2_srs_0_x_1 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
  uint256 constant g2_srs_0_y_0 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
  uint256 constant g2_srs_0_y_1 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
  
  uint256 constant g2_srs_1_x_0 = 21577096137383097098286836177521236017691053027860308045402866491769504750038;
  uint256 constant g2_srs_1_x_1 = 5056288833567422891623076519994676382556411815994611078975286019325971735456;
  uint256 constant g2_srs_1_y_0 = 16718739624519123577073081886933867327433489801032170416450300889863618482798;
  uint256 constant g2_srs_1_y_1 = 12527038463363202864868333842632009163419403695704087127138517330130678271208;
  
  // ----------------------- vk ---------------------
  uint256 constant vk_domain_size = 16;
  uint256 constant vk_inv_domain_size = 20520227692349320520856005386178695395514091625390032197217066424914820464641;
  uint256 constant vk_omega = 14940766826517323942636479241147756311199852622225275649687664389641784935947;
  uint256 constant vk_ql_com_x = 18618661347525750325496598444124701168206681500695374672269837241817213913951;
  uint256 constant vk_ql_com_y = 6650699289552746906437834930795870403580280048629469158602805710302372784035;
  uint256 constant vk_qr_com_x = 5751488232203176802209045438473754355544233234002794691692217398655678786175;
  uint256 constant vk_qr_com_y = 7617253703157687688026236396664281691241941915510929936302642131521227505325;
  uint256 constant vk_qm_com_x = 7161679117436705865011159819684673028557639140084429960607225747005792035248;
  uint256 constant vk_qm_com_y = 13629052214160762611682316273598933092977996145495459762428775758771853083481;
  uint256 constant vk_qo_com_x = 19979670597627131951955558698707080284223524167108707937252769271888262646537;
  uint256 constant vk_qo_com_y = 9369063692568444164911454293238169377342355249224008311713778997646850955484;
  uint256 constant vk_qk_com_x = 8242312149349177695313923031744882154981290265617751100452552524214766210892;
  uint256 constant vk_qk_com_y = 18276080332897324779160272117093382757460439861662327350552339502390409673092;
  
  uint256 constant vk_s1_com_x = 6942181756996174922213540882047522654435606364572728881082950397868613194125;
  uint256 constant vk_s1_com_y = 9571623504927928811611819216559169375075522036711967714038515326543956758698;
  
  uint256 constant vk_s2_com_x = 16126484048522170989669514624973686362805047004586503857593581272757662752508;
  uint256 constant vk_s2_com_y = 5334321807140500092350943754597205248239228014965197968107356598160952687084;
  
  uint256 constant vk_s3_com_x = 19617789897634758851781119372476902104849373170024916037761450655279860989769;
  uint256 constant vk_s3_com_y = 5729902649636507333615789419804042837927697561889582840968919744136353608788;
  
  uint256 constant vk_coset_shift = 5;
  
  
  uint256 constant vk_selector_commitments_commit_api_0_x = 4574884584677296283456061553373991561765200620529265257935150587006968293718;
  uint256 constant vk_selector_commitments_commit_api_0_y = 3396712188916664930620660782356566839297839335383152661838295805437920858916;
  
  uint256 constant vk_selector_commitments_commit_api_1_x = 4480716517402530508375620609397919454334222911410002054082730849779992546134;
  uint256 constant vk_selector_commitments_commit_api_1_y = 19394288833530100210650742845215852197568997151482319696501966919406253946325;
  

  
  function load_vk_commitments_indices_commit_api(uint256[] memory v)
  internal view {
    assembly {
    let _v := add(v, 0x20)
    
    mstore(_v, 3)
    _v := add(_v, 0x20)
    
    mstore(_v, 5)
    _v := add(_v, 0x20)
    
    }
  }
  
  uint256 constant vk_nb_commitments_commit_api = 2;

  // ------------------------------------------------

  // offset proof
  uint256 constant proof_l_com_x = 0x20;
  uint256 constant proof_l_com_y = 0x40;
  uint256 constant proof_r_com_x = 0x60;
  uint256 constant proof_r_com_y = 0x80;
  uint256 constant proof_o_com_x = 0xa0;
  uint256 constant proof_o_com_y = 0xc0;

  // h = h_0 + x^{n+2}h_1 + x^{2(n+2)}h_2
  uint256 constant proof_h_0_x = 0xe0; 
  uint256 constant proof_h_0_y = 0x100;
  uint256 constant proof_h_1_x = 0x120;
  uint256 constant proof_h_1_y = 0x140;
  uint256 constant proof_h_2_x = 0x160;
  uint256 constant proof_h_2_y = 0x180;

  // wire values at zeta
  uint256 constant proof_l_at_zeta = 0x1a0;
  uint256 constant proof_r_at_zeta = 0x1c0;
  uint256 constant proof_o_at_zeta = 0x1e0;

  //uint256[STATE_WIDTH-1] permutation_polynomials_at_zeta; // Sσ1(zeta),Sσ2(zeta)
  uint256 constant proof_s1_at_zeta = 0x200; // Sσ1(zeta)
  uint256 constant proof_s2_at_zeta = 0x220; // Sσ2(zeta)

  //Bn254.G1Point grand_product_commitment;                 // [z(x)]
  uint256 constant proof_grand_product_commitment_x = 0x240;
  uint256 constant proof_grand_product_commitment_y = 0x260;

  uint256 constant proof_grand_product_at_zeta_omega = 0x280;                    // z(w*zeta)
  uint256 constant proof_quotient_polynomial_at_zeta = 0x2a0;                    // t(zeta)
  uint256 constant proof_linearised_polynomial_at_zeta = 0x2c0;               // r(zeta)

  // Folded proof for the opening of H, linearised poly, l, r, o, s_1, s_2, qcp
  uint256 constant proof_batch_opening_at_zeta_x = 0x2e0;            // [Wzeta]
  uint256 constant proof_batch_opening_at_zeta_y = 0x300;

  //Bn254.G1Point opening_at_zeta_omega_proof;      // [Wzeta*omega]
  uint256 constant proof_opening_at_zeta_omega_x = 0x320;
  uint256 constant proof_opening_at_zeta_omega_y = 0x340;
  
  uint256 constant proof_openings_selector_commit_api_at_zeta = 0x360;
  // -> next part of proof is 
  // [ openings_selector_commits || commitments_wires_commit_api]

  // -------- offset state

  // challenges to check the claimed quotient
  uint256 constant state_alpha = 0x00;
  uint256 constant state_beta = 0x20;
  uint256 constant state_gamma = 0x40;
  uint256 constant state_zeta = 0x60;

  // challenges related to KZG
  uint256 constant state_sv = 0x80;
  uint256 constant state_su = 0xa0;

  // reusable value
  uint256 constant state_alpha_square_lagrange = 0xc0;

  // commitment to H
  // Bn254.G1Point folded_h;
  uint256 constant state_folded_h_x = 0xe0;
  uint256 constant state_folded_h_y = 0x100;

  // commitment to the linearised polynomial
  uint256 constant state_linearised_polynomial_x = 0x120;
  uint256 constant state_linearised_polynomial_y = 0x140;

  // Folded proof for the opening of H, linearised poly, l, r, o, s_1, s_2, qcp
  // Kzg.OpeningProof folded_proof;
  uint256 constant state_folded_claimed_values = 0x160;

  // folded digests of H, linearised poly, l, r, o, s_1, s_2, qcp
  // Bn254.G1Point folded_digests;
  uint256 constant state_folded_digests_x = 0x180;
  uint256 constant state_folded_digests_y = 0x1a0;

  uint256 constant state_pi = 0x1c0;

  uint256 constant state_zeta_power_n_minus_one = 0x1e0;
  uint256 constant state_alpha_square_lagrange_one = 0x200;

  uint256 constant state_gamma_kzg = 0x220;

  uint256 constant state_success = 0x240;
  uint256 constant state_check_var = 0x260; // /!\ this slot is used for debugging only


  uint256 constant state_last_mem = 0x280;

  event PrintUint256(uint256 a);

  function derive_gamma_beta_alpha_zeta(bytes memory proof, uint256[] memory public_inputs)
  internal returns(uint256, uint256, uint256, uint256) {

    uint256 gamma;
    uint256 beta;
    uint256 alpha;
    uint256 zeta;

    assembly {

      let mem := mload(0x40)

      derive_gamma(proof, public_inputs)
      gamma := mload(mem)

      derive_beta(proof, gamma)
      beta := mload(mem)

      derive_alpha(proof, beta)
      alpha := mload(mem)

      derive_zeta(proof, alpha)
      zeta := mload(mem)

      gamma := mod(gamma, r_mod)
      beta := mod(beta, r_mod)
      alpha := mod(alpha, r_mod)
      zeta := mod(zeta, r_mod)

      function derive_gamma(aproof, pub_inputs) {
        
        let mPtr := mload(0x40)

        // gamma
        mstore(mPtr, 0x67616d6d61) // "gamma"

        mstore(add(mPtr, 0x20), vk_s1_com_x)
        mstore(add(mPtr, 0x40), vk_s1_com_y)
        mstore(add(mPtr, 0x60), vk_s2_com_x)
        mstore(add(mPtr, 0x80), vk_s2_com_y)
        mstore(add(mPtr, 0xa0), vk_s3_com_x)
        mstore(add(mPtr, 0xc0), vk_s3_com_y)
        mstore(add(mPtr, 0xe0), vk_ql_com_x)
        mstore(add(mPtr, 0x100), vk_ql_com_y)
        mstore(add(mPtr, 0x120), vk_qr_com_x)
        mstore(add(mPtr, 0x140), vk_qr_com_y)
        mstore(add(mPtr, 0x160), vk_qm_com_x)
        mstore(add(mPtr, 0x180), vk_qm_com_y)
        mstore(add(mPtr, 0x1a0), vk_qo_com_x)
        mstore(add(mPtr, 0x1c0), vk_qo_com_y)
        mstore(add(mPtr, 0x1e0), vk_qk_com_x)
        mstore(add(mPtr, 0x200), vk_qk_com_y)

        let pi := add(pub_inputs, 0x20)
        let _mPtr := add(mPtr, 0x220)
        for {let i:=0} lt(i, mload(pub_inputs)) {i:=add(i,1)}
        {
          mstore(_mPtr, mload(pi))
          pi := add(pi, 0x20)
          _mPtr := add(_mPtr, 0x20)
        }

        let _proof := add(aproof, proof_openings_selector_commit_api_at_zeta)
        _proof := add(_proof, mul(vk_nb_commitments_commit_api, 0x20))
        for {let i:=0} lt(i, vk_nb_commitments_commit_api) {i:=add(i,1)}
        {
          mstore(_mPtr, mload(_proof))
          mstore(add(_mPtr, 0x20), mload(add(_proof, 0x20)))
          _mPtr := add(_mPtr, 0x40)
          _proof := add(_proof, 0x40)
        }
        // pop(staticcall(sub(gas(), 2000), 0x2, add(mPtr, 0x1b), 0x2a5, mPtr, 0x20)) //0x1b -> 000.."gamma"

        mstore(_mPtr, mload(add(aproof, proof_l_com_x)))
        mstore(add(_mPtr, 0x20), mload(add(aproof, proof_l_com_y)))
        mstore(add(_mPtr, 0x40), mload(add(aproof, proof_r_com_x)))
        mstore(add(_mPtr, 0x60), mload(add(aproof, proof_r_com_y)))
        mstore(add(_mPtr, 0x80), mload(add(aproof, proof_o_com_x)))
        mstore(add(_mPtr, 0xa0), mload(add(aproof, proof_o_com_y)))
        // pop(staticcall(sub(gas(), 2000), 0x2, add(mPtr, 0x1b), 0x365, mPtr, 0x20)) //0x1b -> 000.."gamma"

        let size := add(0x2c5, mul(mload(pub_inputs), 0x20)) // 0x2c5 = 22*32+5
        size := add(size, mul(vk_nb_commitments_commit_api, 0x40))
        pop(staticcall(sub(gas(), 2000), 0x2, add(mPtr, 0x1b), size, mPtr, 0x20)) //0x1b -> 000.."gamma"
      }

      function derive_beta(aproof, prev_challenge){
        let mPtr := mload(0x40)
        // beta
        mstore(mPtr, 0x62657461) // "beta"
        mstore(add(mPtr, 0x20), prev_challenge)
        pop(staticcall(sub(gas(), 2000), 0x2, add(mPtr, 0x1c), 0x24, mPtr, 0x20)) //0x1b -> 000.."gamma"
      }

      function derive_alpha(aproof, prev_challenge){
        let mPtr := mload(0x40)
        // alpha
        mstore(mPtr, 0x616C706861) // "alpha"
        mstore(add(mPtr, 0x20), prev_challenge)
        mstore(add(mPtr, 0x40), mload(add(aproof, proof_grand_product_commitment_x)))
        mstore(add(mPtr, 0x60), mload(add(aproof, proof_grand_product_commitment_y)))
        pop(staticcall(sub(gas(), 2000), 0x2, add(mPtr, 0x1b), 0x65, mPtr, 0x20)) //0x1b -> 000.."gamma"
      }

      function derive_zeta(aproof, prev_challenge) {
        let mPtr := mload(0x40)
        // zeta
        mstore(mPtr, 0x7a657461) // "zeta"
        mstore(add(mPtr, 0x20), prev_challenge)
        mstore(add(mPtr, 0x40), mload(add(aproof, proof_h_0_x)))
        mstore(add(mPtr, 0x60), mload(add(aproof, proof_h_0_y)))
        mstore(add(mPtr, 0x80), mload(add(aproof, proof_h_1_x)))
        mstore(add(mPtr, 0xa0), mload(add(aproof, proof_h_1_y)))
        mstore(add(mPtr, 0xc0), mload(add(aproof, proof_h_2_x)))
        mstore(add(mPtr, 0xe0), mload(add(aproof, proof_h_2_y)))
        pop(staticcall(sub(gas(), 2000), 0x2, add(mPtr, 0x1c), 0xe4, mPtr, 0x20))
      }
    }

    return (gamma, beta, alpha, zeta);
  }

  function load_wire_commitments_commit_api(uint256[] memory wire_commitments, bytes memory proof)
  internal {
    assembly {
      let w := add(wire_commitments, 0x20)
      let p := add(proof, proof_openings_selector_commit_api_at_zeta)
      p := add(p, mul(vk_nb_commitments_commit_api, 0x20))
      for {let i:=0} lt(i, mul(vk_nb_commitments_commit_api,2)) {i:=add(i,1)}
      {
        mstore(w, mload(p))
        w := add(w,0x20)
        p := add(p,0x20)
        mstore(w, mload(p))
        w := add(w,0x20)
        p := add(p,0x20)
      }
    }
  }

  function compute_ith_lagrange_at_z(uint256 zeta, uint256 i) 
  internal returns (uint256) {

    uint256 res;
    assembly {

      // _n^_i [r]
      function pow_local(x, e)->result {
          let mPtr := mload(0x40)
          mstore(mPtr, 0x20)
          mstore(add(mPtr, 0x20), 0x20)
          mstore(add(mPtr, 0x40), 0x20)
          mstore(add(mPtr, 0x60), x)
          mstore(add(mPtr, 0x80), e)
          mstore(add(mPtr, 0xa0), r_mod)
          pop(staticcall(sub(gas(), 2000),0x05,mPtr,0xc0,0x00,0x20))
          result := mload(0x00)
      }

      let w := pow_local(vk_omega,i) // w**i
      i := addmod(zeta, sub(r_mod, w), r_mod) // z-w**i
      zeta := pow_local(zeta, vk_domain_size) // z**n
      zeta := addmod(zeta, sub(r_mod, 1), r_mod) // z**n-1
      w := mulmod(w, vk_inv_domain_size, r_mod) // w**i/n
      i := pow_local(i, sub(r_mod,2)) // (z-w**i)**-1
      w := mulmod(w, i, r_mod) // w**i/n*(z-w)**-1
      res := mulmod(w, zeta, r_mod)
    }
    
    return res;
  }

  function compute_pi(
        bytes memory proof,
        uint256[] memory public_inputs,
        uint256 zeta
    ) internal returns (uint256) {

      // evaluation of Z=Xⁿ⁻¹ at ζ
      // uint256 zeta_power_n_minus_one = Fr.pow(zeta, vk_domain_size);
      // zeta_power_n_minus_one = Fr.sub(zeta_power_n_minus_one, 1);
      uint256 zeta_power_n_minus_one;

      uint256 pi;

      assembly {
        
        sum_pi_wo_api_commit(add(public_inputs,0x20), mload(public_inputs), zeta)
        pi := mload(mload(0x40))

        function sum_pi_wo_api_commit(ins, n, z) {
          let li := mload(0x40)
          batch_compute_lagranges_at_z(z, n, li)
          let res := 0
          let tmp := 0
          for {let i:=0} lt(i,n) {i:=add(i,1)}
          {
            tmp := mulmod(mload(li), mload(ins), r_mod)
            res := addmod(res, tmp, r_mod)
            li := add(li, 0x20)
            ins := add(ins, 0x20)
          }
          mstore(mload(0x40), res)
        }

        // mPtr <- [L_0(z), .., L_{n-1}(z)]
        function batch_compute_lagranges_at_z(z, n, mPtr) {
          let zn := addmod(pow(z, vk_domain_size, mPtr), sub(r_mod, 1), r_mod)
          zn := mulmod(zn, vk_inv_domain_size, r_mod)
          let _w := 1
          let _mPtr := mPtr
          for {let i:=0} lt(i,n) {i:=add(i,1)}
          {
            mstore(_mPtr, addmod(z,sub(r_mod, _w), r_mod))
            _w := mulmod(_w, vk_omega, r_mod)
            _mPtr := add(_mPtr, 0x20)
          }
          batch_invert(mPtr, n, _mPtr)
          _mPtr := mPtr
          _w := 1
          for {let i:=0} lt(i,n) {i:=add(i,1)}
          {
            mstore(_mPtr, mulmod(mulmod(mload(_mPtr), zn , r_mod), _w, r_mod))
            _mPtr := add(_mPtr, 0x20)
            _w := mulmod(_w, vk_omega, r_mod)
          }
        } 

        function batch_invert(ins, nb_ins, mPtr) {
          mstore(mPtr, 1)
          let offset := 0
          for {let i:=0} lt(i, nb_ins) {i:=add(i,1)}
          {
            let prev := mload(add(mPtr, offset))
            let cur := mload(add(ins, offset))
            cur := mulmod(prev, cur, r_mod)
            offset := add(offset, 0x20)
            mstore(add(mPtr, offset), cur)
          }
          ins := add(ins, sub(offset, 0x20))
          mPtr := add(mPtr, offset)
          let inv := pow(mload(mPtr), sub(r_mod,2), add(mPtr, 0x20))
          for {let i:=0} lt(i, nb_ins) {i:=add(i,1)}
          {
            mPtr := sub(mPtr, 0x20)
            let tmp := mload(ins)
            let cur := mulmod(inv, mload(mPtr), r_mod)
            mstore(ins, cur)
            inv := mulmod(inv, tmp, r_mod)
            ins := sub(ins, 0x20)
          }
        }

        // res <- x^e mod r
        function pow(x, e, mPtr)->res {
          mstore(mPtr, 0x20)
          mstore(add(mPtr, 0x20), 0x20)
          mstore(add(mPtr, 0x40), 0x20)
          mstore(add(mPtr, 0x60), x)
          mstore(add(mPtr, 0x80), e)
          mstore(add(mPtr, 0xa0), r_mod)
          pop(staticcall(sub(gas(), 2000),0x05,mPtr,0xc0,mPtr,0x20))
          res := mload(mPtr)
        }

        zeta_power_n_minus_one := pow(zeta, vk_domain_size, mload(0x40))
        zeta_power_n_minus_one := addmod(zeta_power_n_minus_one, sub(r_mod, 1), r_mod)
      }

      
      uint256[] memory commitment_indices = new uint256[](vk_nb_commitments_commit_api);
      load_vk_commitments_indices_commit_api(commitment_indices);

      uint256[] memory wire_committed_commitments;
      wire_committed_commitments = new uint256[](2*vk_nb_commitments_commit_api);

      load_wire_commitments_commit_api(wire_committed_commitments, proof);

      for (uint256 i=0; i<vk_nb_commitments_commit_api; i++){
          
          uint256 hash_res = Utils.hash_fr(wire_committed_commitments[2*i], wire_committed_commitments[2*i+1]);
          uint256 a = compute_ith_lagrange_at_z(zeta, commitment_indices[i]+public_inputs.length);
          assembly {
            a := mulmod(hash_res, a, r_mod)
            pi := addmod(pi, a, r_mod)
          }
      }
      
      
      return pi;
    }

  function Verify(bytes memory proof, uint256[] memory public_inputs) 
  internal returns(bool) {

    uint256 gamma;
    uint256 beta;
    uint256 alpha;
    uint256 zeta;

    (gamma, beta, alpha, zeta) = derive_gamma_beta_alpha_zeta(proof, public_inputs);

    uint256 pi = compute_pi(proof, public_inputs, zeta);

    uint256 check;

    bool success = false;
    // uint256 success;

    assembly {

      let mem := mload(0x40)
      mstore(add(mem, state_alpha), alpha)
      mstore(add(mem, state_gamma), gamma)
      mstore(add(mem, state_zeta), zeta)
      mstore(add(mem, state_beta), beta)
      mstore(add(mem, state_pi), pi)

      compute_alpha_square_lagrange()
      verify_quotient_poly_eval_at_zeta(proof)
      fold_h(proof)
      compute_commitment_linearised_polynomial(proof)
      compute_gamma_kzg(proof)
      fold_state(proof)
      batch_verify_multi_points(proof)

      success := mload(add(mem, state_success))
      
      check := mload(add(mem, state_check_var))

      function compute_alpha_square_lagrange() {   
        let state := mload(0x40)
        let mPtr := add(mload(0x40), state_last_mem)

        // zeta**n - 1
        let res := pow(mload(add(state, state_zeta)), vk_domain_size, mPtr)
        res := addmod(res, sub(r_mod,1), r_mod)
        mstore(add(state, state_zeta_power_n_minus_one), res)

        // let res := mload(add(state, state_zeta_power_n_minus_one))
        let den := addmod(mload(add(state, state_zeta)), sub(r_mod, 1), r_mod)
        den := pow(den, sub(r_mod, 2), mPtr)
        den := mulmod(den, vk_inv_domain_size, r_mod)
        res := mulmod(den, res, r_mod)

        let l_alpha := mload(add(state, state_alpha))
        res := mulmod(res, l_alpha, r_mod)
        res := mulmod(res, l_alpha, r_mod)
        mstore(add(state, state_alpha_square_lagrange), res)
      }

      function batch_verify_multi_points(aproof) {

        let state := mload(0x40)
        let mPtr := add(state, state_last_mem)

        // here the random is not a challenge, hence no need to use Fiat Shamir, we just
        // need an unpredictible result.
        let random := mod(keccak256(state, 0x20), r_mod)

        let folded_quotients := mPtr
        mPtr := add(folded_quotients, 0x40)
        mstore(folded_quotients, mload(add(aproof, proof_batch_opening_at_zeta_x)))
        mstore(add(folded_quotients, 0x20), mload(add(aproof, proof_batch_opening_at_zeta_y)))
        point_acc_mul(folded_quotients, add(aproof, proof_opening_at_zeta_omega_x), random, mPtr)

        let folded_digests := add(state, state_folded_digests_x)
        point_acc_mul(folded_digests, add(aproof, proof_grand_product_commitment_x), random, mPtr)

        let folded_evals := add(state, state_folded_claimed_values)
        fr_acc_mul(folded_evals, add(aproof, proof_grand_product_at_zeta_omega), random)

        let folded_evals_commit := mPtr
        mPtr := add(folded_evals_commit, 0x40)
        mstore(folded_evals_commit, 0x1)
        mstore(add(folded_evals_commit, 0x20), 0x2)
        mstore(add(folded_evals_commit, 0x40), mload(folded_evals))
        pop(staticcall(sub(gas(), 2000),7,folded_evals_commit,0x60,folded_evals_commit,0x40))

        let folded_evals_commit_y := add(folded_evals_commit, 0x20)
        mstore(folded_evals_commit_y, sub(p_mod, mload(folded_evals_commit_y)))
        point_add(folded_digests, folded_digests, folded_evals_commit, mPtr)

        let folded_points_quotients := mPtr
        mPtr := add(mPtr, 0x40)
        point_mul(folded_points_quotients, add(aproof, proof_batch_opening_at_zeta_x), mload(add(state, state_zeta)), mPtr)
        let zeta_omega := mulmod(mload(add(state, state_zeta)), vk_omega, r_mod)
        random := mulmod(random, zeta_omega, r_mod)
        point_acc_mul(folded_points_quotients, add(aproof, proof_opening_at_zeta_omega_x), random, mPtr)

        point_add(folded_digests, folded_digests, folded_points_quotients, mPtr)

        let folded_quotients_y := add(folded_quotients, 0x20)
        mstore(folded_quotients_y, sub(p_mod, mload(folded_quotients_y)))

        mstore(mPtr, mload(folded_digests))
        mstore(add(mPtr, 0x20), mload(add(folded_digests, 0x20)))
        mstore(add(mPtr, 0x40), g2_srs_0_x_0) // the 4 lines are the canonical G2 point on BN254
        mstore(add(mPtr, 0x60), g2_srs_0_x_1)
        mstore(add(mPtr, 0x80), g2_srs_0_y_0)
        mstore(add(mPtr, 0xa0), g2_srs_0_y_1)
        mstore(add(mPtr, 0xc0), mload(folded_quotients))
        mstore(add(mPtr, 0xe0), mload(add(folded_quotients, 0x20)))
        mstore(add(mPtr, 0x100), g2_srs_1_x_0)
        mstore(add(mPtr, 0x120), g2_srs_1_x_1)
        mstore(add(mPtr, 0x140), g2_srs_1_y_0)
        mstore(add(mPtr, 0x160), g2_srs_1_y_1)
        let l_success := staticcall(sub(gas(), 2000),8,mPtr,0x180,0x00,0x20)
        // l_success := true
        mstore(add(state, state_success), and(l_success,mload(add(state, state_success))))
      }

      // at this stage the state of mPtr is the same as in compute_gamma
      function fold_state(aproof) {
        
        let state := mload(0x40)
        let mPtr := add(mload(0x40), state_last_mem)

        let l_gamma_kzg := mload(add(state, state_gamma_kzg))
        let acc_gamma := l_gamma_kzg

        let offset := add(0x200, mul(vk_nb_commitments_commit_api, 0x40)) // 0x40 = 2*0x20
        let mPtrOffset := add(mPtr, offset)

        mstore(add(state, state_folded_digests_x), mload(add(mPtr,0x40)))
        mstore(add(state, state_folded_digests_y), mload(add(mPtr,0x60)))
        mstore(add(state, state_folded_claimed_values), mload(add(aproof, proof_quotient_polynomial_at_zeta)))

        point_acc_mul(add(state, state_folded_digests_x), add(mPtr,0x80), acc_gamma, mPtrOffset)
        fr_acc_mul(add(state, state_folded_claimed_values), add(aproof, proof_linearised_polynomial_at_zeta), acc_gamma)
        mstore(add(state, state_check_var), acc_gamma)
        
        acc_gamma := mulmod(acc_gamma, l_gamma_kzg, r_mod)
        point_acc_mul(add(state, state_folded_digests_x), add(mPtr,0xc0), acc_gamma, mPtrOffset)
        fr_acc_mul(add(state, state_folded_claimed_values), add(aproof, proof_l_at_zeta), acc_gamma)
        
        acc_gamma := mulmod(acc_gamma, l_gamma_kzg, r_mod)
        point_acc_mul(add(state, state_folded_digests_x), add(mPtr,0x100), acc_gamma, add(mPtr, offset))
        fr_acc_mul(add(state, state_folded_claimed_values), add(aproof, proof_r_at_zeta), acc_gamma)

        acc_gamma := mulmod(acc_gamma, l_gamma_kzg, r_mod)
        point_acc_mul(add(state, state_folded_digests_x), add(mPtr,0x140), acc_gamma, add(mPtr, offset))
        fr_acc_mul(add(state, state_folded_claimed_values), add(aproof, proof_o_at_zeta), acc_gamma)
        
        acc_gamma := mulmod(acc_gamma, l_gamma_kzg, r_mod)
        point_acc_mul(add(state, state_folded_digests_x), add(mPtr,0x180), acc_gamma, add(mPtr, offset))
        fr_acc_mul(add(state, state_folded_claimed_values), add(aproof, proof_s1_at_zeta), acc_gamma)
        
        acc_gamma := mulmod(acc_gamma, l_gamma_kzg, r_mod)
        point_acc_mul(add(state, state_folded_digests_x), add(mPtr,0x1c0), acc_gamma, add(mPtr, offset))
        fr_acc_mul(add(state, state_folded_claimed_values), add(aproof, proof_s2_at_zeta), acc_gamma)
        
        let poscaz := add(aproof, proof_openings_selector_commit_api_at_zeta)
        let opca := add(mPtr, 0x200) // offset_proof_commits_api
        for {let i := 0} lt(i, vk_nb_commitments_commit_api) {i:=add(i,1)}
        {
          acc_gamma := mulmod(acc_gamma, l_gamma_kzg, r_mod)
          point_acc_mul(add(state, state_folded_digests_x), opca, acc_gamma, add(mPtr, offset))
          fr_acc_mul(add(state, state_folded_claimed_values), poscaz, acc_gamma)
          poscaz := add(poscaz, 0x20)
          opca := add(opca, 0x40)
        }

      }

      function compute_gamma_kzg(aproof) {

        let state := mload(0x40)
        let mPtr := add(mload(0x40), state_last_mem)
        mstore(mPtr, 0x67616d6d61) // "gamma"
        mstore(add(mPtr, 0x20), mload(add(state, state_zeta)))
        mstore(add(mPtr,0x40), mload(add(state, state_folded_h_x)))
        mstore(add(mPtr,0x60), mload(add(state, state_folded_h_y)))
        mstore(add(mPtr,0x80), mload(add(state, state_linearised_polynomial_x)))
        mstore(add(mPtr,0xa0), mload(add(state, state_linearised_polynomial_y)))
        mstore(add(mPtr,0xc0), mload(add(aproof, proof_l_com_x)))
        mstore(add(mPtr,0xe0), mload(add(aproof, proof_l_com_y)))
        mstore(add(mPtr,0x100), mload(add(aproof, proof_r_com_x)))
        mstore(add(mPtr,0x120), mload(add(aproof, proof_r_com_y)))
        mstore(add(mPtr,0x140), mload(add(aproof, proof_o_com_x)))
        mstore(add(mPtr,0x160), mload(add(aproof, proof_o_com_y)))
        mstore(add(mPtr,0x180), vk_s1_com_x)
        mstore(add(mPtr,0x1a0), vk_s1_com_y)
        mstore(add(mPtr,0x1c0), vk_s2_com_x)
        mstore(add(mPtr,0x1e0), vk_s2_com_y)
        
        let offset := 0x200
        
        mstore(add(mPtr,offset), vk_selector_commitments_commit_api_0_x)
        mstore(add(mPtr,add(offset, 0x20)), vk_selector_commitments_commit_api_0_y)
        offset := add(offset, 0x40)
        
        mstore(add(mPtr,offset), vk_selector_commitments_commit_api_1_x)
        mstore(add(mPtr,add(offset, 0x20)), vk_selector_commitments_commit_api_1_y)
        offset := add(offset, 0x40)
        

        mstore(add(mPtr, offset), mload(add(aproof, proof_quotient_polynomial_at_zeta)))
        mstore(add(mPtr, add(offset, 0x20)), mload(add(aproof, proof_linearised_polynomial_at_zeta)))
        mstore(add(mPtr, add(offset, 0x40)), mload(add(aproof, proof_l_at_zeta)))
        mstore(add(mPtr, add(offset, 0x60)), mload(add(aproof, proof_r_at_zeta)))
        mstore(add(mPtr, add(offset, 0x80)), mload(add(aproof, proof_o_at_zeta)))
        mstore(add(mPtr, add(offset, 0xa0)), mload(add(aproof, proof_s1_at_zeta)))
        mstore(add(mPtr, add(offset, 0xc0)), mload(add(aproof, proof_s2_at_zeta)))

        
        let _mPtr := add(mPtr, add(offset, 0xe0))
        let _poscaz := add(aproof, proof_openings_selector_commit_api_at_zeta)
        for {let i:=0} lt(i, vk_nb_commitments_commit_api) {i:=add(i,1)}
        {
          mstore(_mPtr, mload(_poscaz))
          _poscaz := add(_poscaz, 0x20)
          _mPtr := add(_mPtr, 0x20)
        }
        

        let start_input := 0x1b // 00.."gamma"
        let size_input := add(0x16, mul(vk_nb_commitments_commit_api,3)) // number of 32bytes elmts = 0x16 (zeta+2*7+7 for the digests+openings) + 2*vk_nb_commitments_commit_api (for the commitments of the selectors) + vk_nb_commitments_commit_api (for the openings of the selectors)
        size_input := add(0x5, mul(size_input, 0x20)) // size in bytes: 15*32 bytes + 5 bytes for gamma
        pop(staticcall(sub(gas(), 2000), 0x2, add(mPtr,start_input), size_input, add(state, state_gamma_kzg), 0x20))
        mstore(add(state, state_gamma_kzg), mod(mload(add(state, state_gamma_kzg)), r_mod))
      }

      function compute_commitment_linearised_polynomial_ec(aproof, s1, s2) {

        let state := mload(0x40)
        let mPtr := add(mload(0x40), state_last_mem)

        mstore(mPtr, vk_ql_com_x)
        mstore(add(mPtr,0x20), vk_ql_com_y)
        point_mul(add(state, state_linearised_polynomial_x), mPtr, mload(add(aproof, proof_l_at_zeta)), add(mPtr,0x40))

        mstore(mPtr, vk_qr_com_x)
        mstore(add(mPtr,0x20), vk_qr_com_y)
        point_acc_mul(add(state, state_linearised_polynomial_x),mPtr,mload(add(aproof, proof_r_at_zeta)),add(mPtr,0x40))
        
        let rl := mulmod(mload(add(aproof, proof_l_at_zeta)), mload(add(aproof, proof_r_at_zeta)), r_mod)
        mstore(mPtr, vk_qm_com_x)
        mstore(add(mPtr,0x20), vk_qm_com_y)
        point_acc_mul(add(state, state_linearised_polynomial_x),mPtr,rl,add(mPtr,0x40))
        
        mstore(mPtr, vk_qo_com_x)
        mstore(add(mPtr,0x20), vk_qo_com_y)
        point_acc_mul(add(state, state_linearised_polynomial_x),mPtr,mload(add(aproof, proof_o_at_zeta)),add(mPtr,0x40))
        
        mstore(mPtr, vk_qk_com_x)
        mstore(add(mPtr, 0x20), vk_qk_com_y)
        point_add(add(state, state_linearised_polynomial_x),add(state, state_linearised_polynomial_x),mPtr,add(mPtr, 0x40))

        let commits_api_at_zeta := add(aproof, proof_openings_selector_commit_api_at_zeta)
        let commits_api := add(aproof, add(proof_openings_selector_commit_api_at_zeta, mul(vk_nb_commitments_commit_api, 0x20)))
        for {let i:=0} lt(i, vk_nb_commitments_commit_api) {i:=add(i,1)}
        {
          mstore(mPtr, mload(commits_api))
          mstore(add(mPtr, 0x20), mload(add(commits_api, 0x20)))
          point_acc_mul(add(state, state_linearised_polynomial_x),mPtr,mload(commits_api_at_zeta),add(mPtr,0x40))
          commits_api_at_zeta := add(commits_api_at_zeta, 0x20)
          commits_api := add(commits_api, 0x40)
        }

        mstore(mPtr, vk_s3_com_x)
        mstore(add(mPtr, 0x20), vk_s3_com_y)
        point_acc_mul(add(state, state_linearised_polynomial_x), mPtr, s1, add(mPtr, 0x40))

        mstore(mPtr, mload(add(aproof, proof_grand_product_commitment_x)))
        mstore(add(mPtr, 0x20), mload(add(aproof, proof_grand_product_commitment_y)))
        point_acc_mul(add(state, state_linearised_polynomial_x), mPtr, s2, add(mPtr, 0x40))

      }

      function compute_commitment_linearised_polynomial(aproof) {
        
        let state := mload(0x40)
        let l_beta := mload(add(state, state_beta))
        let l_gamma := mload(add(state, state_gamma))
        let l_zeta := mload(add(state, state_zeta))
        let l_alpha := mload(add(state, state_alpha))

        let u := mulmod(mload(add(aproof,proof_grand_product_at_zeta_omega)), l_beta, r_mod)
        let v := mulmod(l_beta, mload(add(aproof, proof_s1_at_zeta)), r_mod)
        v := addmod(v, mload(add(aproof, proof_l_at_zeta)), r_mod)
        v := addmod(v, l_gamma, r_mod)

        let w := mulmod(l_beta, mload(add(aproof, proof_s2_at_zeta)), r_mod)
        w := addmod(w, mload(add(aproof, proof_r_at_zeta)), r_mod)
        w := addmod(w, l_gamma, r_mod)

        let s1 := mulmod(u, v, r_mod)
        s1 := mulmod(s1, w, r_mod)
        s1 := mulmod(s1, l_alpha, r_mod)

        let coset_square := mulmod(vk_coset_shift, vk_coset_shift, r_mod)
        let betazeta := mulmod(l_beta, l_zeta, r_mod)
        u := addmod(betazeta, mload(add(aproof, proof_l_at_zeta)), r_mod)
        u := addmod(u, l_gamma, r_mod)

        v := mulmod(betazeta, vk_coset_shift, r_mod)
        v := addmod(v, mload(add(aproof, proof_r_at_zeta)), r_mod)
        v := addmod(v, l_gamma, r_mod)

        w := mulmod(betazeta, coset_square, r_mod)
        w := addmod(w, mload(add(aproof, proof_o_at_zeta)), r_mod)
        w := addmod(w, l_gamma, r_mod)

        let s2 := mulmod(u, v, r_mod)
        s2 := mulmod(s2, w, r_mod)
        s2 := sub(r_mod, s2)
        s2 := mulmod(s2, l_alpha, r_mod)
        s2 := addmod(s2, mload(add(state, state_alpha_square_lagrange)), r_mod)

        compute_commitment_linearised_polynomial_ec(aproof, s1, s2)
      }

      function fold_h(aproof) {
        let state := mload(0x40)
        let n_plus_two := add(vk_domain_size, 2)
        let mPtr := add(mload(0x40), state_last_mem)
        let zeta_power_n_plus_two := pow(mload(add(state, state_zeta)), n_plus_two, mPtr)
        point_mul(add(state, state_folded_h_x), add(aproof, proof_h_2_x), zeta_power_n_plus_two, mPtr)
        point_add(add(state, state_folded_h_x), add(state, state_folded_h_x), add(aproof, proof_h_1_x), mPtr)
        point_mul(add(state, state_folded_h_x), add(state, state_folded_h_x), zeta_power_n_plus_two, mPtr)
        point_add(add(state, state_folded_h_x), add(state, state_folded_h_x), add(aproof, proof_h_0_x), mPtr)
      }

      function verify_quotient_poly_eval_at_zeta(aproof) {

        let state := mload(0x40)

        // (l(ζ)+β*s1(ζ)+γ)
        let s1 := add(mload(0x40), state_last_mem)
        mstore(s1, mulmod(mload(add(aproof,proof_s1_at_zeta)),mload(add(state, state_beta)), r_mod))
        mstore(s1, addmod(mload(s1), mload(add(state, state_gamma)), r_mod))
        mstore(s1, addmod(mload(s1), mload(add(aproof, proof_l_at_zeta)), r_mod))

        // (r(ζ)+β*s2(ζ)+γ)
        let s2 := add(s1,0x20)
        mstore(s2, mulmod(mload(add(aproof,proof_s2_at_zeta)),mload(add(state, state_beta)), r_mod))
        mstore(s2, addmod(mload(s2), mload(add(state, state_gamma)), r_mod))
        mstore(s2, addmod(mload(s2), mload(add(aproof, proof_r_at_zeta)), r_mod))
        // _s2 := mload(s2)

        // (o(ζ)+γ)
        let o := add(s1,0x40)
        mstore(o, addmod(mload(add(aproof,proof_o_at_zeta)), mload(add(state, state_gamma)), r_mod))

        //  α*(Z(μζ))*(l(ζ)+β*s1(ζ)+γ)*(r(ζ)+β*s2(ζ)+γ)*(o(ζ)+γ)
        mstore(s1, mulmod(mload(s1), mload(s2), r_mod))
        mstore(s1, mulmod(mload(s1), mload(o), r_mod))
        mstore(s1, mulmod(mload(s1), mload(add(state, state_alpha)), r_mod))
        mstore(s1, mulmod(mload(s1), mload(add(aproof, proof_grand_product_at_zeta_omega)), r_mod))

        let computed_quotient := add(s1,0x60)

        // linearizedpolynomial + pi(zeta)
        mstore(computed_quotient, addmod(mload(add(aproof, proof_linearised_polynomial_at_zeta)), mload(add(state, state_pi)), r_mod))
        mstore(computed_quotient, addmod(mload(computed_quotient), mload(s1), r_mod))
        mstore(computed_quotient, addmod(mload(computed_quotient), sub(r_mod,mload(add(state, state_alpha_square_lagrange))), r_mod))
        mstore(s2, mulmod(mload(add(aproof,proof_quotient_polynomial_at_zeta)), mload(add(state, state_zeta_power_n_minus_one)), r_mod))

        mstore(add(state, state_success),eq(mload(computed_quotient), mload(s2)))
      }

      function point_add(dst, p, q, mPtr) {
        // let mPtr := add(mload(0x40), state_last_mem)
        let state := mload(0x40)
        mstore(mPtr, mload(p))
        mstore(add(mPtr, 0x20), mload(add(p, 0x20)))
        mstore(add(mPtr, 0x40), mload(q))
        mstore(add(mPtr, 0x60), mload(add(q, 0x20)))
        let l_success := staticcall(sub(gas(), 2000),6,mPtr,0x80,dst,0x40)
        mstore(add(state, state_success), and(l_success,mload(add(state, state_success))))
      }

      // dst <- [s]src
      function point_mul(dst,src,s, mPtr) {
        // let mPtr := add(mload(0x40), state_last_mem)
        let state := mload(0x40)
        mstore(mPtr,mload(src))
        mstore(add(mPtr,0x20),mload(add(src,0x20)))
        mstore(add(mPtr,0x40),s)
        let l_success := staticcall(sub(gas(), 2000),7,mPtr,0x60,dst,0x40)
        mstore(add(state, state_success), and(l_success,mload(add(state, state_success))))
      }

      // dst <- dst + [s]src (Elliptic curve)
      function point_acc_mul(dst,src,s, mPtr) {
        let state := mload(0x40)
        mstore(mPtr,mload(src))
        mstore(add(mPtr,0x20),mload(add(src,0x20)))
        mstore(add(mPtr,0x40),s)
        let l_success := staticcall(sub(gas(), 2000),7,mPtr,0x60,mPtr,0x40)
        mstore(add(mPtr,0x40),mload(dst))
        mstore(add(mPtr,0x60),mload(add(dst,0x20)))
        l_success := and(l_success, staticcall(sub(gas(), 2000),6,mPtr,0x80,dst, 0x40))
        mstore(add(state, state_success), and(l_success,mload(add(state, state_success))))
      }

      // dst <- dst + src (Fr) dst,src are addresses, s is a value
      function fr_acc_mul(dst, src, s) {
        let tmp :=  mulmod(mload(src), s, r_mod)
        mstore(dst, addmod(mload(dst), tmp, r_mod))
      }

      // dst <- x ** e mod r (x, e are values, not pointers)
      function pow(x, e, mPtr)->res {
        mstore(mPtr, 0x20)
        mstore(add(mPtr, 0x20), 0x20)
        mstore(add(mPtr, 0x40), 0x20)
        mstore(add(mPtr, 0x60), x)
        mstore(add(mPtr, 0x80), e)
        mstore(add(mPtr, 0xa0), r_mod)
        pop(staticcall(sub(gas(), 2000),0x05,mPtr,0xc0,mPtr,0x20))
        res := mload(mPtr)
      }
    }

    return success;

  }

}
