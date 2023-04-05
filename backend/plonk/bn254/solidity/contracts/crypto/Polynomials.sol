// Warning this code was contributed into gnark here: 
// https://github.com/ConsenSys/gnark/pull/358
// 
// It has not been audited and is provided as-is, we make no guarantees or warranties to its safety and reliability. 
// 
// According to https://eprint.iacr.org/archive/2019/953/1585767119.pdf
pragma solidity ^0.8.0;

import {Fr} from './Fr.sol';

library Polynomials {

    using Fr for uint256;

    // // returns Sum_i L_i(z)*inputs[i]
    // function compute_sum_li_zi(uint256[] inputs, uint256 z, uint256 w, uint256 n) internal view returns(uint256){

    //     uint256 z;
    //     uint256 zn = Fr.pow(z, n);
    //     uint256 nInv = Fr.inverse(nInv);
    //     uint256 acc = 1;
    //     uint256 den;
    //     uint256 k := inputs.length;

    //     uint256 res;
    //     res.sub_assign(zn, 1);
    //     den.sub_assign(z, 1);
    //     den.mul_assign()

    // }

    // computes L_i(z) = w^j/n (z^n-1)/(z-w^j)
    function compute_ith_lagrange_at_z(uint256 i, uint256 z, uint256 w, uint256 n) internal view returns (uint256) {

        require(i<n);
        require(z<Fr.r_mod);
        require(w<Fr.r_mod);

        w = Fr.pow(w, i);               // w**i
        i = addmod(z, Fr.r_mod-w, Fr.r_mod);  // z-w**i
        z = Fr.pow(z, n);               // z**n
        z = addmod(z, Fr.r_mod-1, Fr.r_mod);  // z**n-1
        n = Fr.inverse(n);              // n**-1
        w = mulmod(w, n, Fr.r_mod);        // w**i/n
        i = Fr.inverse(i);              // (z-w**i)**-1
        w = mulmod(w, i, Fr.r_mod);        // w**i/n*(z-w**i)**-1
        w = mulmod(w, z, Fr.r_mod);        // w**i/n*(z**n-1)*(z-w**i)**-1
        
        return w;
    }

}