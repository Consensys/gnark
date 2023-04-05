// Warning this code was contributed into gnark here: 
// https://github.com/ConsenSys/gnark/pull/358
// 
// It has not been audited and is provided as-is, we make no guarantees or warranties to its safety and reliability. 
// 
// According to https://eprint.iacr.org/archive/2019/953/1585767119.pdf
pragma solidity ^0.8.0;

import {Fr} from './Fr.sol';

library Polynomials {

    using Fr for *;

    // returns Sum_i L_i(z)*inputs[i]
    function compute_sum_li_zi(uint256[] memory inputs, uint256 z, uint256 w, uint256 n) internal view returns(uint256){

        uint256 zn = Fr.pow(z, n);
        uint256 accW = 1;
        uint256 k = inputs.length;

        uint256 res;
        uint256 lagrange;
        uint256 accDen;
        uint256 num;

        accDen = Fr.sub(z, accW);
        num = Fr.sub(zn, 1);
        lagrange = Fr.div(num, accDen);
        lagrange = Fr.div(lagrange, n);
        res = Fr.mul(lagrange, inputs[0]);

        for (uint i=1; i<k; i++) {

            lagrange = Fr.mul(lagrange, accDen);
            lagrange = Fr.mul(lagrange, w);
            
            accW = Fr.mul(accW, w);
            accDen = Fr.sub(z, accW);

            lagrange = Fr.div(lagrange, accDen);

            num = Fr.mul(lagrange, inputs[i]);
            res = Fr.add(num, res);

        }

        return res;

    }

    // computes L_i(z) = w^j/n (z^n-1)/(z-w^j)
    function compute_ith_lagrange_at_z(uint256 i, uint256 z, uint256 w, uint256 n) internal view returns (uint256) {

        require(i<n);
        require(z<Fr.r_mod);
        require(w<Fr.r_mod);

        w = Fr.pow(w, i);               // w**i
        i = Fr.sub(z, w);  // z-w**i
        z = Fr.pow(z, n);               // z**n
        z = Fr.sub(z, 1);  // z**n-1
        n = Fr.inverse(n);              // n**-1
        w = Fr.mul(w, n);        // w**i/n
        i = Fr.inverse(i);              // (z-w**i)**-1
        w = Fr.mul(w, i);        // w**i/n*(z-w**i)**-1
        w = Fr.mul(w, z);        // w**i/n*(z**n-1)*(z-w**i)**-1
        
        return w;
    }

}