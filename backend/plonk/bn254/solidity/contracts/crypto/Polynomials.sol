// It has not been audited and is provided as-is, we make no guarantees or warranties to its safety and reliability. 
// 
// According to https://eprint.iacr.org/archive/2019/953/1585767119.pdf
pragma solidity >=0.6.0;

import {Fr} from './Fr.sol';

library Polynomials {

    using Fr for *;

    function compute_sum_li_zi(uint256[] memory inputs, uint256 z, uint256 w, uint256 n) internal view returns(uint256){
        if (inputs.length == 0) {
            return 0;
        }
        uint256[] memory basis = batch_compute_lagranges_at_z(inputs.length, z, w, n);
        uint256 res = Fr.mul(basis[0], inputs[0]);
        for (uint i = 1; i < inputs.length; i++) {
            res = Fr.add(res, Fr.mul(basis[i], inputs[i]));
        }
        return res;
    }

    // computes L_i(z) = w^j/n (z^n-1)/(z-w^j)
    function compute_ith_lagrange_at_z(uint256 i, uint256 z, uint256 w, uint256 n) 
    internal view returns (uint256) {

        require(i<n);
        require(z<Fr.r_mod);
        require(w<Fr.r_mod);

        uint256 r_mod = Fr.r_mod;
        bool success;
        assembly {

            // w**i
            let a := mload(0x40)
            mstore(a, 0x20)
            mstore(add(a, 0x20), 0x20)
            mstore(add(a, 0x40), 0x20)
            mstore(add(a, 0x60), w)
            mstore(add(a, 0x80), i)
            mstore(add(a, 0xa0), r_mod)
            success := staticcall(
                gas(),
                0x05,
                a,
                0xc0,
                0x00,
                0x20
            )
            w := mload(0x00)

            // z-w**i
            i := addmod(z, sub(r_mod, w), r_mod)

            // z**n
            a := mload(0x40)
            mstore(a, 0x20)
            mstore(add(a, 0x20), 0x20)
            mstore(add(a, 0x40), 0x20)
            mstore(add(a, 0x60), z)
            mstore(add(a, 0x80), n)
            mstore(add(a, 0xa0), r_mod)
            success := and(staticcall(
                gas(),
                0x05,
                a,
                0xc0,
                0x00,
                0x20
            ), success)
            z := mload(0x00)

            // z**n-1
            z := addmod(z, sub(r_mod, 1), r_mod)

             // n**-1
            a := mload(0x40)
            mstore(a, 0x20)
            mstore(add(a, 0x20), 0x20)
            mstore(add(a, 0x40), 0x20)
            mstore(add(a, 0x60), n)
            mstore(add(a, 0x80), sub(r_mod, 2))
            mstore(add(a, 0xa0), r_mod)
            success := and(staticcall(
                gas(),
                0x05,
                a,
                0xc0,
                0x00,
                0x20
            ), success)
            n := mload(0x00)

            // w**i/n
            w := mulmod(w, n, r_mod)

            // (z-w**i)**-1
            a := mload(0x40)
            mstore(a, 0x20)
            mstore(add(a, 0x20), 0x20)
            mstore(add(a, 0x40), 0x20)
            mstore(add(a, 0x60), i)
            mstore(add(a, 0x80), sub(r_mod, 2))
            mstore(add(a, 0xa0), r_mod)
            success := and(staticcall(
                gas(),
                0x05,
                a,
                0xc0,
                0x00,
                0x20
            ), success)
            i := mload(0x00)

            // w**i/n*(z-w**i)**-1
            w := mulmod(w, i, r_mod)

            // w**i/n*(z**n-1)*(z-w**i)**-1
            w := mulmod(w, z, r_mod)
        }
        require(success, "compute_ith_lagrange_at_z failed!");
        
        return w;
    }

    // computes L_0(z) = 1/n (z^n-1)/(z-1) and then recursively L_{i+1}(z) = L_i(z) * w * (z-w^i) / (z-w^{i+1}) for 0 <= i < k
    function batch_compute_lagranges_at_z(uint256 k, uint256 z, uint256 w, uint256 n) 
    internal view returns (uint256[] memory) {

        uint256[] memory den = new uint256[](k);
        uint256 wPowI = 1;
        for (uint i = 0; i < k; i++) {
            den[i] = Fr.sub(z, wPowI);
            if (i + 1 != k) {
                wPowI = Fr.mul(wPowI, w);
            }
        }

        den[0] = Fr.mul(den[0], n);
        uint256[] memory res = Fr.batch_inverse(den);

        wPowI = Fr.pow(z, n);
        wPowI = Fr.sub(wPowI, 1);   //abusing the name wPowI

        res[0] = Fr.mul(wPowI, res[0]);
        den[0] = Fr.sub(z, 1);  // abusing the name den[0]

        for (uint i = 1; i < k; i++) {
            res[i] = Fr.mul(res[i], den[i-1]);  //              (z-w^i) / (z-w^{i+1})
            res[i] = Fr.mul(res[i], w);         //          w * (z-w^i) / (z-w^{i+1})
            res[i] = Fr.mul(res[i], res[i-1]);  // L_i(z) * w * (z-w^i) / (z-w^{i+1})
        }

        return res;
    }
}