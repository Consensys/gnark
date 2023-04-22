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

        uint256 r = Fr.r_mod;
        uint256[] memory den = new uint256[](k);
        uint256 wPowI = 1;
     
        assembly {
            den := add(den, 0x20)
            for {let i:=0} lt(i,sub(k, 1)) {i:=add(i,1)}
            {
                mstore(den, addmod(z, sub(r, wPowI), r))
                wPowI := mulmod(wPowI, w, r)
                den := add(den, 0x20)
            }
            mstore(den, addmod(z, sub(r, wPowI), r))
            den := sub(den, mul(sub(k, 1), 0x20))
            mstore(den, mulmod(mload(den), n, r))
            den := sub(den, 0x20)
        }
        uint256[] memory res = Fr.batch_inverse(den);
        bool success;
        assembly {

            // wPowI <- z^n
            let mPtr := mload(0x40)
            mstore(mPtr, 0x20)
            mstore(add(mPtr, 0x20), 0x20)
            mstore(add(mPtr, 0x40), 0x20)
            mstore(add(mPtr, 0x60), z)
            mstore(add(mPtr, 0x80), n)
            mstore(add(mPtr, 0xa0), r)
            success := staticcall(gas(),0x05,mPtr,0xc0,0x00,0x20)
            wPowI := mload(0x00)

            // wPowI <- z^n-1
            wPowI := addmod(wPowI, sub(r, 1), r)

            res := add(res, 0x20)
            mstore(res, mulmod(wPowI, mload(res), r))
            den := add(den, 0x20)
            mstore(den, addmod(z, sub(r,1), r))
            
            for {let i:=1} lt(i,k) {i := add(i,1)}
            {
                res := add(res, 0x20)
                mstore(res, mulmod(mload(res), mload(den), r))              // (z-w^i) / (z-w^{i+1})
                mstore(res, mulmod(mload(res), w, r))                       //w * (z-w^i) / (z-w^{i+1})
                mstore(res, mulmod(mload(res), mload(sub(res, 0x20)), r))   // L_i(z) * w * (z-w^i) / (z-w^{i+1})
                den := add(den, 0x20)
            }
            res := sub(res, mul(k, 0x20))
        }
        require(success, "batch_compute_lagranges_at_z failed!");

        return res;
    }
}