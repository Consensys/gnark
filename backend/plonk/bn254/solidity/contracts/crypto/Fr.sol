// Warning this code was contributed into gnark here: 
// https://github.com/ConsenSys/gnark/pull/358
// 
// It has not been audited and is provided as-is, we make no guarantees or warranties to its safety and reliability. 
// 
// According to https://eprint.iacr.org/archive/2019/953/1585767119.pdf
pragma solidity ^0.8.0;

library Fr {

    uint256 constant r_mod = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    function add_assign(uint256 self, uint256 other) internal pure {
        self = addmod(self, other, r_mod);
    }

    function sub_assign(uint256 self, uint256 other) internal pure {
        self = addmod(self, r_mod - other, r_mod);
    }

    function mul_assign(uint256 self, uint256 other) internal pure {
        self = mulmod(self, other, r_mod);
    }

    function pow(uint256 x, uint256 power) internal view returns (uint256) {
    uint256[6] memory input = [32, 32, 32, x, power, r_mod];
    uint256[1] memory result;
    bool success;
    assembly {
      success := staticcall(gas(), 0x05, input, 0xc0, result, 0x20)
    }
    require(success);
    return result[0];
  }

  function inverse(uint256 x) internal view returns (uint256) {
    require(x != 0);
    return pow(x, r_mod-2);
  }

  // computes L_i(z) = w^j/n (z^n-1)/(z-w^j)
  function compute_lagrange(uint256 i, uint256 z, uint256 w, uint256 n) internal view returns (uint256) {

    require(i<n);
    require(z<r_mod);
    require(w<r_mod);

    w = pow(w, i);                  // w**i
    i = addmod(z, r_mod-w, r_mod);  // z-w**i
    z = pow(z, n);                  // z**n
    z = addmod(z, r_mod-1, r_mod);  // z**n-1
    n = inverse(n);                 // n**-1
    w = mulmod(w, n, r_mod);        // w**i/n
    i = inverse(i);                 // (z-w**i)**-1
    w = mulmod(w, i, r_mod);        // w**i/n*(z-w**i)**-1
    w = mulmod(w, z, r_mod);        // w**i/n*(z**n-1)*(z-w**i)**-1
    
    return w;
  }

}
