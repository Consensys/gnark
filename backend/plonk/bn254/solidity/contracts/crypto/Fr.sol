// Warning this code was contributed into gnark here: 
// https://github.com/ConsenSys/gnark/pull/358
// 
// It has not been audited and is provided as-is, we make no guarantees or warranties to its safety and reliability. 
// 
// According to https://eprint.iacr.org/archive/2019/953/1585767119.pdf
pragma solidity ^0.8.0;

library Fr {

    uint256 constant r_mod = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    // syntaxic sugar, TO REMOVE
    function add_assign(uint256 self, uint256 y) internal pure returns(uint256) {
      return add(self, y);
    }

    // syntaxic sugar, TO REMOVE
    function mul_assign(uint256 self, uint256 y) internal pure returns(uint256){
      return mul(self, y);
    }

    function add(uint256 x, uint256 y) internal pure returns(uint256 z) {
        z = addmod(x, y, r_mod);
        return z;
    }

    function sub(uint256 x, uint256 y) internal pure returns(uint256 z) {
        z = addmod(x, r_mod - y, r_mod);
        return z;
    }

    function mul(uint256 x, uint256 y) internal pure returns(uint256 z) {
        z = mulmod(x, y, r_mod);
        return z;
    }

    function pow(uint256 x, uint256 power) internal view returns(uint256) {
    uint256[6] memory input = [32, 32, 32, x, power, r_mod];
    uint256[1] memory result;
    bool success;
    assembly {
      success := staticcall(gas(), 0x05, input, 0xc0, result, 0x20)
    }
    require(success);
    return result[0];
  }

  function inverse(uint256 x) internal view returns(uint256) {
    require(x != 0);
    return pow(x, r_mod-2);
  }

  function div(uint256 x, uint256 y) internal view returns(uint256) {
    require(y != 0);
    y = inverse(y);
    return mul(x, y);
  }

  function batch_inverse(uint256[] memory x) internal view returns(uint256[] memory) {
    uint n = x.length;
    uint256[] memory prod_ahead = new uint256[](n);  // prod[i] = x[i] * ... * x[n-1]

    prod_ahead[n-1] = x[n-1];
    for (uint i = n-1; i > 0; i--) {
      prod_ahead[i-1] = mul(prod_ahead[i], x[i-1]);
    }

    uint256 inv = inverse(prod_ahead[0]);
   // emit PrintUint256(Fr.mul(inv, 2));
    uint256[] memory res = new uint256[](n);
    uint256 prod_behind = 1;

    for (uint i = 0; i < n; i++) {
      res[i] = mul(inv, prod_behind); // prod_behind = x[0] * ... * x[i-1]
      if (i + 1 != n) {
        res[i] = mul(res[i], prod_ahead[i+1]);
        prod_behind = mul(prod_behind, x[i]);
      }
    }
    return res;
  }
}
