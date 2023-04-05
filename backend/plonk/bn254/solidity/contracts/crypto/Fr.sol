// Warning this code was contributed into gnark here: 
// https://github.com/ConsenSys/gnark/pull/358
// 
// It has not been audited and is provided as-is, we make no guarantees or warranties to its safety and reliability. 
// 
// According to https://eprint.iacr.org/archive/2019/953/1585767119.pdf
pragma solidity ^0.8.0;

library Fr {

    uint256 constant r_mod = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

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

}
