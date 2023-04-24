 // It has not been audited and is provided as-is, we make no guarantees or warranties to its safety and reliability. 
// 
// According to https://eprint.iacr.org/archive/2019/953/1585767119.pdf
pragma solidity >=0.6.0;

library Fr {

    uint256 constant r_mod = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    function add(uint256 x, uint256 y) internal pure returns(uint256 z) {
        assembly {
          z := addmod(x, y, r_mod)
        }
        return z;
    }

    function sub(uint256 x, uint256 y) internal pure returns(uint256 z) {
        assembly {
          z := addmod(x, sub(r_mod, y), r_mod)
        }
        return z;
    }

    function mul(uint256 x, uint256 y) internal pure returns(uint256 z) {
        assembly {
          z := mulmod(x, y, r_mod)
        }
        return z;
    }

    function pow(uint256 x, uint256 power) 
    internal view returns(uint256) 
    {
        bool success;
        uint256 result;
        uint256 p = r_mod;
        assembly {
          let mPtr := mload(0x40)
          mstore(mPtr, 0x20)
          mstore(add(mPtr, 0x20), 0x20)
          mstore(add(mPtr, 0x40), 0x20)
          mstore(add(mPtr, 0x60), x)
          mstore(add(mPtr, 0x80), power)
          mstore(add(mPtr, 0xa0), p)
          success := staticcall(
            gas(),
            0x05,
            mPtr,
            0xc0,
            0x00,
            0x20
          )
          result := mload(0x00)
        }
        require(success);
        return result;
    }

    function inverse(uint256 x) 
    internal view returns(uint256) 
    {
      bool success;
        uint256 result;
        uint256 p = r_mod;
        assembly {
          let mPtr := mload(0x40)
          mstore(mPtr, 0x20)
          mstore(add(mPtr, 0x20), 0x20)
          mstore(add(mPtr, 0x40), 0x20)
          mstore(add(mPtr, 0x60), x)
          mstore(add(mPtr, 0x80), sub(p, 2))
          mstore(add(mPtr, 0xa0), p)
          success := staticcall(
            gas(),
            0x05,
            mPtr,
            0xc0,
            0x00,
            0x20
          )
          result := mload(0x00)
        }
        require(success);
        return result;
    }

    function batch_inverse(uint256[] memory x) 
    internal view returns(uint256[] memory) 
    {
      uint n = x.length;
      uint256[] memory prod_ahead = new uint256[](n);  // prod[i] = x[i] * ... * x[n-1]
      uint256[] memory res = new uint256[](n);
      uint256 r = r_mod;
      bool success;

      assembly {

        let s := mload(x)
     
        prod_ahead := add(prod_ahead, add(0x20, mul(sub(s,1), 0x20)))
        x := add(x, add(0x20, mul(sub(s,1), 0x20)))
        mstore(prod_ahead, mload(x))
        for {let i:=1} lt(i, s) {i:=add(i,1)} {
          x := sub(x, 0x20)
          let a := mulmod(mload(prod_ahead), mload(x), r)
          prod_ahead := sub(prod_ahead, 0x20)
          mstore(prod_ahead, a)
        }

        let mPtr := mload(0x40)
        mstore(mPtr, 0x20)
        mstore(add(mPtr, 0x20), 0x20)
        mstore(add(mPtr, 0x40), 0x20)
        mstore(add(mPtr, 0x60), mload(prod_ahead))
        mstore(add(mPtr, 0x80), sub(r, 2))
        mstore(add(mPtr, 0xa0), r)
        success := staticcall(
          gas(),
          0x05,
          mPtr,
          0xc0,
          0x00,
          0x20
        )
        let inv := mload(0x00)

        let prod_behind := 1

        res := add(res, 0x20)
        prod_ahead := add(prod_ahead, 0x20)
        for {let i:=0} lt(i,sub(s,1)) {i:=add(i,1)}{
          mstore(res, mulmod(inv, prod_behind, r))
          mstore(res, mulmod(mload(res), mload(prod_ahead), r))
          prod_behind := mulmod(prod_behind, mload(x), r)
          x := add(x, 0x20)
          res := add(res, 0x20)
          prod_ahead := add(prod_ahead, 0x20)
        }
        mstore(res, mulmod(inv, prod_behind, r))

        res := sub(res, add(0x20, mul(0x20, sub(s, 1))))
      }
      require(success, "inverse failed!");

      return res;
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
