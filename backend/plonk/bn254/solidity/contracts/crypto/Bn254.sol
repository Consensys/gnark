// It has not been audited and is provided as-is, we make no guarantees or warranties to its safety and reliability. 
// 
// According to https://eprint.iacr.org/archive/2019/953/1585767119.pdf
pragma solidity >=0.6.0;

library Bn254 {

  uint256 constant p_mod = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
  uint256 constant bn254_b_coeff = 3;

  struct G1Point {
    uint256 X;
    uint256 Y;
  }

  // coordinates are understood as eg X0+uX1
  struct G2Point {
    uint256 X0;
    uint256 X1;
    uint256 Y0;
    uint256 Y1;
  }

  function P1() internal pure returns (G1Point memory) {
    return G1Point(1, 2);
  }

  function new_g1(uint256 x, uint256 y) internal pure returns (G1Point memory) {
    return G1Point(x, y);
  }

  function new_g1_checked(uint256 x, uint256 y) internal pure returns (G1Point memory) {
    if (x == 0 && y == 0) {
      // point of infinity is (0,0)
      return G1Point(x, y);
    }

    // check encoding
    require(x < p_mod);
    require(y < p_mod);
    // check on curve
    uint256 lhs = mulmod(y, y, p_mod); // y^2
    uint256 rhs = mulmod(x, x, p_mod); // x^2
    rhs = mulmod(rhs, x, p_mod); // x^3
    rhs = addmod(rhs, bn254_b_coeff, p_mod); // x^3 + b
    require(lhs == rhs);

    return G1Point(x, y);
  }

  function new_g2(uint256 x0, uint256 x1, uint256 y0, uint256 y1) internal pure returns (G2Point memory) {
    return G2Point(x0, x1, y0, y1);
  }

  function P2() internal pure returns (G2Point memory)
  { 
    return G2Point(
      0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2,
      0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed,
      0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b,
      0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa
    );
  }

  function negate(G1Point memory self) internal pure {
    // The prime q in the base field F_q for G1
    if (self.Y == 0) {
      require(self.X == 0);
      return;
    }

    self.Y = p_mod - self.Y;
  }

  function point_add(G1Point memory p1, G1Point memory p2)
  internal view returns (G1Point memory r)
  {
    point_add_into_dest(p1, p2, r);
    return r;
  }

  function point_add_assign(G1Point memory p1, G1Point memory p2)
  internal view
  {
    point_add_into_dest(p1, p2, p1);
  }

  function point_add_into_dest(G1Point memory p1, G1Point memory p2, G1Point memory dest)
  internal view
  {
    
    bool success = false;
    assembly {
      if and(iszero(mload(p2)), iszero(mload(add(p2,0x20)))) {
        mstore(dest, mload(p1))
        mstore(add(dest, 0x20), mload(add(p1, 0x20)))
        return(0, 0) // TODO not sure about this
      }
      if and(iszero(mload(p1)), iszero(mload(add(p1,0x20)))){
        mstore(dest, p2)
        mstore(dest, mload(add(p2, 0x20)))
        return(0, 0) // TODO not sure about this
      }
      let mPtr := mload(0x40)
      mstore(mPtr, mload(p1))
      mstore(add(mPtr, 0x20), mload(add(p1, 0x20)))
      mstore(add(mPtr, 0x40), mload(p2))
      mstore(add(mPtr, 0x60), mload(add(p2, 0x20)))
      success := staticcall(
        gas(), 
        6, 
        mPtr, 
        0x80, 
        dest, 
        0x40
      )
    }
    require(success);
    // }
  }

  function point_sub_assign(G1Point memory p1, G1Point memory p2)
  internal view
  {
    point_sub_into_dest(p1, p2, p1);
  }

  function point_sub_into_dest(G1Point memory p1, G1Point memory p2, G1Point memory dest)
  internal view
  {
    bool success = false;
    uint256 p = p_mod;
    assembly {

      if and(iszero(mload(p2)), iszero(mload(add(p2,0x20)))) {
        mstore(dest, mload(p1))
        mstore(add(dest, 0x20), mload(add(p1, 0x20)))
        return(0, 0) // TODO not sure about this
      }
      if and(iszero(mload(p1)), iszero(mload(add(p1,0x20)))){
        mstore(dest, p2)
        mstore(dest, sub(p, mload(add(p2, 0x20))))
        return(0, 0) // TODO not sure about this
      }

      let mPtr := mload(0x40)
      mstore(mPtr, mload(p1))
      mstore(add(mPtr, 0x20), mload(add(p1, 0x20)))
      mstore(add(mPtr, 0x40), mload(p2))
      mstore(add(mPtr, 0x60), sub(p_mod, mload(add(p2, 0x20))))
      success := staticcall(
        gas(), 
        6, 
        mPtr, 
        0x80, 
        dest, 
        0x40
      )
    }
    require(success);
    // }
  }

  function copy_g1(G1Point memory dst, G1Point memory src)
  internal pure {
    assembly {
      mstore(dst, mload(src))
      mstore(add(dst, 0x20), mload(add(src, 0x20)))
    }
  }

  function point_mul(G1Point memory p, uint256 s)
  internal view returns (G1Point memory r)
  {
    point_mul_into_dest(p, s, r);
    return r;
  }

  function point_mul_assign(G1Point memory p, uint256 s)
  internal view
  {
    point_mul_into_dest(p, s, p);
  }

  function point_mul_into_dest(G1Point memory p, uint256 s, G1Point memory dest)
  internal view
  {
    bool success;
    assembly {
      let mPtr := mload(0x40)
      mstore(mPtr, mload(p))
      mstore(add(mPtr, 0x20), mload(add(p, 0x20)))
      mstore(add(mPtr, 0x40), s)
      success := staticcall(
        gas(), 
        7, 
        mPtr, 
        0x60, 
        dest, 
        0x40
      )
    }
    require(success);
  }

  function multi_exp(G1Point[] memory p, uint256[] memory s)
  internal view returns (G1Point memory r)
  {
    
    // uint256[] memory ss = new uint256[](25);
    // assembly {
    //     for {let i:=0} lt(i, 25) {i:=add(i,1)}
    //     {
    //         let offset := mul(i, 0x20)
    //         mstore(add(ss,add(offset,0x20)), mload(add(p,offset)))
    //     } 
    // }
    // for (uint i=0; i<25; i++){
    //     emit PrintUint256(ss[i]);
    // }

    require (p.length==s.length);
    G1Point memory tmp;

    bool success;
    assembly {

      // [s[0]]p[0]
      let n := mload(p)
      let offset := mul(add(n,1), 0x20)
      let mPtr := mload(0x40)
      mstore(mPtr, mload(add(p, offset)))
      mstore(add(mPtr, 0x20), mload(add(p, add(offset,0x20))))
      mstore(add(mPtr, 0x40), mload(add(s, 0x20)))
      success := staticcall(gas(),7,mPtr,0x60,r,0x40)

      for {let i:=1} lt(i,n) {i:=add(i,1)}
      {
        // tmp <- [s[i]]p[i]
        offset:=add(offset, 0x40)
        mstore(mPtr, mload(add(p, offset)))
        mstore(add(mPtr, 0x20), mload(add(p, add(offset, 0x20))))
        mstore(add(mPtr, 0x40), mload(add(s, add(0x20, mul(0x20,i)))))
        success := and(staticcall(gas(),7,mPtr,0x60,tmp,0x40), success)

        // r <- r + tmp
        mstore(mPtr, mload(r))
        mstore(add(mPtr,0x20), mload(add(r, 0x20)))
        mstore(add(mPtr,0x40), mload(tmp))
        mstore(add(mPtr,0x60), mload(add(tmp,0x20)))
        success := and(staticcall(gas(),6,mPtr,0x80,r,0x40), success)
      }
    }
    require(success, "multi_exp failed!");

    return r;
  }

  // Returns (e(a1, a2).e(b1, b2) == 1)s
  function pairingProd2(
      G1Point memory a1,
      G2Point memory a2,
      G1Point memory b1,
      G2Point memory b2
  ) internal view returns (bool) {
      bool success;
      uint256 out;
      assembly {
        let mPtr := mload(0x40)
        mstore(mPtr, mload(a1))
        mstore(add(mPtr, 0x20), mload(add(a1, 0x20)))
        mstore(add(mPtr, 0x40), mload(a2))
        mstore(add(mPtr, 0x60), mload(add(a2, 0x20)))
        mstore(add(mPtr, 0x80), mload(add(a2, 0x40)))
        mstore(add(mPtr, 0xa0), mload(add(a2, 0x60)))

        mstore(add(mPtr, 0xc0), mload(b1))
        mstore(add(mPtr, 0xe0), mload(add(b1, 0x20)))
        mstore(add(mPtr, 0x100), mload(b2))
        mstore(add(mPtr, 0x120), mload(add(b2, 0x20)))
        mstore(add(mPtr, 0x140), mload(add(b2, 0x40)))
        mstore(add(mPtr, 0x160), mload(add(b2, 0x60)))
        success := staticcall(
          gas(),
          8,
          mPtr,
          0x180,
          0x00,
          0x20
        )
        out := mload(0x00)
      }
      require(success, "Pairing check failed!");
      return (out != 0);
  }
}
