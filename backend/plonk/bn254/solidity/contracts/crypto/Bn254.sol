// Warning this code was contributed into gnark here: 
// https://github.com/ConsenSys/gnark/pull/358
// 
// It has not been audited and is provided as-is, we make no guarantees or warranties to its safety and reliability. 
// 
// According to https://eprint.iacr.org/archive/2019/953/1585767119.pdf
pragma solidity ^0.8.0;
pragma experimental ABIEncoderV2;

library Bn254 {

  uint256 constant p_mod = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
  uint256 constant r_mod = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
  uint256 constant bn254_b_coeff = 3;

  struct G1Point {
    uint256 X;
    uint256 Y;
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

  // Encoding of field elements is: X[0] * z + X[1]
  struct G2Point {
    uint[2] X;
    uint[2] Y;
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

  function new_g2(uint256[2] memory x, uint256[2] memory y) internal pure returns (G2Point memory) {
    return G2Point(x, y);
  }

  function copy_g1(G1Point memory self) internal pure returns (G1Point memory result) {
    result.X = self.X;
    result.Y = self.Y;
  }

  function P2() internal pure returns (G2Point memory) {
    // for some reason ethereum expects to have c1*v + c0 form

    return G2Point(
      [0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2,
      0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed],
      [0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b,
      0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa]
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
    if (p2.X == 0 && p2.Y == 0) {
      // we add zero, nothing happens
      dest.X = p1.X;
      dest.Y = p1.Y;
      return;
    } else if (p1.X == 0 && p1.Y == 0) {
      // we add into zero, and we add non-zero point
      dest.X = p2.X;
      dest.Y = p2.Y;
      return;
    } else {
      uint256[4] memory input;

      input[0] = p1.X;
      input[1] = p1.Y;
      input[2] = p2.X;
      input[3] = p2.Y;

      bool success = false;
      assembly {
          success := staticcall(gas(), 6, input, 0x80, dest, 0x40)
      }
      require(success);
    }
  }

  function point_sub_assign(G1Point memory p1, G1Point memory p2)
  internal view
  {
    point_sub_into_dest(p1, p2, p1);
  }

  function point_sub_into_dest(G1Point memory p1, G1Point memory p2, G1Point memory dest)
  internal view
  {
    if (p2.X == 0 && p2.Y == 0) {
      // we subtracted zero, nothing happens
      dest.X = p1.X;
      dest.Y = p1.Y;
      return;
    } else if (p1.X == 0 && p1.Y == 0) {
      // we subtract from zero, and we subtract non-zero point
      dest.X = p2.X;
      dest.Y = p_mod - p2.Y;
      return;
    } else {
      uint256[4] memory input;

      input[0] = p1.X;
      input[1] = p1.Y;
      input[2] = p2.X;
      input[3] = p_mod - p2.Y;

      bool success = false;
      assembly {
        success := staticcall(gas(), 6, input, 0x80, dest, 0x40)
      }
      require(success);
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
    uint[3] memory input;
    input[0] = p.X;
    input[1] = p.Y;
    input[2] = s;
    bool success;
    assembly {
      success := staticcall(gas(), 7, input, 0x60, dest, 0x40)
    }
    require(success);
  }

  function pairing(G1Point[] memory p1, G2Point[] memory p2)
  internal view returns (bool)
  {
    require(p1.length == p2.length);
    uint elements = p1.length;
    uint inputSize = elements * 6;
    uint[] memory input = new uint[](inputSize);
    for (uint i = 0; i < elements; i++)
    {
      input[i * 6 + 0] = p1[i].X;
      input[i * 6 + 1] = p1[i].Y;
      input[i * 6 + 2] = p2[i].X[0];
      input[i * 6 + 3] = p2[i].X[1];
      input[i * 6 + 4] = p2[i].Y[0];
      input[i * 6 + 5] = p2[i].Y[1];
    }
    uint[1] memory out;
    bool success;
    assembly {
        success := staticcall(gas(), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
    }
    require(success);
    return out[0] != 0;
  }

  /// Convenience method for a pairing check for two pairs.
  function pairingProd2(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2)
  internal view returns (bool)
  {
    G1Point[] memory p1 = new G1Point[](2);
    G2Point[] memory p2 = new G2Point[](2);
    p1[0] = a1;
    p1[1] = b1;
    p2[0] = a2;
    p2[1] = b2;
    return pairing(p1, p2);
  }
}
