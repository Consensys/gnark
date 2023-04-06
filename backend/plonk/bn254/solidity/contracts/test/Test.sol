pragma solidity ^0.8.0;

import {Fr} from '../crypto/Fr.sol';
import {UtilsFr} from '../crypto/HashFr.sol';
import {Polynomials} from '../crypto/Polynomials.sol';

contract TestContract {

  using UtilsFr for *;
  using Polynomials for *;
  using Fr for *;

  event PrintUint256(uint256 a);

  function test_hash(uint256 x, uint256 y, string memory dst) public returns(uint256 res){

    res = UtilsFr.hash_fr(x, y, dst);

    emit PrintUint256(res);

    return res;

  }

  function test_eval_ith_lagrange(uint256 i, uint256 z, uint256 w, uint256 n) public returns (uint256 res){

    res = Polynomials.compute_ith_lagrange_at_z(i, z, w, n);

    emit PrintUint256(res);

  }

  function test_compute_sum_li_zi(uint256[] memory inputs, uint256 z, uint256 w, uint256 n) public returns (uint256 res){

    res = Polynomials.compute_sum_li_zi(inputs, z, w, n);

    emit PrintUint256(res);

  }

  function test_batch_invert(uint256[] memory inputs) public {
    require( 0 == 1);
    emit PrintUint256(12321);
    uint256[] memory res = Fr.batch_inverse(inputs);
    for (uint i = 0; i < res.length; i++) {
      res[i] = Fr.mul(inputs[i], res[i]);
      emit PrintUint256(res[i]);
      require(res[i] == 1);
    }
  }

}