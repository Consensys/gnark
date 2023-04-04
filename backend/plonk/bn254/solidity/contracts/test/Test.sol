pragma solidity ^0.8.0;

import {UtilsFr} from '../crypto/HashFr.sol';

contract TestContract {

  using UtilsFr for *;

  event PrintUint256(uint256 a);

  function test_hash(uint256 x, uint256 y, string memory dst) public returns(uint256 res){

    res = UtilsFr.hash_fr(x, y, dst);

    emit PrintUint256(res);

    return res;

  }

}