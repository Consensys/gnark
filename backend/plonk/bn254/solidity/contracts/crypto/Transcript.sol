pragma solidity ^0.8.19;
pragma experimental ABIEncoderV2;

import {Bn254} from '.Bn254.sol';

library TranscriptLibrary {
 
    struct Transcript {
        bytes32 previous_randomness;
        bytes bindings;
        string name;
        uint32 challenge_counter;
    }

    function new_transcript() internal pure returns (Transcript memory t) {
        t.challenge_counter = 0;
    }

    function set_challenge_name(Transcript memory self, string memory name) internal pure {
        self.name = name;
    }

    function update_with_u256(Transcript memory self, uint256 value) internal pure {
        self.bindings = abi.encodePacked(self.bindings, value);
    }

    function update_with_fr(Transcript memory self, uint254 value) internal pure {
        self.bindings = abi.encodePacked(self.bindings, value.value);
    }

    function update_with_g1(Transcript memory self, Bn254.G1Point memory p) internal pure {
        self.bindings = abi.encodePacked(self.bindings, p.X, p.Y);
    }

    function get_challenge(Transcript memory self) internal pure returns(uint256 challenge) {
        bytes32 query;
        if (self.challenge_counter != 0) {
            query = sha256(abi.encodePacked(self.name, self.previous_randomness, self.bindings));
        } else {
            query = sha256(abi.encodePacked(self.name, self.bindings));
        }
        self.challenge_counter += 1;
        self.previous_randomness = query;
        challenge = query % Bn254.r_mod;
        self.bindings = "";
    }
}
