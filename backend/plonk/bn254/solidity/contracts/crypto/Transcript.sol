pragma solidity ^0.8.19;
pragma experimental ABIEncoderV2;

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

    function update_with_fr(Transcript memory self, PairingsBn254.Fr memory value) internal pure {
        self.bindings = abi.encodePacked(self.bindings, value.value);
    }

    function update_with_g1(Transcript memory self, PairingsBn254.G1Point memory p) internal pure {
        self.bindings = abi.encodePacked(self.bindings, p.X, p.Y);
    }

    function get_challenge(Transcript memory self) internal pure returns(PairingsBn254.Fr memory challenge) {
        bytes32 query;
        if (self.challenge_counter != 0) {
            query = sha256(abi.encodePacked(self.name, self.previous_randomness, self.bindings));
        } else {
            query = sha256(abi.encodePacked(self.name, self.bindings));
        }
        self.challenge_counter += 1;
        self.previous_randomness = query;
        challenge = PairingsBn254.Fr({value: uint256(query) % PairingsBn254.r_mod});
        self.bindings = "";
    }
}
