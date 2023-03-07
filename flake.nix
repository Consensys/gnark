{
  nixConfig.bash-prompt = "[nix-develop-gnark:] ";
  description = "gnark zk-SNARK library";
  inputs = {
    flake-utils = {
      url = "github:numtide/flake-utils";
    };
    nixpkgs = {
      url = "github:nixos/nixpkgs/nixpkgs-unstable";
    };
  };
  outputs =
    inputs@
    { flake-utils
    , nixpkgs
    , ...
    }:
      flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        gnark = pkgs.buildGoModule {
          pname = "gnark";
          version = "0.7.0";
          src = ./.;
          nativeBuildInputs = [ pkgs.git ];
          vendorHash = "sha512-CPND3xDH9Y2NyBlqPJG71q68JPl3CgAXmaUQs9UZhS/374vHgr4ba8bpY6uFAyr8D7PhTstX3KObot8cwG8NBA==";
          meta = with pkgs.lib; {
            description = "gnark zk-SNARK library";
            homepage = "https://github.com/ConsenSys/gnark";
            license = licenses.asl20;
            maintainers = [];
          };
        };
      in
      {
        packages.default = gnark;
        devShells.default = pkgs.mkShell {
          buildInputs = [ pkgs.go ];
        };
      }
    );
}
