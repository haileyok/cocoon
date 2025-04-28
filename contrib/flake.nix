{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
  };
  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems f;
      outputsBySystem = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          packages = {
            default = pkgs.buildGo124Module {
              pname = "cocoon";
              version = "0.1.0";
              src = ../.;
              vendorHash = "sha256-kFwd2FnOueEOg/YRTQ8c7/iAO3PoO3yzWyVDFu43QOs=";
              meta.mainProgram = "cocoon";
            };
          };
          devShells = {
            default = pkgs.mkShell {
              buildInputs = [
                pkgs.go_1_24
                pkgs.gopls
                pkgs.gotools
                pkgs.go-tools
              ];
            };
          };
        });
      mergeOutputs = outputType:
        nixpkgs.lib.mapAttrs (system: systemOutputs: systemOutputs.${outputType} or {}) outputsBySystem;
    in
    {
      packages = mergeOutputs "packages";
      devShells = mergeOutputs "devShells";
    };
}
