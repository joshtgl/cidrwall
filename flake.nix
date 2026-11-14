{
  description = "Atomically enforce CIDR blocklists with nftables, XDP, and TCX";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    crane.url = "github:ipetkov/crane";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      crane,
      rust-overlay,
    }:
    let
      systems = [ "x86_64-linux" ];
      forAllSystems =
        f:
        nixpkgs.lib.genAttrs systems (
          system:
          f (
            import nixpkgs {
              inherit system;
              overlays = [ rust-overlay.overlays.default ];
            }
          )
        );
      mkPackage = pkgs: pkgs.callPackage ./nix/package.nix { craneLib = crane.mkLib pkgs; };
    in
    {
      packages = forAllSystems (pkgs: {
        cidrwall = mkPackage pkgs;
        default = self.packages.${pkgs.stdenv.hostPlatform.system}.cidrwall;
      });

      overlays.default = final: _prev: {
        cidrwall = self.packages.${final.stdenv.hostPlatform.system}.cidrwall;
      };

      nixosModules.cidrwall = {
        imports = [ ./nix/module.nix ];
        nixpkgs.overlays = [ self.overlays.default ];
      };
      nixosModules.default = self.nixosModules.cidrwall;

      checks = forAllSystems (pkgs: {
        package = self.packages.${pkgs.stdenv.hostPlatform.system}.cidrwall;
      });

      formatter = forAllSystems (pkgs: pkgs.nixfmt);
    };
}
