{
  description = "sliver — tahiba96 fork of BishopFox/sliver: WG-over-HTTPS + the profile-name panic fix, packaged for the xmapa kit";

  # ONE pin across the kit: xmapa/flake.nix pins nixpkgs and folds this input onto it
  # (inputs.sliver.inputs.nixpkgs.follows). Keep this URL identical to that pin so a
  # standalone eval here agrees with the kit's eval.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      # go.mod says `go 1.27.3`; nixpkgs' default go at this pin is 1.26.x. Same override the
      # xmapa flake applies (buildGo127Module there, mirrored here).
      buildGo127Module = pkgs: pkgs.buildGoModule.override { go = pkgs.go_1_27; };
      # revision: the flake source itself is a git tree (nix exports it with .git
      # stripped), so self.rev is the commit the input was fetched at — or dirtyRev for a
      # dirty local tree. Pass it down so the binaries can say what they were built from.
      revision = self.rev or self.dirtyRev or "00000000";
    in
    {
      packages = forAllSystems (
        pkgs:
        let
          # The packer FOD first (network, fixed-output), then the pure builds that embed it.
          assets = pkgs.callPackage ./nix/assets.nix { go = pkgs.go_1_27; };
          bins = pkgs.callPackage ./nix/package.nix {
            buildGoModule = buildGo127Module pkgs;
            go = pkgs.go_1_27;
            inherit assets revision;
          };
        in
        {
          # Internal: the packer FOD, exposed so its hash can be bootstrapped and
          # its output inspected standalone.
          inherit assets;
          inherit (bins) sliver-server sliver-client;
          default = pkgs.symlinkJoin {
            name = "sliver";
            paths = [
              bins.sliver-server
              bins.sliver-client
            ];
            meta.mainProgram = "sliver-server";
          };
        }
      );
    };
}
