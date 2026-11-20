# The sliver operator binaries (sliver-server, sliver-client), built pure: vendored Go
# modules, CGO off, and the embed tree server/assets/fs prefilled from the sliver-assets
# fixed-output derivation. The go:embed patterns in server/assets/assets_*.go need those
# files at compile time; their content matters at server runtime, when the server unpacks
# the toolchains to build implants (assets.Setup, server/cli/daemon.go).
#
# No patch step: this fork's git history carries the operator's fixes (the PrintC2Profiles
# panic fix is commit a1876c00e), so a clean checkout of this fork is the patched source.
#
# Build tags mirror the host build they replace: -tags go_sqlite,server and
# -tags go_sqlite,client (see infra/sliver-ops.sh build() in the xmapa repo).
{
  lib,
  buildGoModule,
  go,
  assets,
  revision, # git commit of this fork the flake input resolved to, for version strings

}:

let
  mkBin =
    {
      pname,
      subPackage,
      tags,
    }:
    buildGoModule {
      inherit pname;
      version = "1.27.3-${lib.substring 0 8 revision}";
      src = lib.cleanSource ../.;
      # vendor/ is committed; the build reads modules from the tree, no fetch, no hash.
      vendorHash = null;

      # Prefill the embed tree. The committed tree has fs/*.txt only (the rest is
      # gitignored); the assets derivation supplies src.zip and the per-platform
      # toolchains the go:embed patterns demand.
      postPatch = ''
        cp -r "${assets}"/* server/assets/fs/
      '';

      env = {
        CGO_ENABLED = "0";
        GOFLAGS = "-mod=vendor";
      };

      inherit tags;

      subPackages = [ subPackage ];

      # buildGoModule names the binary after the sub-package directory (server, client);
      # every consumer (sliver-ops.sh, compose.yaml, preflight.sh) knows them as
      # sliver-server / sliver-client.
      postInstall = ''
        mv "$out/bin/${subPackage}" "$out/bin/${pname}"
      '';

      # The flake source has .git stripped, so debug.ReadBuildInfo cannot fill
      # vcs.revision; set the version package vars at link time instead (both
      # client/version and server/version carry the same vars).
      ldflags = [
        "-s"
        "-w"
        "-X github.com/bishopfox/sliver/${subPackage}/version.Version=1.27.3-${lib.substring 0 9 revision}"
        "-X github.com/bishopfox/sliver/${subPackage}/version.GitCommit=${revision}"
      ];

      meta = {
        description = "Sliver ${pname} (tahiba96 fork, WG-over-HTTPS)";
        mainProgram = pname;
      };
    };
in
{
  sliver-server = mkBin {
    pname = "sliver-server";
    subPackage = "server";
    tags = [ "go_sqlite,server" ];
  };
  sliver-client = mkBin {
    pname = "sliver-client";
    subPackage = "client";
    tags = [ "go_sqlite,client" ];
  };
}
