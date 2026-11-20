# Sliver's implant toolchains (go, zig, garble) and the codename wordlists, packed by
# Sliver's own packer: this derivation runs `go run ./util/cmd/assets` from the source
# tree, so the archive layout cannot drift from what the server's unpacker
# (server/assets/assets-helpers.go) expects at unpack time.
#
# The packer downloads from dl.google.com, the ziglang.org community mirrors and GitHub
# releases, so this is a fixed-output derivation: it gets network, and its result is
# pinned by the recursive sha256 in outputHash. The wordlists (fs/*.txt) it starts from
# are committed in the source tree; the toolchain artifacts are produced here.
#
# To refresh the hash: set outputHash to lib.fakeHash, run the build, copy the
# "got: sha256:..." line into outputHash. The artifacts follow the constants in
# util/assets/constants.go (go 1.27.3, zig 0.15.2, garble 1.27.3b); bumping any of those
# means bumping this hash.
{
  lib,
  stdenv,
  go,
}:

stdenv.mkDerivation {
  name = "sliver-assets";
  src = lib.cleanSource ../.;

  # The packer writes into server/assets/fs of ITS OWN checkout, and its
  # findRepoRoot() walks up from cwd looking for go.mod — so run in place.
  # (No dontBuild: the work happens in buildPhase.)
  unpackPhase = ''
    cp -r "$src" ./src
    chmod -R u+w ./src
    cd ./src
  '';

  nativeBuildInputs = [ go ];

  outputHashAlgo = "sha256";
  outputHashMode = "recursive";
  outputHash = "sha256-sLkeBHyUgLnbnyYTxD4lIKtPz87U9LDSfVyLdDhnP5M=";

  buildPhase = ''
    export GOCACHE="$PWD/.gocache"
    export GOPATH="$PWD/.gopath"
    export HOME="$PWD/.home"
    export GOFLAGS=-mod=vendor
    export CGO_ENABLED=0
    mkdir -p "$HOME"
    go run ./util/cmd/assets --quiet
    mkdir -p "$out"
    cp -r server/assets/fs/* "$out/"
  '';

  installPhase = "true";

  meta = {
    description = "Sliver server embedded implant toolchains, packed by Sliver's own packer";
  };
}
