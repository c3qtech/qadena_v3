#!/bin/zsh
#
# Build artifacts/epdc_register.wasm reproducibly, mirroring enf-smart-contracts/optimizer.sh.
#
# 0.17.0, NOT the 0.16.0 the sibling contracts pin.  0.16.0 ships cargo 1.78, which cannot parse a
# manifest that declares edition 2024 -- and this crate's Cargo.lock, resolved 2026-09-10, pins
# zeroize 1.9.0 and base64ct 1.8.3, both of which moved to that edition.  Resolution reads those
# manifests before anything is compiled, so 0.16.0 dies immediately with "feature `edition2024` is
# required".  The crates arrive only through the TEST dependencies (cw-multi-test -> k256 ->
# elliptic-curve -> spki/der) and the wasm never contains them, which is why the failure looks
# unrelated to this contract.
#
# enf and cadena still build on 0.16.0 only because their locks were resolved 2026-07-30, before
# those releases; a `cargo update` in either one breaks them the same way.  Pinning the lock back is
# the wrong fix -- it pins test-only crates to dodge a toolchain limit.  Pinning base64ct to 1.6.0
# was tried and changes nothing in the wasm: same 233,506 bytes, same hash.
#
# THE TWO IMAGE VARIANTS DO NOT AGREE, and upstream documents this: the arm64 image below is a
# convenience for Apple Silicon, not a reproducible build.  Same source and lock give
#   amd64 (cosmwasm/optimizer):       42d33e958fc19b31454784c6dc50153763be8d3e712effbe5f952b69086c9e1a
#   arm64 (cosmwasm/optimizer-arm64): 4f2707655a260f70b34cfff73e4b54e515c7cd102824ba119bf3edc37a18c93b
# Both are 233,506 bytes and both deploy.  For anything whose hash is published or cited -- a
# release, or a code id a verifier checks -- force the amd64 image by uncommenting M="x86_64" below,
# and expect it to be several times slower under emulation.

U="cosmwasm"
V="0.17.0"

M=$(uname -m)
#M="x86_64" # Force Intel arch

A="linux/${M/x86_64/amd64}"
S=${M#x86_64}
S=${S:+-$S}

docker run --platform $A --rm -v "$(pwd)":/code \
  --mount type=volume,source="$(basename "$(pwd)")_cache",target=/target \
  --mount type=volume,source=registry_cache,target=/usr/local/cargo/registry \
  $U/optimizer$S:$V
