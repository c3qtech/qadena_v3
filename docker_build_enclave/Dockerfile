# syntax=docker/dockerfile:1.4

# go to https://github.com/orgs/edgelesssys/packages/container/package/ego%2Fbuild-base and
# find out the correct version (e.g. 1.8.1) and click on the "..." beside the Digest

# 1.7.0
#FROM ghcr.io/edgelesssys/ego/build-base@sha256:f699547818bcbcef9bfbc60d1ef7b811a76f8133c1c8505d8c6681bd1623bf79 AS base

# 1.8.1
# THE SHARED, DIGEST-PINNED BUILD BASE.  Everything this used to install itself -- the EGo
# base, 108 pinned apt packages, Go and the EGo .deb -- is baked in; see
# docker_build_base/Dockerfile for why, and for the rule that this image is only correct if
# the enclave built from it keeps the SAME measurement.
# Pinned by DIGEST, never a tag: a re-push must not be able to change what we build against.
FROM ghcr.io/c3qtech/qadena-build-base@sha256:47bb675e748ccbec0a91f9f28c248bc4ffabfaf3143bcc335754cce947348128 AS base


# EVERYTHING THAT USED TO BE HERE NOW LIVES IN THE BASE IMAGE.
#
# The apt snapshot setup, the 108 pinned packages, /locked-packages.txt, the Go tarball and the EGo
# .deb were all installed right here, identically, in three separate Dockerfiles.  They moved to
# docker_build_base/Dockerfile, which is built once and pinned above by digest.
#
# The point is not tidiness.  A routine build fetched from snapshot.ubuntu.com, github.com and
# go.dev with no checksum verification, and two of those three failed in a single day -- once
# taking a 40-minute build down after the purge had already destroyed both SGX nodes.  Nothing
# below this line touches the network.


FROM base AS build

ENV DOCKER_BUILD=1

COPY ./ /build/

WORKDIR /build

RUN zsh buildscripts/build_enclave.sh --build-reproducible

# Use the export target if you just want to use Docker to build your app and then export it
FROM scratch AS export
COPY --from=build /build/cmd/qadenad_enclave /
COPY --from=build /locked-packages.txt /locked-packages.txt

