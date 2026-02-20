# syntax=docker/dockerfile:1.4

# go to https://github.com/orgs/edgelesssys/packages/container/package/ego%2Fbuild-base and
# find out the correct version (e.g. 1.8.1) and click on the "..." beside the Digest

# 1.7.0
#FROM ghcr.io/edgelesssys/ego/build-base@sha256:f699547818bcbcef9bfbc60d1ef7b811a76f8133c1c8505d8c6681bd1623bf79 AS base

# 1.8.1
FROM ghcr.io/edgelesssys/ego/build-base@sha256:ce58c2c60d94f766a9aa95c11d69ca149eb13e39e72e63ca122e7368c6bba651 AS base

ARG egover

# Install required packages
# These are cached in the build-base image. Don't run `apt-get update` or
# you may get other package versions and the build won't be reproducible.

# in order to get this list, you need to comment this out

#RUN apt-get install -y --no-install-recommends \




RUN apt-get update

RUN apt-get install -y --no-install-recommends \
  build-essential \
  ca-certificates \
  git \
  wget \
  curl \
  libssl-dev \
  zsh


RUN apt-mark showmanual \
 | xargs dpkg-query -W -f='  ${Package}=${Version}\\\n' \
 | sort > /locked-packages.txt


# Install Go 1.25.7 manually
RUN curl -LO https://go.dev/dl/go1.25.7.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.25.7.linux-amd64.tar.gz && \
    rm go1.25.7.linux-amd64.tar.gz

# Set Go 1.25.7 as active version
ENV PATH="/usr/local/go/bin:${PATH}"

# Optional: confirm Go version
RUN go version

# Download and install further requirements (if any)
#
# Make sure that these stay the same, e.g., don't use "latest", but fixed versions.
#
# Avoid installing packages via apt here. This may change the version of already
# installed dependencies and may influence the final binary. If not using apt isn't
# feasible, consider building a Docker image that gathers all required apt packages
# and serves as a stable base.

# Download and install EGo
# Use --force-depends to ignore SGX dependencies, which aren't required for building
#RUN egodeb=ego_${egover}_amd64_ubuntu-$(grep -oP 'VERSION_ID="\K[^"]+' /etc/os-release).deb \
#  && wget https://github.com/edgelesssys/ego/releases/download/v${egover}/${egodeb} \
#  && dpkg -i --force-depends ${egodeb}

RUN wget https://github.com/edgelesssys/ego/releases/download/v1.7.0/ego_1.7.0_amd64_ubuntu-22.04.deb \
  && dpkg -i --force-depends ego_1.7.0_amd64_ubuntu-22.04.deb

FROM base AS build

ENV DOCKER_BUILD=1

COPY ./ /build/

WORKDIR /build

RUN zsh buildscripts/build.sh --skip-enclave --build-reproducible

# Use the export target if you just want to use Docker to build your app and then export it
FROM scratch AS export
COPY --from=build /build/cmd/qadenad/qadenad /
COPY --from=build /locked-packages.txt /locked-packages.txt

