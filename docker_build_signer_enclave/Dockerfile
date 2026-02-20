# syntax=docker/dockerfile:1.4

# Use this to build an executable for Ubuntu 22.04

# go to https://github.com/orgs/edgelesssys/packages/container/package/ego%2Fbuild-base and
# find out the correct version (e.g. 1.8.1) and click on the "..." beside the Digest

# 1.7.0
#FROM ghcr.io/edgelesssys/ego/build-base@sha256:f699547818bcbcef9bfbc60d1ef7b811a76f8133c1c8505d8c6681bd1623bf79 AS base

# 1.8.1
FROM ghcr.io/edgelesssys/ego/build-base@sha256:ce58c2c60d94f766a9aa95c11d69ca149eb13e39e72e63ca122e7368c6bba651 AS base

# Install required packages
# These are cached in the build-base image. Don't run `apt-get update` or
# you may get other package versions and the build won't be reproducible.

RUN apt-get install -y --no-install-recommends \
  perl-modules-5.34=5.34.0-3ubuntu1.3 \
  libgdbm6:amd64=1.23-1 \
  libexpat1:amd64=2.4.7-1ubuntu0.5 \
  libnghttp2-14:amd64=1.43.0-1ubuntu0.2 \
  libpsl5:amd64=0.21.0-1.2build2 \
  wget=1.21.2-2ubuntu1.1 \
  xz-utils=5.2.5-2ubuntu1 \
  binutils-common:amd64=2.38-4ubuntu2.6 \
  libbinutils:amd64=2.38-4ubuntu2.6 \
  libctf-nobfd0:amd64=2.38-4ubuntu2.6 \
  libctf0:amd64=2.38-4ubuntu2.6 \
  binutils-x86-64-linux-gnu=2.38-4ubuntu2.6 \
  binutils=2.38-4ubuntu2.6 \
  perl=5.34.0-3ubuntu1.3 \
  libc-dev-bin=2.35-0ubuntu3.8 \
  openssl=3.0.2-0ubuntu1.18 \
  libperl5.34:amd64=5.34.0-3ubuntu1.3 \
  linux-libc-dev:amd64=5.15.0-130.140 \
  libcrypt-dev:amd64=1:4.4.27-1 \
  rpcsvc-proto=1.4.2-0ubuntu6 \
  libtirpc-dev:amd64=1.3.2-2ubuntu0.1 \
  libnsl-dev:amd64=1.3.0-2build2 \
  libc6-dev:amd64=2.35-0ubuntu3.8 \
  libgdbm-compat4:amd64=1.23-1 \
  gcc-11-base:amd64=11.4.0-1ubuntu1~22.04 \
  libisl23:amd64=0.24-2build1 \
  libmpfr6:amd64=4.1.0-3build3 \
  libmpc3:amd64=1.2.1-2build1 \
  cpp-11=11.4.0-1ubuntu1~22.04 \
  cpp=4:11.2.0-1ubuntu1 \
  libcc1-0:amd64=12.3.0-1ubuntu1~22.04 \
  libgomp1:amd64=12.3.0-1ubuntu1~22.04 \
  libitm1:amd64=12.3.0-1ubuntu1~22.04 \
  libatomic1:amd64=12.3.0-1ubuntu1~22.04 \
  libasan6:amd64=11.4.0-1ubuntu1~22.04 \
  liblsan0:amd64=12.3.0-1ubuntu1~22.04 \
  libtsan0:amd64=11.4.0-1ubuntu1~22.04 \
  libubsan1:amd64=12.3.0-1ubuntu1~22.04 \
  libquadmath0:amd64=12.3.0-1ubuntu1~22.04 \
  libgcc-11-dev:amd64=11.4.0-1ubuntu1~22.04 \
  gcc-11=11.4.0-1ubuntu1~22.04 \
  gcc=4:11.2.0-1ubuntu1 \
  libstdc++-11-dev:amd64=11.4.0-1ubuntu1~22.04 \
  g++-11=11.4.0-1ubuntu1~22.04 \
  g++=4:11.2.0-1ubuntu1 \
  make=4.3-4.1build1 \
  libdpkg-perl=1.21.1ubuntu2.3 \
  bzip2=1.0.8-5build1 \
  patch=2.7.6-7build2 \
  lto-disabled-list=24 \
  dpkg-dev=1.21.1ubuntu2.3 \
  build-essential=12.9ubuntu3 \
  libbrotli1:amd64=1.0.9-2build6 \
  libsasl2-modules-db:amd64=2.1.27+dfsg2-3ubuntu1.2 \
  libsasl2-2:amd64=2.1.27+dfsg2-3ubuntu1.2 \
  libldap-2.5-0:amd64=2.5.18+dfsg-0ubuntu0.22.04.2 \
  librtmp1:amd64=2.4+20151223.gitfa8646d.1-2build4 \
  libssh-4:amd64=0.9.6-2ubuntu0.22.04.3 \
  libcurl3-gnutls:amd64=7.81.0-1ubuntu1.20 \
  liberror-perl=0.17029-1 \
  git-man=1:2.34.1-1ubuntu1.12 \
  git=1:2.34.1-1ubuntu1.12 \
  zsh-common=5.8.1-1 \
  zsh=5.8.1-1 \
  ca-certificates=20240203~22.04.1 \
  zsh=5.8.1-1
 

#RUN apt-get install -y --no-install-recommends \
#  build-essential=12.9ubuntu3 \
#  ca-certificates \
#  git \
#  wget \
#  zsh

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

RUN wget https://github.com/edgelesssys/ego/releases/download/v1.8.1/ego_1.8.1_amd64_ubuntu-22.04.deb \
  && dpkg -i --force-depends ego_1.8.1_amd64_ubuntu-22.04.deb

FROM base AS build

ENV DOCKER_BUILD=1

COPY ./ /build/

WORKDIR /build

RUN zsh buildscripts/build_enclave.sh --build-reproducible

RUN zsh buildscripts/build_signer_enclave.sh --build-reproducible

# Use the export target if you just want to use Docker to build your app and then export it
FROM scratch AS export
COPY --from=build /build/cmd/qadenad_enclave /
COPY --from=build /build/cmd/signer_enclave /


