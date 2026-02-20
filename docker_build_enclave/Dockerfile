# syntax=docker/dockerfile:1.4

# go to https://github.com/orgs/edgelesssys/packages/container/package/ego%2Fbuild-base and
# find out the correct version (e.g. 1.8.1) and click on the "..." beside the Digest

# 1.7.0
#FROM ghcr.io/edgelesssys/ego/build-base@sha256:f699547818bcbcef9bfbc60d1ef7b811a76f8133c1c8505d8c6681bd1623bf79 AS base

# 1.8.1
FROM ghcr.io/edgelesssys/ego/build-base@sha256:ce58c2c60d94f766a9aa95c11d69ca149eb13e39e72e63ca122e7368c6bba651 AS base


RUN apt-get update

# CUT/PASTE ALERT:  Get the apt-get info from the docker_chain_build/Dockerfile

RUN apt-get install -y --no-install-recommends \
  adduser=3.118ubuntu5 \
  apt=2.4.14 \
  base-files=12ubuntu4.7 \
  base-passwd=3.5.52build1 \
  bash=5.1-6ubuntu1.1 \
  bsdutils=1:2.37.2-4ubuntu3.4 \
  build-essential=12.9ubuntu3 \
  ca-certificates=20240203~22.04.1 \
  coreutils=8.32-4.1ubuntu1.2 \
  curl=7.81.0-1ubuntu1.21 \
  dash=0.5.11+git20210903+057cd650a4ed-3build1 \
  debconf=1.5.79ubuntu1 \
  debianutils=5.5-1ubuntu2 \
  diffutils=1:3.8-0ubuntu2 \
  dpkg=1.21.1ubuntu2.6 \
  e2fsprogs=1.46.5-2ubuntu1.2 \
  findutils=4.8.0-1ubuntu3 \
  gcc-12-base=12.3.0-1ubuntu1~22.04.2 \
  git=1:2.34.1-1ubuntu1.15 \
  gpgv=2.2.27-3ubuntu2.5 \
  grep=3.7-1build1 \
  gzip=1.10-4ubuntu4.1 \
  hostname=3.23ubuntu2 \
  init-system-helpers=1.62 \
  libacl1=2.3.1-1 \
  libapt-pkg6.0=2.4.14 \
  libattr1=1:2.5.1-1build1 \
  libaudit-common=1:3.0.7-1build1 \
  libaudit1=1:3.0.7-1build1 \
  libblkid1=2.37.2-4ubuntu3.4 \
  libbz2-1.0=1.0.8-5build1 \
  libc-bin=2.35-0ubuntu3.11 \
  libc6=2.35-0ubuntu3.13 \
  libcap-ng0=0.7.9-2.2build3 \
  libcap2=1:2.44-1ubuntu0.22.04.2 \
  libcom-err2=1.46.5-2ubuntu1.2 \
  libcrypt1=1:4.4.27-1 \
  libdb5.3=5.3.28+dfsg1-0.8ubuntu3 \
  libdebconfclient0=0.261ubuntu1 \
  libext2fs2=1.46.5-2ubuntu1.2 \
  libffi8=3.4.2-4 \
  libgcc-s1=12.3.0-1ubuntu1~22.04.2 \
  libgcrypt20=1.9.4-3ubuntu3 \
  libgmp10=2:6.2.1+dfsg-3ubuntu1 \
  libgnutls30=3.7.3-4ubuntu1.7 \
  libgpg-error0=1.43-3 \
  libgssapi-krb5-2=1.19.2-2ubuntu0.7 \
  libhogweed6=3.7.3-1build2 \
  libidn2-0=2.3.2-2build1 \
  libk5crypto3=1.19.2-2ubuntu0.7 \
  libkeyutils1=1.6.1-2ubuntu3 \
  libkrb5-3=1.19.2-2ubuntu0.7 \
  libkrb5support0=1.19.2-2ubuntu0.7 \
  liblz4-1=1.9.3-2build2 \
  liblzma5=5.2.5-2ubuntu1 \
  libmount1=2.37.2-4ubuntu3.4 \
  libncurses6=6.3-2ubuntu0.1 \
  libncursesw6=6.3-2ubuntu0.1 \
  libnettle8=3.7.3-1build2 \
  libnsl2=1.3.0-2build2 \
  libp11-kit0=0.24.0-6build1 \
  libpam-modules-bin=1.4.0-11ubuntu2.6 \
  libpam-modules=1.4.0-11ubuntu2.6 \
  libpam-runtime=1.4.0-11ubuntu2.6 \
  libpam0g=1.4.0-11ubuntu2.6 \
  libpcre2-8-0=10.39-3ubuntu0.1 \
  libpcre3=2:8.39-13ubuntu0.22.04.1 \
  libprocps8=2:3.3.17-6ubuntu2.1 \
  libseccomp2=2.5.3-2ubuntu3~22.04.1 \
  libselinux1=3.3-1build2 \
  libsemanage-common=3.3-1build2 \
  libsemanage2=3.3-1build2 \
  libsepol2=3.3-1build1 \
  libsmartcols1=2.37.2-4ubuntu3.4 \
  libss2=1.46.5-2ubuntu1.2 \
  libssl-dev=3.0.2-0ubuntu1.21 \
  libssl3=3.0.2-0ubuntu1.21 \
  libstdc++6=12.3.0-1ubuntu1~22.04.2 \
  libsystemd0=249.11-0ubuntu3.17 \
  libtasn1-6=4.18.0-4ubuntu0.1 \
  libtinfo6=6.3-2ubuntu0.1 \
  libtirpc-common=1.3.2-2ubuntu0.1 \
  libtirpc3=1.3.2-2ubuntu0.1 \
  libudev1=249.11-0ubuntu3.17 \
  libunistring2=1.0-1 \
  libuuid1=2.37.2-4ubuntu3.4 \
  libxxhash0=0.8.1-1 \
  libzstd1=1.4.8+dfsg-3build1 \
  login=1:4.8.1-2ubuntu2.2 \
  logsave=1.46.5-2ubuntu1.2 \
  lsb-base=11.1.0ubuntu4 \
  mawk=1.3.4.20200120-3 \
  mount=2.37.2-4ubuntu3.4 \
  ncurses-base=6.3-2ubuntu0.1 \
  ncurses-bin=6.3-2ubuntu0.1 \
  passwd=1:4.8.1-2ubuntu2.2 \
  perl-base=5.34.0-3ubuntu1.5 \
  procps=2:3.3.17-6ubuntu2.1 \
  sed=4.8-1ubuntu2 \
  sensible-utils=0.0.17 \
  sysvinit-utils=3.01-1ubuntu1 \
  tar=1.34+dfsg-1ubuntu0.1.22.04.2 \
  ubuntu-keyring=2021.03.26 \
  usrmerge=25ubuntu2 \
  util-linux=2.37.2-4ubuntu3.4 \
  wget=1.21.2-2ubuntu1.1 \
  zlib1g=1:1.2.11.dfsg-2ubuntu9.2 \
  zsh=5.8.1-1

RUN apt-mark showmanual \
 | xargs dpkg-query -W -f='  ${Package}=${Version} \\\n' \
 | sort > /locked-packages.txt

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

# Use the export target if you just want to use Docker to build your app and then export it
FROM scratch AS export
COPY --from=build /build/cmd/qadenad_enclave /
COPY --from=build /locked-packages.txt /locked-packages.txt

