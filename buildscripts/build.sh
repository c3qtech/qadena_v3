#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

update_test_unique_id_flag=""
build_sgx_flag=""
update_build_number=0
TITLE="FINAL"
skip_enclave=0
force_sgx=0
no_sgx=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --update-test-unique-id)
      update_test_unique_id_flag="--update-test-unique-id"
      shift
      ;;
    --update-build-number)
      update_build_number=1
      shift
      ;;
    --skip-enclave)
      skip_enclave=1
      shift
      ;;
    --build-sgx|--build-reproducible)
      build_sgx_flag="--build-sgx"
      force_sgx=1
      shift
      ;;
    --no-sgx|--debug-build)
      # The opt-OUT.  Needed on a machine that has ego but wants debug artifacts (a dev box
      # building for a debug chain, say).  Explicit, because the mistake this guards against is
      # silent and the mistake it enables is loud.
      no_sgx=1
      shift
      ;;
    --title)
      if [[ -n "$2" && "$2" != --* ]]; then
        TITLE="$2"
        shift 2
      else
        echo "Error: --title requires a title argument"
        exit 1
      fi
      ;;
    --help)
      echo "Usage: build.sh [--update-test-unique-id] [--update-build-number] [--skip-enclave] [--build-sgx] [--no-sgx] [--title <title>]"
      echo "  SGX is the DEFAULT when ego is installed (it decides -tags realenclave, which"
      echo "  silently controls whether real attestation is verified).  --no-sgx opts out."
      exit 0
      ;;      
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

# EGO INSTALLED MEANS SGX, UNLESS YOU SAY OTHERWISE.
#
# --build-sgx does two things, and only one of them is loud.  It builds the enclave reproducibly
# (whose failure mode is a measurement mismatch -- impossible to miss), and it adds `-tags
# realenclave` to the CHAIN binary, which decides whether ClientVerifyRemoteReport uses the real
# SGX verifier or DebugVerifyRemoteReport.  That second one is SILENT: a chain binary built without
# the tag on an SGX node verifies real quotes with the debug verifier, which means it ACCEPTS
# FORGED DEBUG REPORTS while believing it has attestation.
#
# `build.sh --skip-enclave` did exactly that here: it was meant to rebuild only the chain binary
# and leave MRENCLAVE alone, and it silently dropped the tag as well.  Every joiner was then
# refused with a bare "Invalid enclave" and nothing in the log said why.
#
# So the default follows the TOOLCHAIN: ego present means this machine builds SGX artefacts.  ego
# is a build dependency, not a runtime one -- an x86 box with no SGX devices can still produce SGX
# binaries -- which is why this keys on ego rather than on /dev/sgx*.  A machine without ego (the
# ARM boxes, a Mac) cannot build SGX at all and is unaffected.
#
# The asymmetry justifies the default: forgetting the flag is silent and dangerous, while opting
# out is one word and its failure ("Invalid enclave" on every message) is immediate and obvious.
if [[ $no_sgx -eq 1 ]]; then
    build_sgx_flag=""
    echo "build.sh: --no-sgx: building DEBUG artifacts (chain binary WITHOUT -tags realenclave)"
elif [[ $force_sgx -eq 0 ]] && command -v ego > /dev/null 2>&1; then
    build_sgx_flag="--build-sgx"
    echo "build.sh: ego is installed, so building for SGX (chain binary WITH -tags realenclave)."
    echo "build.sh: pass --no-sgx for a debug build."
fi

VERSION_FILE="$qadenabuild/cmd/qadenad/version.txt"
# update version
if [ $update_build_number -eq 1 ] ; then
    VERSION=$(increment_version "$VERSION_FILE")
    echo "--------------------"
    echo "Updated build number to $VERSION"
    echo "--------------------"
else
    VERSION=$(cat "$VERSION_FILE")
fi

echo "--------------------"
echo "$TITLE BUILD CHAIN $VERSION"
echo "--------------------"


qadenaconfig="$QADENAHOME/config"

if [[ ! -d "$qadenabin" ]] ; then
    mkdir -p "$qadenabin"
fi

chain_path="$qadenabuild/cmd/qadenad"

cd $qadenabuild

# --build-sgx (was --build-reproducible; the old name still works)
#
# The rename names the PURPOSE rather than the means.  It is the only thing that produces an
# ego-signed SGX enclave -- REAL_ENCLAVE is auto-detected from the CPU and is never consulted here.
#
# The build must still be reproducible, and that is not incidental: the enclave's unique id
# (MRENCLAVE) IS a hash of the built binary, so a non-deterministic SGX build would measure
# differently on every machine and nothing could attest to it or whitelist it.  Reproducibility is a
# requirement of the SGX build, not a separate option -- which is why one flag drives both.
if [[ $build_sgx_flag == "--build-sgx" ]]; then
  if [[ "$DOCKER_BUILD" = "1" ]]; then
    echo "------------------------------------------------------------------"
    echo "$TITLE BUILDING QADENAD WITHIN DOCKER FOR SGX (REPRODUCIBLE BUILD)"
    echo "------------------------------------------------------------------"
    export CGO_CFLAGS="-I/opt/ego/include"
    export CGO_LDFLAGS="-L/opt/ego/lib -L/usr/lib/x86_64-linux-gnu"
    go build -trimpath -ldflags "-X github.com/cosmos/cosmos-sdk/version.Version=$VERSION -extldflags '-Wl,-rpath,\$ORIGIN'" -tags realenclave -o $chain_path/qadenad -mod=vendor github.com/c3qtech/qadena_v3/cmd/qadenad
  else
    echo "-----------------------------------------------------"
    echo "$TITLE STARTING REPRODUCIBLE DOCKER BUILD FOR QADENAD"
    echo "-----------------------------------------------------"
    # remove any git changes
    if [ -n "$(git status --porcelain)" ]; then
      echo "----------------------------------------------------------------"
      echo "WARNING!!!  Untracked or modified files detected, removing them."
      echo "----------------------------------------------------------------"
      git checkout -f && git clean -fd
    fi    
	  (cd $qadenabuild/docker_build_chain; ./build.sh)
  fi
else
    echo "-----------------------------------------"
    echo "$TITLE BUILDING DEBUG QADENAD $VERSION"
    echo "-----------------------------------------"

    # if docs/static/openapi.yml doesn't exist, create it
    if [ ! -f docs/static/openapi.yml ]; then
        echo "Creating empty docs/static/openapi.yml"
		mkdir -p docs/static
        touch docs/static/openapi.yml
    fi
    export CGO_ENABLED="1"
    go build -trimpath -ldflags "-X github.com/cosmos/cosmos-sdk/version.Version=$VERSION -extldflags '-Wl,-rpath,\$ORIGIN'" -o $chain_path/qadenad -mod=vendor github.com/c3qtech/qadena_v3/cmd/qadenad
fi

if [ $? -ne 0 ] ; then
    echo "************************"
    echo "$TITLE ERROR BUILDING"
    echo "************************"
    exit 1
fi

$qadenabuildscripts/install.sh --chain

if [[ $skip_enclave == 0 ]] ; then
    $qadenabuildscripts/build_enclave.sh --title $TITLE $update_test_unique_id_flag $build_sgx_flag
    if [ $? -ne 0 ] ; then
        echo "************"
        echo "   $TITLE ERROR"
        echo "************"
        exit 1
    fi

    $qadenabuildscripts/build_signer_enclave.sh --title $TITLE $update_test_unique_id_flag $build_sgx_flag
    if [ $? -ne 0 ] ; then
        echo "************"
        echo "   $TITLE ERROR"
        echo "************"
        exit 1
    fi
fi

echo "------------------"
echo "      $TITLE SUCCESS!"
echo "------------------"
