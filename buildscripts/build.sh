#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

update_test_unique_id_flag=""
build_reproducible_flag=""
update_build_number=0
TITLE="FINAL"
skip_enclave=0

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
    --build-reproducible)
      build_reproducible_flag="--build-reproducible"
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
      echo "Usage: build.sh [--update-test-unique-id] [--update-build-number] [--skip-enclave] [--build-reproducible] [--title <title>]"
      exit 0
      ;;      
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

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

# if build_reproducible is set, build for real enclave
if [[ $build_reproducible_flag == "--build-reproducible" ]]; then
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
    $qadenabuildscripts/build_enclave.sh --title $TITLE $update_test_unique_id_flag $build_reproducible_flag
    if [ $? -ne 0 ] ; then
        echo "************"
        echo "   $TITLE ERROR"
        echo "************"
        exit 1
    fi

    $qadenabuildscripts/build_signer_enclave.sh --title $TITLE $update_test_unique_id_flag $build_reproducible_flag
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
