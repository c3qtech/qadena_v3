#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

update_test_unique_id=0
build_reproducible=0
TITLE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --update-test-unique-id)
      update_test_unique_id=1
      shift
      ;;
    --build-reproducible)
      build_reproducible=1
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
      echo "Usage: build_signer_enclave.sh [--update-test-unique-id] [--build-reproducible] [--title <title>]"
      exit 0
      ;;      
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

if [[ ! -d "$qadenabin" ]] ; then
    mkdir -p "$qadenabin"
fi

signer_enclave_path="$qadenabuild/cmd/signer_enclave"

rm -f $signer_enclave_path/reproducible_build_signer_id.txt
rm -f $signer_enclave_path/reproducible_build_unique_id.txt

cd $qadenabuild

if [[ $build_reproducible == 1 ]] ; then
  if [[ "$DOCKER_BUILD" = "1" ]]; then
    echo "---------------------------------------"
    echo "$TITLE BUILD SIGNER ENCLAVE (ego-go/ego toolset) (REPRODUCIBLE BUILD)"
    echo "---------------------------------------"
    signer_enclave_path="cmd/signer_enclave"
    echo "Signer enclave path: $signer_enclave_path"
    export CFLAGS="-Wdate-time -D__DATE__=\"fixed\" -D__TIME__=\"fixed\""
    export SOURCE_DATE_EPOCH=1710000000
    echo "Tool Versions:"
    gcc --version
    ldd --version
    ego-go version
    echo "Build..."
    ego-go build -buildvcs=false -ldflags="-s -w" -trimpath -o $signer_enclave_path/signer_enclave -mod=vendor github.com/c3qtech/qadena_v3/cmd/signer_enclave || exit 1
    cd $signer_enclave_path
#    cp signer_enclave signer_enclave.unsigned
    echo "Signing signer_enclave executable"
    ego sign signer_enclave || exit 1
    signer_id=`ego signerid public.pem`
    echo "Extracted signer id from public.pem: $signer_id"
    unique_id=`ego uniqueid signer_enclave`
    echo "Extracted unique id from signer_enclave: $unique_id"
    echo $signer_id > reproducible_build_signer_id.txt
    echo $unique_id > reproducible_build_unique_id.txt
  else
    # remove any git changes
    if [ -n "$(git status --porcelain)" ]; then
      echo "----------------------------------------------------------------"
      echo "WARNING!!!  Untracked or modified files detected, removing them."
      echo "----------------------------------------------------------------"
      git checkout -f && git clean -fd
    fi    
    (cd $qadenabuild/docker_build_signer_enclave; ./build.sh) || exit 1
    signer_id=`cat $signer_enclave_path/reproducible_build_signer_id.txt`
    unique_id=`cat $signer_enclave_path/reproducible_build_unique_id.txt`
  fi
else
  if [[ $update_test_unique_id == 1 ]] ; then
      # Files to update
      signer_file="cmd/signer_enclave/test_signer_id.txt"
      unique_file="cmd/signer_enclave/test_unique_id.txt"
      version_file="cmd/signer_enclave/version.txt"

      # Increment both files
      signer_id=$(increment_id "$signer_file")
      unique_id=$(increment_id "$unique_file")
      version=$(increment_version "$version_file")

  fi

  signer_id=`cat cmd/signer_enclave/test_signer_id.txt`
  echo "Extracted signer id from cmd/signer_enclave/test_signer_id.txt: $signer_id"
  unique_id=`cat cmd/signer_enclave/test_unique_id.txt`
  echo "Extracted unique id from cmd/signer_enclave/test_unique_id.txt: $unique_id"
  VERSION=`cat cmd/signer_enclave/version.txt`

  echo "-------------------"
  echo "$TITLE BUILD DEBUG SIGNER ENCLAVE $VERSION"
  echo "-------------------"
  cd $qadenabuild
  go build -trimpath -o $signer_enclave_path/signer_enclave -mod=vendor github.com/c3qtech/qadena_v3/cmd/signer_enclave || exit 1

fi

echo "Signer enclave build completed successfully!"
echo "Executable: $signer_enclave_path/signer_enclave"
echo "Signer ID: $signer_id"
echo "Unique ID: $unique_id"

if [[ "$DOCKER_BUILD" = "" ]]; then
    $qadenabuildscripts/install.sh --signer-enclave
fi