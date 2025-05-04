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
      echo "Usage: build_enclave.sh [--update-test-unique-id] [--build-reproducible] [--title <title>]"
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

enclave_path="$qadenabuild/cmd/qadenad_enclave"

rm -f $enclave_path/reproducible_build_signer_id.txt
rm -f $enclave_path/reproducible_build_unique_id.txt

cd $qadenabuild

if [[ $build_reproducible == 1 ]] ; then
  if [[ "$DOCKER_BUILD" = "1" ]]; then
    echo "---------------------------------------"
    echo "$TITLE BUILD REAL ENCLAVE (ego-go/ego toolset) (REPRODUCIBLE BUILD)"
    echo "---------------------------------------"
    enclave_path="cmd/qadenad_enclave"
    echo "Enclave path: $enclave_path"
    export CFLAGS="-Wdate-time -D__DATE__=\"fixed\" -D__TIME__=\"fixed\""
    export SOURCE_DATE_EPOCH=1710000000
    echo "Tool Versions:"
    gcc --version
    ldd --version
    ego-go version
    echo "Build..."
    ego-go build -buildvcs=false -ldflags="-s -w" -trimpath -o $enclave_path/qadenad_enclave -mod=vendor qadena_v3/cmd/qadenad_enclave || exit 1
    cd $enclave_path
#    cp qadenad_enclave qadenad_enclave.unsigned
    echo "Signing qadenad_enclave executable"
    ego sign qadenad_enclave || exit 1
    signer_id=`ego signerid public.pem`
    echo "Extracted signer id from public.pem: $signer_id"
    unique_id=`ego uniqueid qadenad_enclave`
    echo "Extracted unique id from qadenad_enclave: $unique_id"
    echo $signer_id > reproducible_build_signer_id.txt
    echo $unique_id > reproducible_build_unique_id.txt
  else
    (cd $qadenabuild/docker_build_enclave; ./build.sh) || exit 1
    signer_id=`cat $enclave_path/reproducible_build_signer_id.txt`
    unique_id=`cat $enclave_path/reproducible_build_unique_id.txt`
  fi
else
  if [[ $update_test_unique_id == 1 ]] ; then
      # Files to update
      signer_file="cmd/qadenad_enclave/test_signer_id.txt"
      unique_file="cmd/qadenad_enclave/test_unique_id.txt"
      version_file="cmd/qadenad_enclave/version.txt"

      # Increment both files
      signer_id=$(increment_id "$signer_file")
      unique_id=$(increment_id "$unique_file")
      version=$(increment_version "$version_file")

  fi

  signer_id=`cat cmd/qadenad_enclave/test_signer_id.txt`
  echo "Extracted signer id from cmd/qadenad_enclave/test_signer_id.txt: $signer_id"
  unique_id=`cat cmd/qadenad_enclave/test_unique_id.txt`
  echo "Extracted unique id from cmd/qadenad_enclave/test_unique_id.txt: $unique_id"
  VERSION=`cat cmd/qadenad_enclave/version.txt`

  echo "-------------------"
  echo "$TITLE BUILD DEBUG ENCLAVE $VERSION"
  echo "-------------------"
  cd $qadenabuild
  go build -trimpath -o $enclave_path/qadenad_enclave -mod=vendor qadena_v3/cmd/qadenad_enclave || exit 1

fi

if [[ "$DOCKER_BUILD" = "" ]]; then
    qadenaconfig="$QADENAHOME/config"
    genesisfile="$qadenaconfig/genesis.json"

    # modify genesis.json
    jq --arg uniqueid "$unique_id" --arg signerid "$signer_id" '
       .app_state.qadena.enclaveIdentityList |= map(.uniqueID = $uniqueid | .signerID = $signerid)
          ' $genesisfile > $genesisfile.tmp

    # Rename the new files
    mv $genesisfile.tmp $genesisfile

    $qadenabuildscripts/install.sh --enclave
fi


