#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

update_test_unique_id=0
build_sgx=0
TITLE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --update-test-unique-id)
      update_test_unique_id=1
      shift
      ;;
    --build-sgx|--build-reproducible)
      build_sgx=1
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
      echo "Usage: build_enclave.sh [--update-test-unique-id] [--build-sgx] [--title <title>]"
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

# --build-sgx (was --build-reproducible; the old name still works)
#
# The rename names the PURPOSE rather than the means.  It is the only thing that produces an
# ego-signed SGX enclave -- REAL_ENCLAVE is auto-detected from the CPU and is never consulted here.
#
# The build must still be reproducible, and that is not incidental: the enclave's unique id
# (MRENCLAVE) IS a hash of the built binary, so a non-deterministic SGX build would measure
# differently on every machine and nothing could attest to it or whitelist it.  Reproducibility is a
# requirement of the SGX build, not a separate option -- which is why one flag drives both.
if [[ $build_sgx == 1 ]] ; then
  if [[ "$DOCKER_BUILD" = "1" ]]; then
    echo "--------------------------------------------------------------------------"
    echo "$TITLE BUILDING QADENAD_ENCLAVE WITHIN DOCKER FOR SGX (REPRODUCIBLE BUILD)"
    echo "--------------------------------------------------------------------------"
    enclave_path="cmd/qadenad_enclave"
    echo "Enclave path: $enclave_path"
    export CFLAGS="-Wdate-time -D__DATE__=\"fixed\" -D__TIME__=\"fixed\""
    export SOURCE_DATE_EPOCH=1710000000
    echo "Tool Versions:"
    gcc --version
    ldd --version
    ego-go version
    echo "Build..."
    ego-go build -buildvcs=false -ldflags="-s -w" -trimpath -o $enclave_path/qadenad_enclave -mod=vendor github.com/c3qtech/qadena_v3/cmd/qadenad_enclave || exit 1
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
    echo "-------------------------------------------------------------"
    echo "$TITLE STARTING REPRODUCIBLE DOCKER BUILD FOR QADENAD_ENCLAVE"
    echo "-------------------------------------------------------------"
    # remove any git changes
    if [ -n "$(git status --porcelain)" ]; then
      echo "----------------------------------------------------------------"
      echo "WARNING!!!  Untracked or modified files detected, removing them."
      echo "----------------------------------------------------------------"
      git checkout -f && git clean -fd
    fi    
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

  echo "----------------------------------------------"
  echo "$TITLE BUILDING DEBUG QADENAD_ENCLAVE $VERSION"
  echo "----------------------------------------------"
  cd $qadenabuild
  go build -trimpath -o $enclave_path/qadenad_enclave -mod=vendor github.com/c3qtech/qadena_v3/cmd/qadenad_enclave || exit 1

fi

if [[ "$DOCKER_BUILD" = "" ]]; then
    qadenaconfig="$QADENAHOME/config"
    genesisfile="$qadenaconfig/genesis.json"

    # modify genesis.json
    # CHECKED, because the obvious form DESTROYS GENESIS on any failure.
    #
    # `jq ... $genesisfile > $genesisfile.tmp` creates the temp file before jq runs, so a jq that
    # fails for any reason -- an unreadable genesis, most easily after the node was last run under
    # sudo and the file is owned by root -- leaves an EMPTY temp file, and the unconditional mv then
    # replaces a valid genesis with zero bytes.  The build still reports success; the node fails much
    # later with "failed to parse chain-id from genesis file: EOF".
    #
    # That happened: a build run as the ordinary user truncated a full node's genesis to 0 bytes and
    # the failure only surfaced at the next start.
    if ! jq --arg uniqueid "$unique_id" --arg signerid "$signer_id" '
       .app_state.qadena.enclaveIdentityList |= map(.uniqueID = $uniqueid | .signerID = $signerid)
          ' $genesisfile > $genesisfile.tmp ; then
        echo "************************"
        echo "   ERROR: could not rewrite $genesisfile with the enclave identity."
        echo "   The original is untouched.  If it is owned by another user (root, after a sudo run),"
        echo "   fix the ownership and rebuild."
        echo "************************"
        rm -f $genesisfile.tmp
        exit 1
    fi
    if [[ ! -s $genesisfile.tmp ]] ; then
        echo "   ERROR: the rewritten genesis is empty; refusing to replace $genesisfile"
        rm -f $genesisfile.tmp
        exit 1
    fi

    # Rename the new files
    mv $genesisfile.tmp $genesisfile

    $qadenabuildscripts/install.sh --enclave
fi


