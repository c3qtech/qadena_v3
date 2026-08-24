#!/bin/zsh

hold_flag=""

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

update_test_unique_id=0
build_sgx=0
TITLE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --hold)
      # Pass through to install.sh: stage the measurement-labelled binary but leave the live one
      # alone.  Required on SGX, where MRENCLAVE is only knowable after the build.
      hold_flag="--hold"
      shift
      ;;
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
      echo "Usage: build_enclave.sh [--update-test-unique-id] [--build-sgx] [--hold] [--title <title>]"
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
      # THE SIGNER ID IS DELIBERATELY NOT INCREMENTED HERE.  It used to be, and that quietly
      # destroyed sealed state on every debug enclave upgrade.
      #
      # In a debug build these two ids ARE the sealing keys: SealWithProductKey prefixes the
      # plaintext with signerID and SealWithUniqueKey with uniqueID (enclave.go), and Unseal
      # accepts a blob only if it carries the CURRENT one of those as its prefix.  That models real
      # SGX faithfully -- product-key sealing is designed to survive a MRENCLAVE change, which is
      # precisely what lets an upgraded enclave still read data the previous measurement sealed.
      #
      # On SGX a rebuild changes MRENCLAVE (the uniqueID) and NOTHING ELSE: the signer id is the
      # hash of the signing key in public.pem, which a rebuild does not touch.  Incrementing it
      # here simulated re-signing with a DIFFERENT KEY on every ordinary rebuild -- something SGX
      # would never do -- so every product-key-sealed value became unreadable the moment the new
      # enclave started.
      #
      # Observed: upgrading unique055 -> unique057 also moved signer051 -> signer052, and the
      # upgraded enclave panicked in getPrivKCache with "Couldn't unseal, unrecognized prefix" --
      # the SS interval private key cache, sealed under signer051, was no longer readable by
      # anything.  The handover itself reported success, which is what made it confusing.
      #
      # Rotating the signer id is a real operation, but it is a deliberate one (a new signing key),
      # and it invalidates product-key-sealed state by design.  It does not belong on the path that
      # every routine rebuild takes.  Do it by editing test_signer_id.txt by hand, knowing that the
      # node's sealed state goes with it.
      unique_file="cmd/qadenad_enclave/test_unique_id.txt"
      version_file="cmd/qadenad_enclave/version.txt"

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

    # NEVER REWRITE THE GENESIS OF A CHAIN THAT HAS ALREADY RUN.
    #
    # Genesis is immutable history: every node agreed it, and CometBFT loads it once at InitChain and
    # then serves that copy over /genesis forever.  Editing the FILE afterwards does not change the
    # chain -- it just makes the file disagree with the node standing next to it.
    #
    # .120 is in exactly that state today: its genesis.json records b43e245d... while its own RPC
    # serves bcbea7c9..., because an enclave upgrade ran this rewrite against a live node.  Two
    # costs, both paid: the file was read as authoritative during a joiner investigation and sent it
    # down the wrong path for a while; and CometBFT validates genesis against what it stored, so
    # whether .120 can still RESTART is unknown and untested.
    #
    # The rewrite is correct and necessary for a chain being INITIALISED (init.sh runs this before
    # any node exists).  The test is therefore "has this home already run a chain", not "is a node
    # running now" -- a stopped node whose data survives is exactly the case that must be refused.
    if [[ -d "$QADENAHOME/data/application.db" && "$FORCE_GENESIS_REWRITE" != "1" ]] ; then
        echo ""
        echo "NOT rewriting $genesisfile: this home has chain data, so the chain has already run."
        echo "    Genesis is fixed at InitChain; rewriting the file now would only make it disagree"
        echo "    with the genesis this node serves, and CometBFT may refuse to restart on it."
        echo "    The enclave binary was still built and installed -- only the genesis edit is skipped."
        echo "    To re-initialise a chain from scratch, use init.sh (which wipes the home first),"
        echo "    or pass FORCE_GENESIS_REWRITE=1 if you really mean to edit a live node's genesis."
        echo ""
        $qadenabuildscripts/install.sh --enclave $hold_flag
        exit 0
    fi

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

    $qadenabuildscripts/install.sh --enclave $hold_flag
fi


