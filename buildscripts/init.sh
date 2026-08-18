#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

# make sure not running as root
if [[ $(id -u) -eq 0 ]]; then
    echo "init.sh:  Error: init.sh must not be run as root"
    exit 1
fi

if which jq > /dev/null ; then
else
  echo "jq needs to be installed (e.g. sudo apt-get install jq, brew install jq, ...)"
  exit 1
fi


# ensure $QADENAHOME exists
mkdir -p "$QADENAHOME"

qadenaconfig="$QADENAHOME/config"
genesisfile="$qadenaconfig/genesis.json"
nodeparamsfile="$qadenaconfig/node_params.json"
#enclaveparamsfile="$qadenaconfig/enclave_params.json"
#enclave_path="$(pwd)/cmd/qadenad_enclave"

ADVERTISE_IP_ADDRESS=""
build_sgx_flag=""
skip_build=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --advertise-ip-address)
      if [[ -n "$2" && "$2" != --* ]]; then
        ADVERTISE_IP_ADDRESS="$2"
        shift 2
      else
        echo "Error: --advertise-ip-address requires an IP argument"
        exit 1
      fi
      ;;
    --build-sgx|--build-reproducible)
      build_sgx_flag="--build-sgx"
      shift
      ;;
    --skip-build)
      skip_build=1
      shift
      ;;
    --help)
      echo "Usage: init.sh [--advertise-ip-address <ip>] [--build-sgx] [--skip-build]"
      exit 0
      ;;      
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done





if [[ $ADVERTISE_IP_ADDRESS == "" ]] ; then
    ADVERTISE_IP_ADDRESS=`$qadenabuildscripts/get_default_ip.sh`
    # if get_default_ip.sh fails, it will exit 1

    if [[ $ADVERTISE_IP_ADDRESS == "" || $? != 0 ]] ; then
	echo "Failed to get a default IP address for your node."
	echo "Args: init.sh [--advertise-ip-address <ip>]"
	echo "Example:  init.sh --advertise-ip-address 192.168.86.100"
	exit 1
    fi
    echo "You didn't enter an IP address to advertise for your node.  This will be used for other nodes to connect to this node."
    echo "You can avoid this prompt by calling init.sh --advertise-ip-address <ip>"
    read REPLY\?"*** For now, shall I use $ADVERTISE_IP_ADDRESS? (y/N) "
    if [[ $REPLY == "y" ]] ; then
	echo "Ok"
    else
	echo "Args: init.sh [--advertise-ip-address <ip>]"
	echo "Example:  init.sh --advertise-ip-address 192.168.86.100"
	exit 1
    fi
fi



echo "-------------------------------------------"
echo "INIT CHAIN FROM SCRATCH AND ERASE ALL DATA"
echo "-------------------------------------------"

PIONEER1=pioneer1

echo "Running Ignite chain init..."
echo "Removing $QADENAHOME"

if [[ -d "$QADENAHOME" ]]; then
    rm -rf $QADENAHOME
    # if fails, check if there are files owned by root
    if [[ $? != 0 ]]; then
        echo "Failed to remove $QADENAHOME"
        # check if there are files owned by root in $QADENAHOME, and if so, do a "sudo rm -rf"
        if find $QADENAHOME -user root | grep -q .; then
            echo "Found files owned by root in $QADENAHOME, using sudo to remove"
            sudo rm -rf $QADENAHOME
        fi
    fi
fi

cd $qadenabuild

# config.yml is now just a verbatim copy of config/config.yml.  Nothing is substituted into it any
# more -- pioneer1 and treasury are both fixed up in genesis.json after the init -- so there is no
# reason to detect or preserve an existing copy.
#
# Copying unconditionally also removes a real trap.  The old code kept a previously generated
# config.yml if it looked complete, so an edit to config/config.yml silently had no effect until you
# remembered to delete the generated one first.
echo "Copying config/config.yml -> config.yml"
cp $qadenabuild/config/config.yml $qadenabuild/config.yml

# `ignite chain init` REGENERATES THE PROTOS as a side effect, using the machine's local plugins.
# A mismatched one rewrites nine .pb.go files and the failure surfaces minutes later at packaging,
# naming neither the plugin nor the version.  Checked here, where it is still cheap to fix.
"$qadenabuildscripts/check_codegen_plugins.sh" || exit 1

echo "Initializing chain"
if ignite chain init --home $QADENAHOME ; then
    echo "Built chain, copying"
    if [[ ! -d "$qadenabin" ]] ; then
        mkdir -p "$qadenabin"
    fi
    cp `which qadena_v3d` $qadenabin/qadenad
else
    rm $qadenabuild/config.yml
    echo "Failed to build chain, removing config.yml"
    exit 1
fi

# pioneer1 substituted here rather than into config.yml before the init.
#
# This is what removes the need for the truncated-config bootstrap pass.  The placeholders only had
# to be resolved before `ignite chain init` if ignite validated them -- and it plainly does not:
# treasuryPubKID has always survived the init as a literal string and been rewritten in genesis.json
# afterwards.  pioneer1 can take the same route, so the keys can be minted by a single init and the
# substitution can happen against the resulting genesis.
if $qadenabuildscripts/setPubKAndPubKID.sh $PIONEER1 $genesisfile ; then
else
    echo "failed to modify $genesisfile"
    exit 1
fi

echo "Fixing up config.toml"

external_address='external_address = ""'
replaceexternaladdress="s#${external_address}#external_address = \"${ADVERTISE_IP_ADDRESS}:26656\"#g"

if [[ "$(uname -s)" == "Darwin" ]] ; then
    sed -i '' $replaceexternaladdress $QADENAHOME/config/config.toml
elif [[ "$(uname -s)" == "Linux" ]] ; then
    sed -i $replaceexternaladdress $QADENAHOME/config/config.toml
fi

echo "Fixing up genesis file -- pubk and pubkid..."

#if ./setPubKAndPubKID.sh $PIONEER1 $genesisfile ; then
#else
#    echo "failed to modify config.yml"
#    exit 1
#fi

if $qadenabuildscripts/setPubKAndPubKID.sh treasury $genesisfile ; then
else
    echo "failed to modify config.yml"
    exit 1
fi


# no setPubKAndPubKID for testdsvssrvprv / testidentitysrvprv: they are no longer genesis accounts,
# so ignite never creates their keys and there is nothing to substitute.  They are onboarded after
# the chain is up by testscripts/setup_prerequisites.sh.

#if $qadenabuildscripts/setPubKAndPubKID.sh ekycphidentitysrvprv $genesisfile ; then
#else
#    echo "failed to modify config.yml"
#    exit 1
#fi

# no setPubKAndPubKID for maya / coinsph / coopnet / unionbank identitysrvprv or testfinancesrvprv
# either -- same reason: they are srv-prv providers, so they belong in a MsgAddServiceProvider
# proposal, not genesis.  pioneer1 and treasury are the only substitutions left.
    
echo "Copying node_params.json"
cp config/node_params.json $qadenaconfig
#echo "Copying enclave_params.json"
#cp config/enclave_params.json $qadenaconfig
echo "Fixing up node_params.json..."
$qadenascripts/setPioneerID.sh pioneer1 $nodeparamsfile
#echo "Fixing up enclave_params.json..."


#if [[ $REAL_ENCLAVE == 1 ]] ; then
#    echo "EGo (Edgelesssys Go) is installed, doing 'real enclave' specific tasks."
#    ./create_enclave_dirs.sh
#else    
#fi

# --skip-build: reset the CHAIN without rebuilding the BINARIES.
#
# Everything above -- ignite chain init, the genesis fixups, the config.toml edits -- is quick.  The
# expensive part is build.sh, which on --build-sgx runs three reproducible docker builds and takes
# roughly twenty minutes.  When only the chain state needs resetting and the code has not changed,
# that work is pure waste.
#
# The catch is that build_enclave.sh is what normally writes the enclave identity into genesis.
# Skipping the build means doing it here instead, from the binary that will actually run -- otherwise
# genesis keeps config.yml's literal test-unique-id and the chain refuses its own enclave at startup.
if [[ $skip_build -eq 1 ]] ; then
    echo "--skip-build: reusing the binaries already built in this repo"

    enclave_src="$qadenabuild/cmd/qadenad_enclave/qadenad_enclave"
    chain_src="$qadenabuild/cmd/qadenad/qadenad"
    for f in "$chain_src" "$enclave_src" ; do
        if [[ ! -x "$f" ]] ; then
            echo "************************"
            echo "   INIT FAILED: --skip-build needs $f, which does not exist."
            echo "   Run init.sh once WITHOUT --skip-build (add --build-sgx on SGX hardware)."
            echo "************************"
            exit 1
        fi
    done

    # Read from the BINARY, not from a text file, so the identity written into genesis is the one the
    # chain will actually measure.  A signed enclave carries its measurement; a debug one is
    # described by the *.txt files embedded in it.
    if use_real_enclave "$enclave_src" ; then
        unique_id=`ego uniqueid "$enclave_src"`
        signer_id=`ego signerid "$enclave_src"`
        echo "SGX enclave identity from the binary"
    else
        unique_id=`cat $qadenabuild/cmd/qadenad_enclave/test_unique_id.txt`
        signer_id=`cat $qadenabuild/cmd/qadenad_enclave/test_signer_id.txt`
        echo "debug enclave identity from cmd/qadenad_enclave/*.txt"
    fi
    if [[ -z "$unique_id" || -z "$signer_id" ]] ; then
        echo "   INIT FAILED: could not determine the enclave identity of $enclave_src"
        exit 1
    fi
    echo "Enclave identity: $unique_id / $signer_id"

    if ! jq --arg uniqueid "$unique_id" --arg signerid "$signer_id" \
         '.app_state.qadena.enclaveIdentityList |= map(.uniqueID = $uniqueid | .signerID = $signerid)' \
         $genesisfile > $genesisfile.tmp ; then
        echo "   INIT FAILED: could not write the enclave identity into $genesisfile"
        exit 1
    fi
    mv $genesisfile.tmp $genesisfile

    $qadenabuildscripts/install.sh --chain --enclave --signer-enclave
    if [ $? -ne 0 ] ; then
        echo "   INIT FAILED: install.sh failed"
        exit 1
    fi

    $qadenabuildscripts/install.sh --scripts
    if [ $? -ne 0 ] ; then
        echo "   INIT FAILED: install.sh --scripts failed"
        exit 1
    fi

    echo "Init done (binaries reused; no rebuild)."
    exit 0
fi

echo "Calling build.sh"
# THE EXIT STATUS MUST BE CHECKED.  build.sh already exits 1 on a failed build and prints a banner,
# but init.sh used to run straight on to install.sh and then exit with ITS status -- so a chain that
# never compiled produced a successful init.
#
# That is not a theoretical ordering nit.  A --build-sgx run whose docker export failed on a
# permissions error reported "FINAL BUILD ERROR", installed the scripts, exited 0, and left
# $QADENAHOME with no enclave binary at all and genesis still carrying the unsubstituted
# test-unique-id placeholder.  The first thing to actually complain was the node failing to start two
# minutes later, naming neither the build nor the reason.
$qadenabuildscripts/build.sh --title "FINAL BUILD" $build_sgx_flag
if [ $? -ne 0 ] ; then
    echo "************************"
    echo "   INIT FAILED: the build did not succeed, so nothing was installed"
    echo "************************"
    exit 1
fi

$qadenabuildscripts/install.sh --scripts
if [ $? -ne 0 ] ; then
    echo "************************"
    echo "   INIT FAILED: install.sh failed"
    echo "************************"
    exit 1
fi

    