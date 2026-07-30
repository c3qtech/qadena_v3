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
build_reproducible_flag=""

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
    --build-reproducible)
      build_reproducible_flag="--build-reproducible"
      shift
      ;;
    --help)
      echo "Usage: init.sh [--advertise-ip-address <ip>] [--build-reproducible]"
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

echo "Calling build.sh"
$qadenabuildscripts/build.sh --title "FINAL BUILD" $build_reproducible_flag

$qadenabuildscripts/install.sh --scripts

    