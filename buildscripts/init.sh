#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

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
    if [[ $ADVERTISE_IP_ADDRESS == "" ]] ; then
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

rm -rf $QADENAHOME

cd $qadenabuild

# if not exists config.yml
if [ ! -f $qadenabuild/config.yml ]; then
    echo "-----------------------------------------------------"
    echo "WARNING:  No config.yml yet, NEED to BOOTSTRAP first."
    echo "-----------------------------------------------------"
    
    #
    echo "Using a truncated config.yml"
    sed '/qadena:/,$d' config/config.yml > config.yml
    
    if $qadenabuildscripts/build.sh --skip-enclave --title "BOOTSTRAP" ; then
    	echo "Bootstrap build.sh SUCCESS"
    else
        echo "Bootstrap build.sh FAILED"
        rm $qadenabuild/config.yml
        exit 1
    fi
    echo "Init chain to create accounts, so we can extract them to put into real config.yml"

    if ignite chain init --home $QADENAHOME ; then
    	echo "Created accounts"
        echo "Built chain, copying"
        if [[ ! -d "$qadenabin" ]] ; then
            mkdir -p "$qadenabin"
        fi
        cp `which qadena_v3d` $qadenabin/qadenad
    else
        echo "ignite chain init failed"
	    rm $qadenabuild/config.yml
        exit 1
    fi

    echo "Modify config.yml"
    
    cp $qadenabuild/config/config.yml $qadenabuild/config.yml
    
    if $qadenabuildscripts/setPubKAndPubKID.sh coingecko-oracle $qadenabuild/config.yml ; then
    else
        echo "failed to modify $qadenabuild/config.yml"
        exit 1
    fi
    
    if $qadenabuildscripts/setPubKAndPubKID.sh band-protocol-oracle $qadenabuild/config.yml ; then
    else
        echo "failed to modify $qadenabuild/config.yml"
        exit 1
    fi

    if $qadenabuildscripts/setPubKAndPubKID.sh $PIONEER1 $qadenabuild/config.yml ; then
    else
        echo "failed to modify $qadenabuild/config.yml"
        exit 1
    fi
    
    echo "Initializing chain after bootstrap"
    if ignite chain init --home $QADENAHOME ; then
        echo "Built chain, copying"
        if [[ ! -d "$qadenabin" ]] ; then
            mkdir -p "$qadenabin"
        fi
        cp `which qadena_v3d` $qadenabin/qadenad
    else
        echo "FAAAAAIIIILLL"
        exit 1
	    rm $qadenabuild/config.yml
        echo "Failed to build chain, removing config.yml"
        exit 1
    fi
else
    if ignite chain init --home $QADENAHOME  ; then
        echo "Built chain, copying"
        if [[ ! -d "$qadenabin" ]] ; then
            mkdir -p "$qadenabin"
        fi
        cp `which qadena_v3d` $qadenabin/qadenad
    else
        echo ""
        echo ""
        echo "Scroll up...if you see this error:  'Error: failed to validate genesis state: decoding bech32 failed: string not all lowercase or all uppercase'"
        echo "Remove $qadenabuild/config.yml, then try again"
        exit 1
    fi
    
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


if $qadenabuildscripts/setPubKAndPubKID.sh testdsvssrvprv $genesisfile ; then
else
    echo "failed to modify config.yml"
    exit 1
fi

if $qadenabuildscripts/setPubKAndPubKID.sh testidentitysrvprv $genesisfile ; then
else
    echo "failed to modify config.yml"
    exit 1
fi

if $qadenabuildscripts/setPubKAndPubKID.sh ekycphidentitysrvprv $genesisfile ; then
else
    echo "failed to modify config.yml"
    exit 1
fi

if $qadenabuildscripts/setPubKAndPubKID.sh mayaidentitysrvprv $genesisfile ; then
else
    echo "failed to modify config.yml"
    exit 1
fi

if $qadenabuildscripts/setPubKAndPubKID.sh coinsphidentitysrvprv $genesisfile ; then
else
    echo "failed to modify config.yml"
    exit 1
fi

if $qadenabuildscripts/setPubKAndPubKID.sh coopnetidentitysrvprv $genesisfile ; then
else
    echo "failed to modify config.yml"
    exit 1
fi


if $qadenabuildscripts/setPubKAndPubKID.sh unionbankidentitysrvprv $genesisfile ; then
else
    echo "failed to modify config.yml"
    exit 1
fi


if $qadenabuildscripts/setPubKAndPubKID.sh testfinancesrvprv $genesisfile ; then
else
    echo "failed to modify config.yml"
    exit 1
fi
    
echo "Copying node_params.json"
cp config/node_params.json $qadenaconfig
#echo "Copying enclave_params.json"
#cp config/enclave_params.json $qadenaconfig
echo "Fixing up node_params.json..."
$qadenabuildscripts/setPioneerID.sh pioneer1 $nodeparamsfile
#echo "Fixing up enclave_params.json..."


#if [[ $REAL_ENCLAVE == 1 ]] ; then
#    echo "EGo (Edgelesssys Go) is installed, doing 'real enclave' specific tasks."
#    ./create_enclave_dirs.sh
#else    
#fi

echo "Calling build.sh"
$qadenabuildscripts/build.sh --title "FINAL" $build_reproducible_flag

$qadenabuildscripts/install.sh --scripts

    