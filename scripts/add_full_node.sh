#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

# if REAL_ENCLAVE, check if running as root
if [[ $REAL_ENCLAVE -eq 1 ]]; then
    if [[ $(id -u) -ne 0 ]]; then
        echo "run.sh:  Error: qadenad_enclave must be run as root"
        exit 1
    fi
fi


if [ -d "$QADENAHOME/enclave_config" ] && [ -n "$(ls -A "$QADENAHOME/enclave_config")" ] && [ -f "$QADENAHOME/config/genesis.json" ]; then

    echo "**********************************"
    echo "* WARNING:  THIS NODE LOOKS LIKE *"
	echo "* IT IS ALREADY INITIALIZED.     *"
    echo "**********************************"
    read REPLY\?"Are you sure you want to proceed?  This will erase all existing data.  (y/N) "
    if [[ $REPLY == "y" ]] ; then
		echo "Ok"
    else
		echo "Will not proceed."
		exit 1
    fi
fi

if which jq > /dev/null ; then
else
  echo "jq needs to be installed (e.g. sudo apt-get install jq, brew install jq, ...)"
  exit 1
fi

if which dasel > /dev/null ; then
else
  echo "dasel needs to be installed"
  echo "   macos: brew install dasel"
  echo '   linux_x86: curl -sSLf "$(curl -sSLf https://api.github.com/repos/tomwright/dasel/releases/latest | grep browser_download_url | grep linux_amd64 | grep -v .gz | cut -d\" -f 4)" -L -o dasel && chmod +x dasel
sudo mv ./dasel /usr/local/bin/dasel'
  echo '   linux_arm64: curl -sSLf "$(curl -sSLf https://api.github.com/repos/tomwright/dasel/releases/latest | grep browser_download_url | grep linux_arm64 | grep -v .gz | cut -d\" -f 4)" -L -o dasel && chmod +x dasel
sudo mv ./dasel /usr/local/bin/dasel'
  exit 1
fi


if which curl > /dev/null ; then
else
  echo "curl needs to be installed (e.g. sudo apt-get install curl, brew install curl, ...)"
  exit 1
fi

if which $qadenad_binary > /dev/null ; then
else
  echo "$qadenad_binary is missing"
  exit 1
fi

PIONEER=$1
ADVERTISE_IP_ADDRESS=$2
GENESIS_PIONEER_FIRST_IP_ADDRESS=$3
GENESIS_PIONEER_SECOND_IP_ADDRESS=$4

if [[ $PIONEER == "" || $GENESIS_PIONEER_FIRST_IP_ADDRESS == "" ]] ; then
    echo "Args: add_full_node.sh new-pioneer-id new-pioneer-advertise-ip-address genesis-pioneer-first-ip-address [optional: genesis-pioneer-second-ip-address]"
    echo "Example 1 (adding the second node):  add_full_node.sh pioneer2 192.168.86.133 192.168.86.109"
    echo "Example 2 (adding the 3rd node):  add_full_node.sh pioneer3 192.168.86.140 192.168.86.109 192.168.86.133"
    exit 1
fi

echo "Stopping any running qadenad and qadenad_enclave processes..."
$qadenascripts/stop_chain.sh --all

echo "Removing configuration directories from:  $QADENAHOME (config, data, keyring-test, enclave_config, enclave_data)"
rm -f $QADENAHOME/config/public.pem
rm -f $QADENAHOME/config/*.toml
rm -f $QADENAHOME/config/*.1
rm -f $QADENAHOME/config/genesis.json
rm -f $QADENAHOME/config/node_key.json
rm -f $QADENAHOME/config/priv_validator_key.json
rm -rf $QADENAHOME/data
rm -rf $QADENAHOME/keyring-test
rm -rf $QADENAHOME/enclave_config
rm -rf $QADENAHOME/enclave_data

echo "Calling 'qadenad init'"
qadenad_alias init $PIONEER > /dev/null 2> /dev/null

if [[ $? != 0 ]] ; then
    echo "Failed to qadenad init"
    exit 1
fi

echo "Fixing up app.toml"
# get it from config.yml
minimum_gas_prices=`dasel -f $QADENAHOME/config/config.yml 'validators.first().app.minimum-gas-prices'`
# set it on app.toml
dasel put -v "$minimum_gas_prices" '.minimum-gas-prices' -f $QADENAHOME/config/app.toml

echo "Fixing up config.toml"

new_external_address="${ADVERTISE_IP_ADDRESS}:26656"
new_rpc_laddr_url="tcp://0.0.0.0:26657"
dasel put -v "$new_external_address" '.p2p.external_address' -f $QADENAHOME/config/config.toml
dasel put -v "$new_rpc_laddr_url" '.rpc.laddr' -f $QADENAHOME/config/config.toml
dasel put -v "false" '.p2p.addr_book_strict' -f $QADENAHOME/config/config.toml

new_log_level="info"
dasel put -v "$new_log_level" '.log_level' -f $QADENAHOME/config/config.toml

echo "Getting genesis block from $GENESIS_PIONEER_FIRST_IP_ADDRESS"
if curl --fail -k "http://$GENESIS_PIONEER_FIRST_IP_ADDRESS:26657/genesis" --output $QADENAHOME/config/genesis.json.1 > /dev/null 2> /dev/null ; then
    echo "...it's good."
else
    echo "...couldn't get it from $GENESIS_PIONEER_FIRST_IP_ADDRESS, are you sure Qadena is running?"
    exit 1
fi

echo "Fixing up client.toml"

new_keyring_backend="test"
dasel put -v "$new_keyring_backend" '.keyring-backend' -f $QADENAHOME/config/client.toml
new_chain_id=`jq -r '.result.genesis.chain_id' $QADENAHOME/config/genesis.json.1`
echo "new_chain_id $new_chain_id"
dasel put -v "$new_chain_id" '.chain-id' -f $QADENAHOME/config/client.toml


if [[ $GENESIS_PIONEER_SECOND_IP_ADDRESS != "" ]] ; then
    echo "Getting genesis block from $GENESIS_PIONEER_SECOND_IP_ADDRESS"
    if curl --fail -k "http://$GENESIS_PIONEER_SECOND_IP_ADDRESS:26657/genesis" --output $QADENAHOME/config/genesis.json.2 > /dev/null 2> /dev/null ; then
	echo "...it's good."
	echo "Comparing against the genesis block we got from $GENESIS_PIONEER_FIRST_IP_ADDRESS"
	if diff $QADENAHOME/config/genesis.json.1 $QADENAHOME/config/genesis.json.2 > /dev/null 2> /dev/null ; then
	    echo "Great, same same!"
	else
	    echo "They're different!  Something is wrong, please try another set of Qadena Pioneers"
	    exit 1
	fi
    else
	echo "...couldn't get it"
	exit 1
    fi
fi

echo "Extracting genesis"
jq ".result.genesis" $QADENAHOME/config/genesis.json.1 > $QADENAHOME/config/genesis.json

echo "Getting node ID from $GENESIS_PIONEER_FIRST_IP_ADDRESS..."
if curl --fail -k "http://$GENESIS_PIONEER_FIRST_IP_ADDRESS:26657/status" --output $QADENAHOME/config/status.1 > /dev/null 2> /dev/null ; then
    echo "...it's good."
    PIONEER_FIRST_ID=`jq -r '.result.node_info.id' $QADENAHOME/config/status.1`
fi

if [[ $GENESIS_PIONEER_SECOND_IP_ADDRESS != "" ]] ; then
    echo "Getting node ID from $GENESIS_PIONEER_SECOND_IP_ADDRESS"
    if curl --fail -k "http://$GENESIS_PIONEER_SECOND_IP_ADDRESS:26657/status" --output $QADENAHOME/config/status.2 > /dev/null 2> /dev/null ; then
	echo "...it's good."
	PIONEER_SECOND_ID=`jq -r '.result.node_info.id' $QADENAHOME/config/status.2`
    fi
fi

# now we need to get a trust height and trust hash

if [[ $GENESIS_PIONEER_FIRST_IP_ADDRESS != "" && $GENESIS_PIONEER_SECOND_IP_ADDRESS != "" ]] ; then
    echo "Getting trust height and trust hash for quicker 'statesync'..."
    if curl --fail -k "http://$GENESIS_PIONEER_FIRST_IP_ADDRESS:26657/block" --output $QADENAHOME/config/block.1 > /dev/null 2> /dev/null ; then
	echo "...it's good."
	TRUSTHEIGHT=`jq '.result.block.header.height' $QADENAHOME/config/block.1`
	TRUSTHASH=`jq '.result.block_id.hash' $QADENAHOME/config/block.1`
	
	echo "TRUSTHEIGHT $TRUSTHEIGHT, TRUSTHASH $TRUSTHASH"

	if [[ $TH -gt 1500 ]] ; then
	
	    if curl --fail -k "http://$GENESIS_PIONEER_SECOND_IP_ADDRESS:26657/block?height=$TH" --output $QADENAHOME/config/block.2 > /dev/null 2> /dev/null ; then
		TRUSTHEIGHT2=`jq '.result.block.header.height' $QADENAHOME/config/block.2`
		TRUSTHASH2=`jq '.result.block_id.hash' $QADENAHOME/config/block.2`
		
		if [[ $TRUSTHEIGHT == $TRUSTHEIGHT2 && $TRUSTHASH == $TRUSTHASH2 ]] ; then
		    echo "Great, same same, we can trust height/hash, modifying config.toml"

			dasel put -v true '.enable' -f $QADENAHOME/config/config.toml

			new_rpc_servers = "$GENESIS_PIONEER_FIRST_IP_ADDRESS:26657,$GENESIS_PIONEER_SECOND_IP_ADDRESS:26657"
			dasel put -v "$new_rpc_servers" '.statesync.rpc_servers' -f $QADENAHOME/config/config.toml

			new_trust_height = "$TH"
			dasel put -v "$new_trust_height" '.statesync.trust_height' -f $QADENAHOME/config/config.toml
			
			new_trust_hash = "$TRUSTHASH"
			dasel put -v "$new_trust_hash" '.statesync.trust_hash' -f $QADENAHOME/config/config.toml
		else
		    echo "Trust height and trust hash do not match"
		    exit 1
		fi
	    else
		echo "...couldn't get it"
		exit 1
	    fi
	else
	    echo "Trust height is too low, we won't use state sync"
	fi
    else
	echo "...couldn't get it"
	exit 1
    fi
else
    echo "Using normal sync"
fi

#cp config/node_params.json $QADENAHOME/config
echo "Fixing up node_params.json..."
$qadenascripts/setPioneerID.sh $PIONEER $QADENAHOME/config/node_params.json

if [[ $? != 0 ]] ; then
    echo "Failed to copy genesis file"
    exit 1
fi

#ORIG_VALIDATOR=`jq ".app_state.genutil.gen_txs[0].body.memo" $QADENAHOME/config/genesis.json`
#
#if [[ $? != 0 ]] ; then
#    echo "Failed to extract the validator from the genesis.json file."
#    exit 1
#fi
#
#echo $ORIG_VALIDATOR

new_persistent_peers=''
if [[ $PIONEER_SECOND_ID == "" ]] ; then
    new_persistent_peers="${PIONEER_FIRST_ID}@${GENESIS_PIONEER_FIRST_IP_ADDRESS}:26656"
else
    new_persistent_peers="${PIONEER_FIRST_ID}@${GENESIS_PIONEER_FIRST_IP_ADDRESS}:26656,${PIONEER_SECOND_ID}@${GENESIS_PIONEER_SECOND_IP_ADDRESS}:26656"
fi

dasel put -v "$new_persistent_peers" '.p2p.persistent_peers' -f $QADENAHOME/config/config.toml

echo "DEBUG $DEBUG"

if [[ $REAL_ENCLAVE == 1 ]] ; then
    $qadenascripts/run_realenclave.sh &
    sleep 10
else
    $qadenascripts/run_enclave.sh $DEBUG &
fi

# wait for socket to come up
IS_UP=0
for i in {90..1}
do
    if [[ "$(uname -s)" == "Darwin" ]] ; then
	listen=`netstat -an`
    else
	listen=`netstat -l`
    fi
    
    if echo $listen | grep 50051 > /dev/null ; then
	echo "qadenad_enclave is up and running!"
	IS_UP=1


	if [[ "$(uname -s)" == "Darwin" ]] ; then
	    echo -n -e "\033]0;\007"
	fi
	break
    else
	echo "qadenad_enclave is not yet up, waiting...$i"
	sleep 1
    fi
done
if [ $IS_UP -ne 1 ] ; then
    echo "Could not run the qadenad_enclave"
    exit 1
fi

qadenad_alias query --node "tcp://$GENESIS_PIONEER_FIRST_IP_ADDRESS:26657" qadena show-interval-public-key-id $PIONEER pioneer

if [[ $? != 5 ]] ; then
    echo "The Pioneer $PIONEER already exists, please choose a different Pioneer name."
    exit 1
fi

echo "If I couldn't find $PIONEER, that's good."

qadenad_alias keys add $PIONEER --keyring-backend test

if [[ $? != 0 ]] ; then
    echo "Failed to add keys for $PIONEER"
    exit 1
fi

echo ""

echo "PIONEER $PIONEER"

PIONEERADDRESS=`qadenad_alias keys show $PIONEER -a --keyring-backend test`
echo "PIONEER ADDRESS $PIONEERADDRESS"
FULL="10"
VALIDATOR="11000"
FULL_AQDN=`echo "$FULL * 1000000000000000000" | bc`

echo ""
echo "This node is *almost* a qadena 'full-node'"
echo "(TESTNET) Please execute this on the one of the validators"
echo ""
echo "  For full node:"
echo "    $QADENAHOME/bin/qadenad --home $QADENAHOME tx bank send treasury $PIONEERADDRESS ${FULL}qdn --yes"
echo "  For validator node:"
echo "    $QADENAHOME/bin/qadenad --home $QADENAHOME tx bank send treasury $PIONEERADDRESS ${VALIDATOR}qdn --yes"
echo ""
echo "(PRODUCTION) Full Node:  Please purchase and send at least ${FULL}qdn to $PIONEERADDRESS"
echo "(PRODUCTION) Validator Node:  Please purchase and send at least ${VALIDATOR}qdn to $PIONEERADDRESS"
read REPLY\?"Are you done sending funds to $PIONEERADDRESS? (y/N) "
if [[ $REPLY == "y" ]] ; then

    echo "I will attempt to detect when $PIONEERADDRESS has at least ${FULL}qdn."
    
    IS_UP=0
    for i in {120..1}
    do
	BALANCE_JSON=`qadenad_alias --node "tcp://$GENESIS_PIONEER_FIRST_IP_ADDRESS:26657" query bank balances $PIONEERADDRESS --output json`
	BALANCE=`echo $BALANCE_JSON | jq -r '.balances[] | select(.denom=="aqdn") | .amount'`
	if [[ $BALANCE != "" ]] ; then
	    ret=`echo "$BALANCE >= $FULL_AQDN" | bc`
	    #    echo "ret $ret"
	    if [[ $ret = 1 ]] ; then
		echo "$PIONEER has balance!"
		IS_UP=1
		break
	    else
		echo "Balance is ${BALANCE}aqdn, not enough.  Waiting...$i"
		sleep 3
	    fi
	else
	    echo "No balance detected yet"
	    sleep 3
	fi
    done

    if [ $IS_UP -eq 0 ] ; then
		echo "Couldn't find balance for $PIONEERADDRESS"
		echo "Stopping the enclave"
		$qadenascripts/stop_chain.sh --enclave
		exit 1
    fi

    # ask the enclave to sync with another enclave and get the necessary keys for a full-node to be able to sync with the chain
    
    qadenad_alias enclave sync-enclave $PIONEER $ADVERTISE_IP_ADDRESS "tcp://$GENESIS_PIONEER_FIRST_IP_ADDRESS:26657"
    
    if [[ $? != 0 ]] ; then
		echo "Failed to syncrhonize my enclave with the Pioneer/Enclave on $GENESIS_PIONEER_FIRST_IP_ADDRESS"
		echo "Stopping the enclave"
		$qadenascripts/stop_chain.sh --enclave
		exit 1
	fi
else
    echo "Ok, in order to continue, you'll need to add funds as shown above."
	echo "Once that's done, you can start the full node by typing in:"
	echo "  $qadenascripts/run.sh --sync-with-pioneer $GENESIS_PIONEER_FIRST_IP_ADDRESS"
	echo "Stopping the enclave"
	$qadenascripts/stop_chain.sh --enclave
	exit 1
fi

echo "Stopping the enclave"
$qadenascripts/stop_chain.sh --enclave

echo "Start the new qadena 'full-node' and wait until it synchronizes with the qadena network."
echo "Once synchronized, if you want to make it a candidate validator by staking qadena, run ./add_validator.sh."
echo ""
read REPLY\?"Do you want to start the new qadena 'full-node' now? (y/N) "
if [[ $REPLY == "y" ]] ; then
    $qadenascripts/run.sh --sync-with-pioneer $GENESIS_PIONEER_FIRST_IP_ADDRESS
else
    echo "Ok, will not start it now.  You can do so later by typing in:"
    echo "  $qadenascripts/run.sh --sync-with-pioneer $GENESIS_PIONEER_FIRST_IP_ADDRESS"
fi

