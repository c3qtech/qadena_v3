#!/bin/zsh

show_manual_funding_instructions() {
    echo "Ok, in order to continue, you'll need to add funds as shown above."
	echo "Once that's done, you can continue converting this node to a full node by typing in:"
	if [[ $GENESIS_PIONEER_SECOND_IP_ADDRESS == "" ]]; then
		echo "  ~/qadena/scripts/add_full_node.sh --pioneer $PIONEER --advertise-ip-address $ADVERTISE_IP_ADDRESS --genesis-pioneer-first-ip-address $GENESIS_PIONEER_FIRST_IP_ADDRESS"
	else
		echo "  ~qadena/scripts/add_full_node.sh --pioneer $PIONEER --advertise-ip-address $ADVERTISE_IP_ADDRESS --genesis-pioneer-first-ip-address $GENESIS_PIONEER_FIRST_IP_ADDRESS --genesis-pioneer-second-ip-address $GENESIS_PIONEER_SECOND_IP_ADDRESS"
	fi
	echo "Stopping the enclave for now"
	$qadenascripts/stop_qadena.sh --enclave > /dev/null
	exit 0
}

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh" 2> /dev/null

# if REAL_ENCLAVE, check if running as root
if [[ $REAL_ENCLAVE -eq 1 ]]; then
    if [[ $(id -u) -ne 0 ]]; then
        echo "run.sh:  Error: qadenad_enclave must be run as root"
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

ADVERTISE_IP_ADDRESS=""
PIONEER=""
GENESIS_PIONEER_FIRST_IP_ADDRESS=""
GENESIS_PIONEER_SECOND_IP_ADDRESS=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --advertise-ip-address)
      if [[ -n "$2" && "$2" != --* ]]; then
        ADVERTISE_IP_ADDRESS="$2"
        shift 2
      else
        echo "Error: --advertise-ip-address requires an argument"
        exit 1
      fi
      ;;
	--pioneer)
      if [[ -n "$2" && "$2" != --* ]]; then
        PIONEER="$2"
        shift 2
      else
        echo "Error: --pioneer requires an argument"
        exit 1
      fi
      ;;
	--genesis-pioneer-first-ip-address)
      if [[ -n "$2" && "$2" != --* ]]; then
        GENESIS_PIONEER_FIRST_IP_ADDRESS="$2"
        shift 2
      else
        echo "Error: --genesis-pioneer-first-ip-address requires an argument"
        exit 1
      fi
      ;;
	--genesis-pioneer-second-ip-address)
      if [[ -n "$2" && "$2" != --* ]]; then
        GENESIS_PIONEER_SECOND_IP_ADDRESS="$2"
        shift 2
      else
        echo "Error: --genesis-pioneer-second-ip-address requires an argument"
        exit 1
      fi
      ;;
    --help)
      echo "Usage: add_full_node.sh --pioneer <pioneer> --advertise-ip-address <advertise-ip-address> --genesis-pioneer-first-ip-address <genesis-pioneer-first-ip-address> [optional: --genesis-pioneer-second-ip-address <genesis-pioneer-second-ip-address>]"
	  echo "Example 1 (adding the second node):  add_full_node.sh --pioneer pioneer2 --advertise-ip-address 192.168.86.133 --genesis-pioneer-first-ip-address 192.168.86.109"
	  echo "Example 2 (adding the 3rd node):  add_full_node.sh --pioneer pioneer3 --advertise-ip-address 192.168.86.140 --genesis-pioneer-first-ip-address 192.168.86.109 --genesis-pioneer-second-ip-address 192.168.86.133"
      exit 0
      ;;      
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

if [[ $PIONEER == "" || $PIONEER == "--help" || $GENESIS_PIONEER_FIRST_IP_ADDRESS == "" ]] ; then
    echo "Args: add_full_node.sh --pioneer <pioneer> --advertise-ip-address <advertise-ip-address> --genesis-pioneer-first-ip-address <genesis-pioneer-first-ip-address> [optional: --genesis-pioneer-second-ip-address <genesis-pioneer-second-ip-address>]"
    echo "Example 1 (adding the second node):  add_full_node.sh --pioneer pioneer2 --advertise-ip-address 192.168.86.133 --genesis-pioneer-first-ip-address 192.168.86.109"
    echo "Example 2 (adding the 3rd node):  add_full_node.sh --pioneer pioneer3 --advertise-ip-address 192.168.86.140 --genesis-pioneer-first-ip-address 192.168.86.109 --genesis-pioneer-second-ip-address 192.168.86.133"
    exit 1
fi

CONTINUE_AFTER_FUNDING=0

if [ -d "$QADENAHOME/enclave_config" ] && [ -f "$QADENAHOME/config/genesis.json" ]; then
	# use dasel to extract the moniker from config.yml
	MONIKER=`dasel -f $QADENAHOME/config/config.toml '.moniker' | tr -d '"' | tr -d "'"`

	# if the moniker matches the default "pioneer1", then most likely it was a test node
	if [[ $MONIKER == "pioneer1" ]] ; then
		echo "*************************************"
		echo "* WARNING:  THIS NODE LOOKS LIKE    *"
		echo "* IT IS ALREADY INITIALIZED, MOST   *"
		echo "* LIKELY AS A STANDALONE NODE.      *"
		echo "* Current Pioneer name: '$MONIKER'  *"
		echo "*************************************"
		echo ""
		REPLY=""
		while [[ $REPLY != "y" && $REPLY != "n" ]]; do
			echo "You are about to make this node into a full node, with a new Pioneer name '$PIONEER'."
			read REPLY\?"This will erase all existing configuration data.  Proceed? (y/n) "
			if [[ $REPLY == "y" ]] ; then
				echo "Ok, will make this a full node."
			elif [[ $REPLY == "n" ]] ; then
				echo "Got it, will not proceed."
				exit 0
			else
				echo "Invalid option $REPLY.  Please try again."
			fi
		done
	else
	    if [[ $MONIKER == $PIONEER ]] ; then
			REPLY=""
			echo "This node is already initialized as $MONIKER."
			while [[ $REPLY != "c" && $REPLY != "s" && $REPLY != "q" ]]; do
				read REPLY\?"Would you like to [c]ontinue after receiving funding, or [s]tart from scratch (erase all existing configuration data), or [q]uit? (c/s/q) "
				if [[ $REPLY == "q" ]] ; then
					exit 0
				elif [[ $REPLY == "s" ]] ; then
					CONTINUE_AFTER_FUNDING=0
				elif [[ $REPLY == "c" ]] ; then
					CONTINUE_AFTER_FUNDING=1
				else
					echo "Invalid option $REPLY.  Please try again."
				fi
			done
		else
  		 	echo "This node is already initialized as $MONIKER."
			REPLY=""
			while [[ $REPLY != "s" && $REPLY != "q" ]]; do
				read REPLY\?"Would you like to [s]tart from scratch (erase all existing configuration data), or [q]uit? (s/q) "
				if [[ $REPLY == "q" ]] ; then
					exit 0
				elif [[ $REPLY == "s" ]] ; then
					CONTINUE_AFTER_FUNDING=0
				elif [[ $REPLY == "c" ]] ; then
					CONTINUE_AFTER_FUNDING=1
				else
					echo "Invalid option $REPLY.  Please try again."
				fi
			done
		fi
	fi
else
	echo "You would like to make this node a full node."
fi

if [[ $CONTINUE_AFTER_FUNDING -eq 1 ]]; then
	echo "Ok, will continue after receiving funding."
else
	REPLY=""
	while [[ $REPLY != "y" && $REPLY != "n" ]]; do
		read REPLY\?"Final confirmation.  Are you really sure? (y/n) "
		if [[ $REPLY == "y" ]] ; then
			echo "Ok, will start from scratch."
		elif [[ $REPLY == "n" ]] ; then
			echo "Got it, will not proceed."
			exit 0
		else
			echo "Invalid option $REPLY.  Please try again."
		fi
	done

	echo "Stopping any running qadenad and qadenad_enclave processes..."
	$qadenascripts/stop_qadena.sh --all > /dev/null

	# save the config/*.toml files
	rm -rf /tmp/qadena_config_backup
	mkdir /tmp/qadena_config_backup
	cp $QADENAHOME/config/*.toml /tmp/qadena_config_backup/

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

	# restore the config/*.toml files
	cp /tmp/qadena_config_backup/*.toml $QADENAHOME/config/

	echo "Fixing up app.toml"
	# get it from config.yml
	minimum_gas_prices=`dasel -f $QADENAHOME/config/config.yml 'validators.first().app.minimum-gas-prices'`
	# set it on app.toml
	dasel put -v "$minimum_gas_prices" '.minimum-gas-prices' -f $QADENAHOME/config/app.toml

	echo "Fixing up config.toml"

	new_external_address="${ADVERTISE_IP_ADDRESS}:26656"
	new_rpc_laddr_url="tcp://0.0.0.0:26657"
	new_priv_validator_laddr_url="tcp://0.0.0.0:26659"
	dasel put -v "$PIONEER" '.moniker' -f $QADENAHOME/config/config.toml
	dasel put -v "$new_external_address" '.p2p.external_address' -f $QADENAHOME/config/config.toml
	dasel put -v "$new_rpc_laddr_url" '.rpc.laddr' -f $QADENAHOME/config/config.toml
	dasel put -v "$new_priv_validator_laddr_url" '.priv_validator_laddr' -f $QADENAHOME/config/config.toml
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
		TRUSTHEIGHT=`jq -r '.result.block.header.height' $QADENAHOME/config/block.1`
		TRUSTHASH=`jq -r '.result.block_id.hash' $QADENAHOME/config/block.1`
		
		echo "TRUSTHEIGHT $TRUSTHEIGHT, TRUSTHASH $TRUSTHASH"

		if [[ $TRUSTHEIGHT -gt 1500 ]] ; then
		
			if curl --fail -k "http://$GENESIS_PIONEER_SECOND_IP_ADDRESS:26657/block?height=$TRUSTHEIGHT" --output $QADENAHOME/config/block.2 > /dev/null 2> /dev/null ; then
			TRUSTHEIGHT2=`jq -r '.result.block.header.height' $QADENAHOME/config/block.2`
			TRUSTHASH2=`jq -r '.result.block_id.hash' $QADENAHOME/config/block.2`
			
			if [[ $TRUSTHEIGHT == $TRUSTHEIGHT2 && $TRUSTHASH == $TRUSTHASH2 ]] ; then
				echo "Great, same same, we can trust height/hash, modifying config.toml"

				dasel put -v true '.statesync.enable' -f $QADENAHOME/config/config.toml

				new_rpc_servers="$GENESIS_PIONEER_FIRST_IP_ADDRESS:26657,$GENESIS_PIONEER_SECOND_IP_ADDRESS:26657"
				dasel put -v "$new_rpc_servers" '.statesync.rpc_servers' -f $QADENAHOME/config/config.toml

				new_trust_height="$TRUSTHEIGHT"
				dasel put -v "$new_trust_height" '.statesync.trust_height' -f $QADENAHOME/config/config.toml
				
				new_trust_hash="$TRUSTHASH"
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


	qadenad_alias query --node "tcp://$GENESIS_PIONEER_FIRST_IP_ADDRESS:26657" qadena show-interval-public-key-id $PIONEER pioneer

	if [[ $? != 5 ]] ; then
		echo "The Pioneer $PIONEER already exists, please choose a different Pioneer name."
		exit 1
	fi

	echo "$PIONEER does not already exist (the name can be used), that's good."

	qadenad_alias keys add $PIONEER --keyring-backend test

	if [[ $? != 0 ]] ; then
		echo "Failed to add keys for $PIONEER"
		exit 1
	fi

	echo ""

fi

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


echo "PIONEER $PIONEER"

PIONEERADDRESS=`qadenad_alias keys show $PIONEER -a --keyring-backend test`
echo "PIONEER ADDRESS $PIONEERADDRESS"
FULL="10"
VALIDATOR="110000"
FULL_AQDN=`echo "$FULL * 1000000000000000000" | bc`

echo ""
echo "This node is *almost* a Qadena 'full-node'"
#echo "(TESTNET) Please execute this on the one of the validators"
#echo ""
#echo "  For full node:"
#echo "    ~/qadena/bin/qadenad --home ~/qadena tx bank send treasury $PIONEERADDRESS ${FULL}qdn --yes --gas-prices $minimum_gas_prices --gas auto --gas-adjustment $gas_adjustment"
#echo "  For validator node:"
#echo "    ~/qadena/bin/qadenad --home ~/qadena tx bank send treasury $PIONEERADDRESS ${VALIDATOR}qdn --yes --gas-prices $minimum_gas_prices --gas auto --gas-adjustment $gas_adjustment"
#echo ""
echo "(TESTNET) Please send an email to qadenatestnet@c3qtech.com with the subject 'Qadena Testnet Full Node'"
echo "(TESTNET) and include the Pioneer name, the Pioneer address ($PIONEERADDRESS), the Pioneer public IP address of the node."
echo "(TESTNET) If you're going to run a full-node, request for ${FULL}qdn to be sent to $PIONEERADDRESS."
echo "(TESTNET) If you're going to run a validator node, request for ${VALIDATOR}qdn to be sent to $PIONEERADDRESS."
echo ""
echo "(PRODUCTION) Full Node:  Please purchase and send at least ${FULL}qdn to $PIONEERADDRESS"
echo "(PRODUCTION) Validator Node:  Please purchase and send at least ${VALIDATOR}qdn to $PIONEERADDRESS"
REPLY=""
while [[ $REPLY != "y" && $REPLY != "n" ]]; do
	read REPLY\?"Are you done sending funds to $PIONEERADDRESS ? (y/n) "
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
			echo "$PIONEER has enough funds!"
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
			$qadenascripts/stop_qadena.sh --enclave > /dev/null
			show_manual_funding_instructions
		fi

		# ask the enclave to sync with another enclave and get the necessary keys for a full-node to be able to sync with the chain
		
		qadenad_alias enclave sync-enclave $PIONEER $ADVERTISE_IP_ADDRESS "tcp://$GENESIS_PIONEER_FIRST_IP_ADDRESS:26657"
		
		if [[ $? != 0 ]] ; then
			echo "Failed to syncrhonize my enclave with the Pioneer/Enclave on $GENESIS_PIONEER_FIRST_IP_ADDRESS"
			echo "Stopping the enclave"
			$qadenascripts/stop_qadena.sh --enclave &> /dev/null
			exit 1
		fi
	elif [[ $REPLY == "n" ]] ; then
		show_manual_funding_instructions
	else
		echo "Invalid option $REPLY.  Please try again."
	fi
done

echo "Stopping the enclave"
$qadenascripts/stop_qadena.sh --enclave  > /dev/null

echo "Start the new qadena 'full-node' and wait until it synchronizes with the qadena network."
echo "Once synchronized, if you want to make it a candidate validator by staking qadena, run ./add_validator.sh."
echo ""

REPLY=""
while [[ $REPLY != "y" && $REPLY != "n" ]]; do
	read REPLY\?"Do you want to start the new qadena 'full-node' now? (y/n) "
	if [[ $REPLY == "y" ]] ; then
		$qadenascripts/start_qadena.sh
	elif [[ $REPLY == "n" ]] ; then
		echo "Ok, will not start it now.  You can do so later by typing in:"
		echo "  $qadenascripts/start_qadena.sh"
	else
		echo "Invalid option $REPLY.  Please try again."
	fi
done
