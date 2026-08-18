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

# Root only when an ego enclave will actually run: SGX hardware AND a signed binary.
needs_root_if_real_enclave "add_full_node.sh" "$qadenabin/qadenad_enclave"



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
STOP_FOR_FUNDING=""
TEST_NET=""
GENESIS_PIONEER_FIRST_IP_ADDRESS=""
# Escape hatch for the enclave-build pre-check below: for a seed too old to answer
# `q qadena enclave-measurement`.  Not for making an inconvenient refusal go away -- a genuine
# mismatch cannot join, whatever this flag says.
SKIP_ENCLAVE_CHECK=0
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
	--skip-enclave-check)
		SKIP_ENCLAVE_CHECK=1
		shift
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
    --stop-for-funding)
      STOP_FOR_FUNDING="true"
      shift
      ;;
    --test-net)
      TEST_NET="true"
      shift
      ;;
    --help)
      echo "Usage: add_full_node.sh --pioneer <pioneer> --advertise-ip-address <advertise-ip-address> --genesis-pioneer-first-ip-address <genesis-pioneer-first-ip-address> [optional: --genesis-pioneer-second-ip-address <genesis-pioneer-second-ip-address>]"
	  echo "Example 1 (adding the second node):  add_full_node.sh --pioneer pioneer2 --advertise-ip-address 192.168.86.133 --genesis-pioneer-first-ip-address 192.168.86.109"
	  echo "Example 2 (adding the 3rd node):  add_full_node.sh --pioneer pioneer3 --advertise-ip-address 192.168.86.140 --genesis-pioneer-first-ip-address 192.168.86.109 --genesis-pioneer-second-ip-address 192.168.86.133"
	  echo ""
	  echo "  --stop-for-funding   Mint the pioneer key, print its address, and EXIT instead of"
	  echo "                       waiting for the balance.  Re-run without the flag once the funds"
	  echo "                       have arrived and answer [c] to continue, which keeps the key."
	  echo "                       Use this when funding is not something you can do within minutes"
	  echo "                       -- which on the testnet it is not, since the instructions above"
	  echo "                       are to EMAIL for coins while the wait below lasts six minutes."
	  echo "  --skip-enclave-check Do not compare enclave builds with the seed before wiping this"
	  echo "                       node.  For a seed too old to answer 'q qadena enclave-measurement'."
	  echo "                       A genuine mismatch still cannot join: the joiner bootstraps its"
	  echo "                       trusted set from the seed and can only accept that from a seed"
	  echo "                       running its own measurement."
	  echo "  --test-net           Print the ACTUAL command that funds this node, to run on a"
	  echo "                       validator, instead of the email-us instructions.  On a test"
	  echo "                       network whoever is standing this node up also holds the"
	  echo "                       treasury key, so the useful output is a command, not an"
	  echo "                       address and an address to write to."
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

# EVERY PROMPT BELOW GUARDS AGAINST EOF, and that is a bug fix rather than defensive habit.
#
# The prompts are `while [[ $REPLY != ... ]]; do read REPLY?"..."` loops.  `read` returns non-zero at
# end of input and leaves REPLY untouched, so the loop condition stays true and it spins as fast as
# the CPU allows.  Anything that closes stdin does it: a pipe that ends, a here-string, a FIFO whose
# writer went away, nohup with no terminal.
#
# Observed: a run driven through a FIFO sat spinning at ~100% of a core for two and a half hours
# after its work had finished, stuck on the final "start the node now?" prompt -- competing with a
# reproducible build and a regression run on the same machine, with nothing in any log to say so.
#
# Failing beats defaulting here: these prompts erase configuration and start validators, and
# guessing on behalf of an absent operator is worse than stopping.

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
			read REPLY\?"This will erase all existing configuration data.  Proceed? (y/n) " || { echo ""; echo "add_full_node.sh: stdin closed while waiting for an answer -- refusing to loop."; exit 1; }
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
				read REPLY\?"Would you like to [c]ontinue after receiving funding, or [s]tart from scratch (erase all existing configuration data), or [q]uit? (c/s/q) " || { echo ""; echo "add_full_node.sh: stdin closed while waiting for an answer -- refusing to loop."; exit 1; }
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
				read REPLY\?"Would you like to [s]tart from scratch (erase all existing configuration data), or [q]uit? (s/q) " || { echo ""; echo "add_full_node.sh: stdin closed while waiting for an answer -- refusing to loop."; exit 1; }
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
		read REPLY\?"Final confirmation.  Are you really sure? (y/n) " || { echo ""; echo "add_full_node.sh: stdin closed while waiting for an answer -- refusing to loop."; exit 1; }
		if [[ $REPLY == "y" ]] ; then
			echo "Ok, will start from scratch."
		elif [[ $REPLY == "n" ]] ; then
			echo "Got it, will not proceed."
			exit 0
		else
			echo "Invalid option $REPLY.  Please try again."
		fi
	done

	# DO THE ENCLAVE BUILDS MATCH?  Asked here, before anything is stopped, wiped, minted or funded.
	#
	# A joiner bootstraps its trusted set from the seed during sync-enclave, and it can only accept
	# that from a seed running its OWN measurement -- that is the single anchor a fresh enclave can
	# verify (see enclave_trusted_identities.go).  A mismatch therefore cannot succeed, and finding
	# out at the handshake means discovering it after this script has wiped the node's state and
	# spent a funding transfer, from an error that names neither build.
	#
	# FAILS CLOSED.  This was advisory when the query failed -- on the reasoning that an older seed
	# has no enclave-measurement command and refusing would be worse than proceeding.  The effect was
	# that a BROKEN query silently disabled the protection: the first real mismatch printed "could
	# not ask ... which enclave it runs" and carried straight on to
	#
	#     Removing configuration directories from: /home/alvillarica/qadena
	#
	# wiping the node this check exists to protect.  A check that is advisory exactly when it cannot
	# see is not a check.  Being unable to ask is itself a reason to stop, because proceeding risks
	# precisely that damage; --skip-enclave-check is the way to say "I know, this seed is older".
	local_measurement=$($qadenabin/qadenad_enclave --unique-id 2>/dev/null)
	seed_measurement=$(qadenad_alias q qadena enclave-measurement --node "tcp://$GENESIS_PIONEER_FIRST_IP_ADDRESS:26657" -o json 2>/dev/null | jq -r '.uniqueID // empty' 2>/dev/null)
	if [[ $SKIP_ENCLAVE_CHECK -eq 1 ]] ; then
		echo "add_full_node.sh: --skip-enclave-check given; not comparing enclave builds with the seed"
	elif [[ -z $local_measurement ]] ; then
		echo "add_full_node.sh: could not read THIS node's enclave measurement from $qadenabin/qadenad_enclave"
		echo "    Without it there is nothing to compare, and this script is about to wipe this node's"
		echo "    configuration and spend a funding transfer.  Refusing."
		echo "    Re-run with --skip-enclave-check to proceed anyway."
		exit 1
	elif [[ -z $seed_measurement ]] ; then
		echo "add_full_node.sh: could not ask $GENESIS_PIONEER_FIRST_IP_ADDRESS which enclave it runs."
		echo "    Either the seed predates 'q qadena enclave-measurement', or the query failed."
		echo "    Refusing rather than guessing: a joiner can only bootstrap trust from a seed running"
		echo "    its own measurement ($local_measurement), and the next thing this script does is wipe"
		echo "    this node and spend a funding transfer."
		echo "    Check by hand:"
		echo "        qadenad q qadena enclave-measurement --node tcp://$GENESIS_PIONEER_FIRST_IP_ADDRESS:26657"
		echo "    or re-run with --skip-enclave-check if you know the seed is older than this check."
		exit 1
	elif [[ "$seed_measurement" != "$local_measurement" ]] ; then
		echo "add_full_node.sh: ENCLAVE MISMATCH -- this join cannot succeed."
		echo "    the seed at $GENESIS_PIONEER_FIRST_IP_ADDRESS runs:  $seed_measurement"
		echo "    this node was built as:                              ${local_measurement:-unknown}"
		echo ""
		echo "    A joiner takes its initial trusted set from the seed, over a channel it can only"
		echo "    authenticate by recognising the seed as its own build.  sync-enclave will refuse."
		echo ""
		echo "    Fix it either way round:"
		echo "      - install this node from a package built on the seed, or"
		echo "      - point --genesis-pioneer-first-ip-address at a node running $local_measurement."
		exit 1
	else
		echo "add_full_node.sh: seed and joiner both run enclave $local_measurement"
	fi

	echo "Stopping any running qadenad and qadenad_enclave processes..."
	$qadenascripts/stop_qadena.sh --all > /dev/null

	# save the config/*.toml files
	rm -rf /tmp/qadena_config_backup
	mkdir /tmp/qadena_config_backup
	cp $QADENAHOME/config/*.toml /tmp/qadena_config_backup/

	echo "Removing configuration directories from:  $QADENAHOME (config, data, keyring-test, enclave_config, enclave_data, enclave_secrets)"
	# public.pem IS NOT NODE STATE and is deliberately NOT removed here.  It is the enclave signer's
	# public key, installed alongside the binaries by install.sh / install_release.sh, and nothing
	# anywhere puts it back once deleted.
	#
	# Deleting it does not fail here, or at the next step, which is why it survived so long.  It
	# fails at the node's FIRST START, in init_enclave.sh:
	#
	#   qadenad_alias enclave init-enclave --enclave-signer-id $SIGNER_ID --enclave-unique-id ...
	#
	# is unquoted, so an unreadable public.pem makes $SIGNER_ID empty, --enclave-signer-id swallows
	# --enclave-unique-id as its value, every positional shifts left, and the command dies with
	# "accepts 4 arg(s), received 5".  The enclave never initialises and the node kills itself.
	#
	# It was survivable only while every machine also had a build tree whose install.sh could put the
	# file back; a node installed from a release package has no such tree.  (The value is not read by
	# run.sh's --enclave-signer-id -- keeper.InitEnclave takes the unix-domain-socket branch and only
	# logs it -- but init_enclave.sh needs the FILE to exist to form a valid command line at all.)
	rm -f $QADENAHOME/config/*.toml
	rm -f $QADENAHOME/config/*.1
	rm -f $QADENAHOME/config/genesis.json
	rm -f $QADENAHOME/config/node_key.json
	rm -f $QADENAHOME/config/priv_validator_key.json
	rm -rf $QADENAHOME/data
	rm -rf $QADENAHOME/keyring-test
	rm -rf $QADENAHOME/enclave_config
	rm -rf $QADENAHOME/enclave_data
	# enclave_secrets holds the SS interval shares and privK cache.  It is deleted IN LOCKSTEP
	# with enclave_data: a secrets DB surviving next to a wiped tree would describe keys the
	# fresh enclave never generated.
	rm -rf $QADENAHOME/enclave_secrets

	echo "Calling 'qadenad init'"
	qadenad_alias init $PIONEER > /dev/null 2> /dev/null

	if [[ $? != 0 ]] ; then
		echo "Failed to qadenad init"
		exit 1
	fi

	# restore the config/*.toml files
	cp /tmp/qadena_config_backup/*.toml $QADENAHOME/config/

	echo "Fixing up app.toml"
	# THE WHOLE app: STANZA, not just minimum-gas-prices.
	#
	# This used to copy exactly one key out of config.yml.  The genesis node gets its app.toml from
	# `ignite chain init`, which renders that stanza in full; a joining node gets it from
	# `qadenad init`, whose stock template has NO [json-rpc], NO [evm] and NO [wasm] section at all.
	# So every joined node silently differed from the genesis node in everything config.yml
	# prescribes -- and nothing failed, because none of it is consensus-critical.
	#
	# It surfaced as the EVM JSON-RPC never coming up on the second validator: port 8545 simply was
	# not listening, because json-rpc.enable lives in a section that did not exist.  run.sh hides
	# that further by passing --json-rpc.api on the command line, so the API list is configured
	# while the server stays off.  Also silently missing: the evm mempool limits, wasm's
	# query_gas_limit and memory_cache_size, and the pruning settings.
	$qadenascripts/apply_app_config.sh \
	    --config $QADENAHOME/config/config.yml \
	    --app-toml $QADENAHOME/config/app.toml

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

				# A chain snapshot carries CHAIN stores only.  The enclave-private tables -- the AML
				# rolling window, the credential uniqueness index and its superseded aliases, the
				# sub-wallet and recovery maps -- are produced only by executing blocks, and nothing
				# on chain encodes them.  A node that state-synced without them would run with an
				# empty AML window, reach different accept/reject verdicts than the network on
				# threshold-straddling transfers, and fork silently.
				#
				# They are fetched from a peer instead: the app rejects a snapshot at a height no
				# peer's enclave can serve (App.OfferSnapshot), and the first BeginBlock pulls the
				# tables before any transaction of that block executes, halting if it cannot.  Both
				# rely on at least one of the peers below having been running since before the
				# snapshot height, which is the same assumption state-sync already makes.
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

# The enclave ALONE, no chain: this phase mints/funds the pioneer key and runs sync-enclave (the
# attested key fetch from a peer enclave) BEFORE the node's first start.  run_enclave_standalone.sh
# is the single-shot form -- the old respawn-loop scripts are gone; `qadenad start` spawns its own
# enclave for normal operation.
$qadenascripts/run_enclave_standalone.sh &

# Wait for the socket to answer.  The old netstat probe here watched TCP port 50051, which nothing
# has bound since the enclave moved to a unix domain socket -- it worked only because netstat -an
# happens to print the SOCKET PATH containing "50051".  Test the socket file directly, the way
# qadena_status.sh does.
IS_UP=0
for i in {90..1}
do
	if [ -S /tmp/qadena_50051.sock ] && qadenad_alias enclave check-enclave > /dev/null 2>&1 ; then
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
# ON A TEST NETWORK THE INSTRUCTION SHOULD BE A COMMAND.  The email-and-wait text below describes
# a public testnet where someone else holds the treasury; on a private one -- which is every
# development and CI network -- the person running this script can fund it themselves in one line.
# These lines existed here commented out, which helped nobody: the reader still had to reconstruct
# the flags.
if [[ "$TEST_NET" == "true" ]] ; then
	echo "Run ONE of these on a validator (it holds the treasury key):"
	echo ""
	echo "  full node:"
	echo "    ~/qadena/bin/qadenad --home ~/qadena tx bank send treasury $PIONEERADDRESS ${FULL}qdn --yes --gas-prices $minimum_gas_prices --gas auto --gas-adjustment $gas_adjustment"
	echo ""
	echo "  validator node:"
	echo "    ~/qadena/bin/qadenad --home ~/qadena tx bank send treasury $PIONEERADDRESS ${VALIDATOR}qdn --yes --gas-prices $minimum_gas_prices --gas auto --gas-adjustment $gas_adjustment"
	echo ""
else
echo "(TESTNET) Please send an email to qadenatestnet@c3qtech.com with the subject 'Qadena Testnet Full Node'"
echo "(TESTNET) and include the Pioneer name, the Pioneer address ($PIONEERADDRESS), the Pioneer public IP address of the node."
echo "(TESTNET) If you're going to run a full-node, request for ${FULL}qdn to be sent to $PIONEERADDRESS."
echo "(TESTNET) If you're going to run a validator node, request for ${VALIDATOR}qdn to be sent to $PIONEERADDRESS."
echo ""
echo "(PRODUCTION) Full Node:  Please purchase and send at least ${FULL}qdn to $PIONEERADDRESS"
echo "(PRODUCTION) Validator Node:  Please purchase and send at least ${VALIDATOR}qdn to $PIONEERADDRESS"
fi
# STOP HERE RATHER THAN WAIT, if asked.  The key exists and is on record from this point on, so
# there is nothing to lose by exiting: re-running and answering [c] resumes from exactly here and
# KEEPS this key.  Without this, the only way past this point is to have the coins land inside the
# 120x3s window below -- which cannot serve the process described immediately above, where the
# testnet instruction is to email someone and wait.  It also makes the step scriptable: a caller can
# mint the key, fund it, and come back, instead of racing a poll from a second shell.
if [[ "$STOP_FOR_FUNDING" == "true" ]] ; then
	echo ""
	echo "add_full_node.sh: stopping for funding, as requested."
	echo "  pioneer:  $PIONEER"
	echo "  address:  $PIONEERADDRESS"
	echo "  needs:    ${FULL}qdn (full node) or ${VALIDATOR}qdn (validator)"
	echo ""
	echo "The key is minted and kept.  When the funds have arrived, run the SAME command without"
	echo "--stop-for-funding and answer [c] to continue -- answering [s] would erase this key and"
	echo "mint a new one, stranding whatever was sent to the address above."

	# STOP THE ENCLAVE WE STARTED, or the resume run fights it for the socket.
	#
	# This path used to `exit 0` with the enclave still running -- and since we were started in the
	# background by a driver that then exits, it is left ORPHANED to init, still holding
	# /tmp/qadena_50051.sock.  The resume run starts its OWN enclave, and the enclave removes a
	# "stale" socket before binding, so the second one takes the path out from under the first.
	#
	# The result is a race whose symptom names neither cause: sync-enclave's readiness probe reaches
	# the ORPHAN (fully loaded, answers in milliseconds), and then the real call dies with
	#     rpc error: code = Unavailable desc = error reading from server: EOF
	# because the socket it was using has been replaced underneath it.  Observed repeatedly on a
	# real SGX joiner, where the second enclave takes tens of seconds to load and the window is
	# wide; on a debug box the two starts are close enough together that it usually goes unnoticed.
	#
	# Whoever resumes will start a fresh enclave anyway, so nothing is lost by stopping this one.
	# STOP THE ENCLAVE WE STARTED, and CHECK THAT IT STOPPED.
	#
	# This path used to `exit 0` with the enclave still running.  Started in the background by a
	# driver that then exits, it is left ORPHANED to init, still holding /tmp/qadena_50051.sock --
	# and the resume run starts its OWN enclave, which UNLINKS the "stale" socket before binding.
	# The two then overlap: a client's readiness probe reaches the OLD enclave (loaded, answers in
	# milliseconds) and its next call dies with
	#     rpc error: code = Unavailable desc = error reading from server: EOF
	# because the socket underneath it has been replaced.  Wide open on real SGX, where the second
	# enclave takes tens of seconds to load; usually invisible on a debug box.
	#
	# The status is CHECKED rather than discarded: stop_qadena.sh now waits for the enclave to
	# actually exit and escalates to SIGKILL, so a non-zero return means something is genuinely
	# still holding that socket -- which the resume run must not walk into.
	echo "add_full_node.sh: stopping the enclave this run started (the resume will start its own)"
	if $qadenascripts/stop_qadena.sh --enclave ; then
		echo "add_full_node.sh: the enclave is stopped; safe to resume"
	else
		echo "add_full_node.sh: WARNING: the enclave did not stop cleanly."
		echo "  Resuming now would start a second enclave and they would fight over"
		echo "  /tmp/qadena_50051.sock.  Check with:  pgrep -af qadenad_enclave"
	fi
	exit 0
fi

REPLY=""
while [[ $REPLY != "y" && $REPLY != "n" ]]; do
	read REPLY\?"Are you done sending funds to $PIONEERADDRESS ? (y/n) " || { echo ""; echo "add_full_node.sh: stdin closed while waiting for an answer -- refusing to loop."; exit 1; }
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
			echo "Failed to synchronize my enclave with the Pioneer/Enclave on $GENESIS_PIONEER_FIRST_IP_ADDRESS"
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
	read REPLY\?"Do you want to start the new qadena 'full-node' now? (y/n) " || { echo ""; echo "add_full_node.sh: stdin closed while waiting for an answer -- refusing to loop."; exit 1; }
	if [[ $REPLY == "y" ]] ; then
		$qadenascripts/start_qadena.sh
	elif [[ $REPLY == "n" ]] ; then
		echo "Ok, will not start it now.  You can do so later by typing in:"
		echo "  $qadenascripts/start_qadena.sh"
	else
		echo "Invalid option $REPLY.  Please try again."
	fi
done
