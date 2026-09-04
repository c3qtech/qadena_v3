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
mainnet_source=""
mainnet_vault=""
pioneer_mnemonic=""
vault_passphrase=""
build_sgx_flag=""
no_sgx_flag=""
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
    # BUILD A MAINNET-SHAPED CHAIN FROM THIS IGNITE CONFIG, instead of the devnet's
    # config/config.yml.  Two things change, and they are the same decision:
    #
    #   1. the config is read from HERE.  A token-launch genesis rendered by
    #      foundation_scripts/fill_launch_config.py --apply would otherwise have to overwrite config/config.yml to be
    #      built at all, since the copy below reads only that one path -- and that file is the
    #      devnet's own tracked config.
    #
    #   2. the setPubKAndPubKID substitutions below are SKIPPED.  That script resolves
    #      "<name>PubKID" from the local keyring, and it also splices in "<name>PrivKHex" --
    #      a private key, exported unarmored.  That is a devnet convenience for minting
    #      throwaway identities in one command.  A real launch collects the pioneer's ADDRESS
    #      and PUBKEY from whoever holds the key, in their own custody, and carries them as
    #      literals; the build host never sees the secret and has no such keyring entry to
    #      resolve.  So the correct mainnet behaviour is not "substitute" -- it is "there is
    #      nothing left to substitute", which is then asserted rather than assumed.
    --mainnet-source)
      if [[ -n "$2" && "$2" != --* ]]; then
        mainnet_source="$2"
        # VALIDATE HERE, NOT WHERE IT IS USED.  The copy happens at line ~170, which is AFTER
        # `rm -rf $QADENAHOME` -- so a typo'd path would wipe the node's home and its keyring
        # and only then report the mistake.  Fail before anything is destroyed.
        if [[ ! -f "$mainnet_source" ]]; then
          echo "Error: --mainnet-source $mainnet_source does not exist"
          exit 1
        fi
        shift 2
      else
        echo "Error: --mainnet-source requires a path"
        exit 1
      fi
      ;;
    # THE ONE KEY A BUILD HOST NEEDS.  Under --mainnet-source the accounts carry literal
    # ADDRESSES, not mnemonics, so `ignite chain init` creates funded accounts with no signing
    # key -- and the genesis validator still has to sign a gentx.  The key is restored from a
    # vault AFTER the wipe below (which takes $QADENAHOME/keyring-test with it) and BEFORE the
    # init, which is the only window where it survives to be used.
    #
    # Restored with --strip-prefix dev-, because ignite looks the key up by the ACCOUNT name in
    # config.yml (qfi-pioneer1) while the vault stores it prefixed to keep throwaway keys
    # obviously throwaway.  Only the pioneer vault belongs here: the bucket multisigs are
    # genesis addresses and no key of theirs is ever needed to build a chain.
    # THE GENESIS VALIDATOR'S KEY, for --mainnet-source only.
    #
    # `ignite chain init` wipes the chain home and THEN needs a key to sign the gentx, so the
    # only way one can be there is for ignite to create it during "add accounts" -- and it only
    # does that from a `mnemonic:`.  An account given neither address nor mnemonic gets a freshly
    # MINTED key whose mnemonic ignite prints once and nothing captures: the chain comes up with
    # a validator nobody can ever sign for again.  So the operator supplies it.
    #
    # It is injected into the WORKING config.yml, never into the source given to
    # --mainnet-source.  That file stays free of key material.
    #
    # The devnet path is untouched: config/config.yml carries its own mnemonics already.
    --pioneer-mnemonic)
      if [[ -n "$2" && "$2" != --* ]]; then
        pioneer_mnemonic="$2"
        shift 2
      else
        echo "Error: --pioneer-mnemonic requires the mnemonic in quotes"
        exit 1
      fi
      ;;
    --mainnet-vault)
      if [[ -n "$2" && "$2" != --* ]]; then
        mainnet_vault="$2"
        if [[ ! -f "$mainnet_vault" ]]; then
          echo "Error: --mainnet-vault $mainnet_vault does not exist"
          exit 1
        fi
        shift 2
      else
        echo "Error: --mainnet-vault requires a path"
        exit 1
      fi
      ;;
    --vault-passphrase)
      if [[ -n "$2" && "$2" != --* ]]; then
        vault_passphrase="$2"
        if [[ ! -f "$vault_passphrase" ]]; then
          echo "Error: --vault-passphrase $vault_passphrase does not exist"
          exit 1
        fi
        shift 2
      else
        echo "Error: --vault-passphrase requires a path"
        exit 1
      fi
      ;;
    --build-sgx|--build-reproducible)
      build_sgx_flag="--build-sgx"
      shift
      ;;
    # FORWARDED, because build.sh's default is "ego installed means SGX" and there was previously no
    # way to opt out from here.  init.sh rejected --no-sgx outright, so on an Intel box with ego the
    # only ways to get a debug build were to call build.sh directly (losing the genesis init and the
    # install) or to uninstall ego -- which setup_qadena_build.sh silently puts back, on x86,
    # unconditionally.  See TESTING-BACKLOG.md item 90.
    --no-sgx)
      no_sgx_flag="--no-sgx"
      shift
      ;;
    --skip-build)
      skip_build=1
      shift
      ;;
    --help)
      echo "Usage: init.sh [--advertise-ip-address <ip>] [--build-sgx | --no-sgx] [--skip-build]"
      echo "               [--mainnet-source <path-to-yml>]"
      echo "  --mainnet-source  build a MAINNET-shaped chain from THIS ignite config instead"
      echo "            of the devnet's config/config.yml -- e.g. a genesis rendered by"
      echo "            foundation_scripts/fill_launch_config.py --apply.  Also SKIPS the setPubKAndPubKID key"
      echo "            splicing, which is devnet-only (it exports a private key), and instead"
      echo "            asserts the genesis carries no unresolved placeholder."
      echo "  --pioneer-mnemonic <words>"
      echo "            the genesis validator's mnemonic, for --mainnet-source.  Prompted for if"
      echo "            omitted.  Injected into the working config.yml only, never the source."
      echo "  --mainnet-vault / --vault-passphrase"
      echo "            restore the pioneer signing key from a key vault after the home is"
      echo "            wiped and before the chain init, so the genesis validator can sign its"
      echo "            gentx.  Only meaningful with --mainnet-source."
      echo "  --no-sgx  force a DEBUG enclave even where ego is installed.  Without it, build.sh"
      echo "            builds SGX artifacts on any machine that has ego."
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

# THE PIONEER ID IS A CONFIG FACT, NOT A CONSTANT.  The devnet's genesis identity is
# `pioneer1`; a mainnet-shaped chain names its own (qfi-pioneer1).  It has to match the
# account/validator name in the config being built, because setPioneerID.sh writes it into
# node_params.json and the enclave later hands it to InitEnclave -- a mismatch produces a node
# whose sealed identity is not the one genesis registered.
PIONEER1=pioneer1
if [[ -n "$mainnet_source" ]]; then
    mv_name=$(awk '/^validators:/{v=1;next} v&&/^[a-z]/{exit} v&&/^[[:space:]]*- name:/{print $3;exit}' "$mainnet_source")
    if [[ -z "$mv_name" ]]; then
        echo "   INIT FAILED: could not read validators[0].name from $mainnet_source"
        exit 1
    fi
    PIONEER1="$mv_name"
    echo "Pioneer ID from $mainnet_source: $PIONEER1"
fi

# ASKED BEFORE ANYTHING IS DESTROYED, for the same reason the IP is: a prompt discovered after
# `rm -rf $QADENAHOME` leaves the operator with a wiped node and a question.
if [[ -n "$mainnet_source" ]]; then
    # Only when the config actually needs one: an account carrying a literal address (the real
    # mainnet shape, where the holder keeps their key) needs no mnemonic here at all.
    #
    # SCOPED TO `accounts:`, AND THAT SCOPE IS THE WHOLE CORRECTNESS OF THIS CHECK.  The pioneer
    # name appears TWICE in a launch config -- once under `validators:` and once under
    # `accounts:` -- and the validators entry contains, ~40 lines in:
    #     address: "0.0.0.0:8545"     # the EVM JSON-RPC LISTEN address
    # An unscoped scan matches the validators block first, sees that `address:`, concludes the
    # account already has a key and SKIPS THE PROMPT.  It did exactly that for every launch config
    # in the tree, which silently disabled the one protection this block exists to provide: ignite
    # then mints a key, prints its mnemonic once to nothing, and the genesis validator is
    # unrecoverable.  Only --pioneer-mnemonic(-file) being passed on every fleet run hid it.
    if ! awk -v n="$PIONEER1" '
            /^accounts:/ {a=1; next}
            a && /^[a-z]/ {exit}                      # left accounts:, stop
            a && $0 ~ "^[[:space:]]*- name: " n "$" {f=1; next}
            f && /^[[:space:]]*(address|mnemonic):/ {print "has"; exit}
            f && /^[[:space:]]*- name:/ {exit}        # next account, ours had neither
        ' "$mainnet_source" | grep -q has ; then
        if [[ -z "$pioneer_mnemonic" ]]; then
            echo ""
            echo "The genesis validator '$PIONEER1' has no address and no mnemonic in"
            echo "$mainnet_source, so ignite would MINT a key and print its mnemonic once."
            echo "Nothing captures that, and the validator would be unrecoverable."
            echo "You can avoid this prompt by calling init.sh --pioneer-mnemonic \"<words>\""
            echo ""
            read -s "pioneer_mnemonic?*** Paste the mnemonic for $PIONEER1 (hidden): "
            echo ""
        fi
        wc=$(echo "$pioneer_mnemonic" | wc -w | tr -d ' ')
        if [[ $wc -lt 12 ]]; then
            echo "   INIT FAILED: that is $wc word(s); a BIP39 mnemonic is 12 or 24."
            exit 1
        fi
        echo "Got a $wc-word mnemonic for $PIONEER1"
    fi
fi

# PLACEHOLDER ALLOCATIONS: WHO IS ALLOWED TO HAVE THEM.
#
# tokenomics/allocations.csv is tracked, human-owned, and its genesis_address column holds
# <NN_MSIG_ADDR> until the real bucket multisigs are generated in custody -- which for a mainnet
# launch happens ONCE, late.  So placeholders there are the normal state of the repo, and a
# launch-SHAPED test build (fleet bringup, 1st_node_bringup --mainnet-source) renders its instance
# from dev addresses and is right to proceed with them.  A REAL launch is not: assertion 13 exists
# to stop a permanent genesis whose custody record is still a placeholder.
#
# Default strict, therefore, and let the test paths opt out by name.  The variable says exactly
# what it permits, so it cannot be set by someone who thinks it means something else.
_ph_flag=()
if [[ -n "${QADENA_ALLOW_PLACEHOLDER_ALLOCATIONS:-}" ]]; then
    _ph_flag=(--allow-placeholders)
fi

# THE INSTANCE IS CHECKED BEFORE ANYTHING IS DESTROYED, for the same reason the mnemonic is asked
# for here: an amount that disagrees with allocations.csv is free to fix now and expensive to fix
# once a genesis exists.  verify_launch_config.py compares every account's `coins:` against the
# CSV, which is the human-owned authority (HARD RULE 1), and reports anything still unset.
#
# --strict, because a launch build has no business proceeding with a placeholder or a mismatch.
# Set QADENA_SKIP_CONFIG_VERIFY=1 to bypass it -- deliberately awkward, and it says so.
if [[ -n "$mainnet_source" ]]; then
    # THE CSV FIRST, BEFORE THE CONFIG THAT IS COMPARED AGAINST IT.  verify_launch_config asks
    # "does the instance agree with allocations.csv"; that question is meaningless if the CSV
    # itself does not add up.  Assertions 1-3 and 13 need no chain and no genesis, so they cost
    # about a second and they run while $QADENAHOME is still intact.
    #
    # WITHOUT THIS THE ONLY CSV CHECK IS AT THE POST-INIT GATE BELOW -- 250 lines and one
    # `rm -rf $QADENAHOME` later.  A hand-edit slip in the human-owned file would take the node
    # home, the keyring and the enclave state with it before saying so.
    _vg_pre="$qadenabuild/foundation_scripts/verify_genesis.py"
    if [[ ! -f "$_vg_pre" ]]; then
        echo "   INIT FAILED: $_vg_pre is missing -- cannot verify allocations.csv"
        exit 1
    elif [[ -n "${QADENA_SKIP_CONFIG_VERIFY:-}" ]]; then
        : # the same bypass covers both pre-wipe checks; it announces itself below
    else
        echo "Verifying tokenomics/allocations.csv..."
        if ! python3 "$_vg_pre" --csv-only "${_ph_flag[@]}"; then
            echo ""
            echo "   INIT FAILED: allocations.csv does not add up, or still holds placeholders."
            echo "   Nothing has been destroyed yet.  Fix the CSV and re-run."
            echo "   A launch-SHAPED TEST build wants QADENA_ALLOW_PLACEHOLDER_ALLOCATIONS=1."
            exit 1
        fi
        echo "   OK: allocations.csv is internally consistent."
    fi

    _vlc="$qadenabuild/foundation_scripts/verify_launch_config.py"
    if [[ ! -f "$_vlc" ]]; then
        echo "   INIT FAILED: $_vlc is missing -- cannot verify the instance against allocations.csv"
        exit 1
    elif [[ -n "${QADENA_SKIP_CONFIG_VERIFY:-}" ]]; then
        echo "SKIPPING the instance check (QADENA_SKIP_CONFIG_VERIFY set).  Amounts are UNVERIFIED."
    else
        echo "Verifying $mainnet_source against tokenomics/allocations.csv..."
        if ! python3 "$_vlc" --config "$mainnet_source" --strict; then
            echo ""
            echo "   INIT FAILED: the instance disagrees with allocations.csv, or something is unset."
            echo "   Nothing has been destroyed yet.  Fix the instance (or the CSV) and re-run."
            echo "   To proceed anyway:  QADENA_SKIP_CONFIG_VERIFY=1 $0 ..."
            exit 1
        fi
        echo "   OK: the instance matches allocations.csv."
    fi
fi

# CHECKED BEFORE ANYTHING IS DESTROYED.  `ignite chain init` below REGENERATES THE PROTOS as a side
# effect, using the machine's local plugins; a mismatched one rewrites nine .pb.go files and the
# failure surfaces minutes later at packaging, naming neither the plugin nor the version.
#
# This used to sit AFTER the `rm -rf $QADENAHOME` below, which was pure accident -- the plugin
# versions do not depend on anything the removal does.  The cost was real: on a machine provisioned
# before the current pins, init.sh deleted the entire node home -- chain data, keyring, enclave
# state -- and THEN reported that it could not build.  None of that is recoverable, and the check
# takes under a second, so it goes first.  See TESTING-BACKLOG.md item 85.
"$qadenabuildscripts/check_codegen_plugins.sh" || exit 1

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

# RESTORE THE PIONEER KEY -- the wipe above just deleted $QADENAHOME/keyring-test, and
# `ignite chain init` below needs a signing key for the genesis validator.
if [[ -n "$mainnet_vault" ]]; then
    if [[ -z "$vault_passphrase" ]]; then
        echo "   INIT FAILED: --mainnet-vault needs --vault-passphrase"
        exit 1
    fi
    echo "Restoring the pioneer key from $mainnet_vault"
    if ! python3 "$qadenabuild/testscripts/dev_key_vault.py" import \
            --in "$mainnet_vault" --passphrase-file "$vault_passphrase" --strip-prefix dev- ; then
        echo "   INIT FAILED: could not restore the key vault -- the gentx would fail with the"
        echo "   key sitting in a file right next to it."
        exit 1
    fi
fi

# config.yml is now just a verbatim copy of config/config.yml.  Nothing is substituted into it any
# more -- pioneer1 and treasury are both fixed up in genesis.json after the init -- so there is no
# reason to detect or preserve an existing copy.
#
# Copying unconditionally also removes a real trap.  The old code kept a previously generated
# config.yml if it looked complete, so an edit to config/config.yml silently had no effect until you
# remembered to delete the generated one first.
# STILL AN UNCONDITIONAL COPY.  Only the SOURCE is selectable now -- the old trap it warns
# about above (keeping a stale generated config.yml because it "looked complete") stays
# closed either way.
config_src="${mainnet_source:-$qadenabuild/config/config.yml}"
if [[ ! -f "$config_src" ]]; then
    # --mainnet-source is validated at parse time; this only catches a missing default.
    echo "init.sh: $config_src does not exist"
    exit 1
fi
if [[ -n "$mainnet_source" ]]; then
    echo "Copying $config_src -> config.yml  (MAINNET source, NOT config/config.yml)"
else
    echo "Copying config/config.yml -> config.yml"
fi
cp "$config_src" $qadenabuild/config.yml

# INTO THE COPY, NEVER THE SOURCE.  $config_src keeps no key material; the working config.yml
# is regenerated by every init and is gitignored.
if [[ -n "$pioneer_mnemonic" ]]; then
    echo "Injecting the $PIONEER1 mnemonic into the working config.yml"
    PIONEER1="$PIONEER1" MNEMONIC="$pioneer_mnemonic" python3 - "$qadenabuild/config.yml" <<'PYINJECT'
import io, os, sys
p = sys.argv[1]; name = os.environ["PIONEER1"]; mn = os.environ["MNEMONIC"].strip()
lines = io.open(p, encoding="utf-8").read().splitlines()
out, done = [], False
for i, l in enumerate(lines):
    out.append(l)
    if not done and l.strip() == f"- name: {name}":
        # accounts entry only: the validators entry is followed by `bonded:`, not `coins:`
        nxt = next((x for x in lines[i+1:] if x.strip() and not x.strip().startswith("#")), "")
        if "coins:" in nxt:
            indent = " " * (len(l) - len(l.lstrip()) + 2)
            out.append(f'{indent}mnemonic: "{mn}"')
            done = True
io.open(p, "w", encoding="utf-8").write("\n".join(out) + "\n")
sys.exit(0 if done else 1)
PYINJECT
    if [[ $? != 0 ]]; then
        echo "   INIT FAILED: could not find the $PIONEER1 accounts entry to inject into"
        exit 1
    fi
fi

echo "Initializing chain"
if ignite chain init --home $QADENAHOME ; then
    echo "Built chain, creating the cosmovisor layout"

    # A NODE IS BORN MANAGED.  There is no flat layout and no conversion step: the home is
    # created in its final shape here, so nothing downstream has to ask whether this node "is"
    # a cosmovisor node.  genesis/ is the generation that executes blocks from height 1, which
    # is what lets a replaying joiner reproduce this chain's history later.
    mkdir -p "$QADENAHOME/cosmovisor/genesis/bin" || { echo "cannot create the cosmovisor tree"; exit 1; }
    ( cd "$QADENAHOME/cosmovisor" && ln -sfn genesis current ) || { echo "cannot create current"; exit 1; }

    # The supervisor itself, which can never live inside the tree it swaps.  Built here rather
    # than assumed: init.sh already builds from source, and a node with a tree but no cosmovisor
    # cannot start at all.
    "$qadenabuildscripts/build_cosmovisor.sh" || { echo "cannot build cosmovisor"; exit 1; }

    # The at-height hook, as a shim execing the scripts/ copy (install.sh --scripts keeps that
    # one current; cosmovisor requires the hook at this fixed path).
    cat > "$QADENAHOME/cosmovisor/cosmovisor_preupgrade.sh" <<'SHIM'
#!/bin/zsh
exec "$(dirname "$0")/../scripts/cosmovisor_preupgrade.sh" "$@"
SHIM
    chmod +x "$QADENAHOME/cosmovisor/cosmovisor_preupgrade.sh"

    # Seed the generation with ignite's binary so the genesis-patching steps below have a working
    # qadenad.  install.sh replaces it with the properly linked build (this one carries no version
    # ldflags, so it would register no version-named upgrade handler).
    cp `which qadena_v3d` "$QADENAHOME/cosmovisor/genesis/bin/qadenad"
    cosmovisor_relink || { echo "cannot link $qadenabin into the generation"; exit 1; }
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
# SUBSTITUTE ONLY IF THERE IS A PLACEHOLDER.  Keyed on the FILE, not on --mainnet-source.
# Both shapes are legitimate and the genesis says which one it is:
#
#   "<name>PubKID" survived the init as a literal   -> the key was minted locally (ignite
#       generates one for an account given neither address nor mnemonic), so resolve it from
#       the keyring.  This is how the devnet has always worked.
#   a real bech32 address is already there          -> the holder supplied their address and
#       pubkey as literals and no key of theirs exists here.  Nothing to do; substituting
#       would need a private key this host must never have.
#
# Tying the skip to the flag was wrong: it disabled the mechanism for a mainnet-SHAPED test
# chain whose key is minted locally, and the gentx then failed on a keyring that had no key.
if ! grep -q "${PIONEER1}PubKID" $genesisfile 2>/dev/null; then
    echo "no ${PIONEER1}PubKID placeholder in the genesis -- address already literal, nothing to substitute"
elif $qadenabuildscripts/setPubKAndPubKID.sh $PIONEER1 $genesisfile ; then
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

if ! grep -q "treasuryPubKID" $genesisfile 2>/dev/null; then
    echo "no treasuryPubKID placeholder in the genesis -- nothing to substitute"
elif $qadenabuildscripts/setPubKAndPubKID.sh treasury $genesisfile ; then
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
    
# --mainnet-source: ASSERT THE SUBSTITUTIONS WERE NOT NEEDED.
#
# Skipping setPubKAndPubKID above is only correct if the config already carries real values.  If
# it does not, the genesis ships a literal string like "pioneer1PubKID" in an address field --
# a chain whose pioneer identity is unresolvable, built without a single error.  So the skip is
# paired with a check: after a mainnet build, NO devnet placeholder may survive.
#
# The pattern is deliberately case-sensitive.  The real genesis field is "pubKID" (lowercase p);
# only the placeholder VALUES carry a capital "...PubKID", so the field names never match.
# ALWAYS, not just under --mainnet-source: an unresolved placeholder ships a literal string
# like "qfi-pioneer1PubKID" in an address field, and the chain comes up with an identity
# nobody can act as.  Cheap to check, and it fails the build rather than the network.
if true; then
    echo "Checking the genesis carries no unresolved key placeholder..."
    leftover=$(grep -oE '[A-Za-z0-9_]*(PubKID|PubK_pubk|PrivKHex)' $genesisfile \
               | grep -v '^setPubKAndPubKID$' | sort -u)
    if [[ -n "$leftover" ]]; then
        echo "   INIT FAILED: these key placeholders are unresolved in $genesisfile:"
        echo "$leftover" | sed 's/^/     /'
        echo ""
        echo "   A mainnet config must carry the real address and pubkey as literals -- they are"
        echo "   public values, collected from whoever holds the key.  They are NOT resolved from"
        echo "   this host's keyring, which is why the substitution was skipped."
        exit 1
    fi
    echo "   OK: no placeholders remain."
fi

# AND THE ARTIFACT ITSELF.  The check above proves no placeholder survived; this proves the
# genesis says what allocations.csv says -- balances, supply, the whitelist, the incentive-pool
# entry.  ignite is between the instance and the genesis, so verifying the input does not verify
# the output.
#
# --pre-gentx: at this point the gentx has been signed but the validator is not collected yet, so
# the assertions that need a collected validator are correctly skipped.
if [[ -n "$mainnet_source" ]]; then
    _vg="$qadenabuild/foundation_scripts/verify_genesis.py"
    if [[ ! -f "$_vg" ]]; then
        echo "   INIT FAILED: $_vg is missing -- cannot verify the genesis against allocations.csv"
        exit 1
    elif [[ -n "${QADENA_SKIP_GENESIS_VERIFY:-}" ]]; then
        echo "SKIPPING the genesis check (QADENA_SKIP_GENESIS_VERIFY set).  Amounts are UNVERIFIED."
    else
        echo "Verifying $genesisfile against tokenomics/allocations.csv..."
        if ! python3 "$_vg" --genesis "$genesisfile" --pre-gentx "${_ph_flag[@]}"; then
            echo ""
            echo "   INIT FAILED: the genesis does not match allocations.csv."
            echo "   The chain has NOT been started.  Re-run init after fixing it."
            echo "   To proceed anyway:  QADENA_SKIP_GENESIS_VERIFY=1 $0 ..."
            exit 1
        fi
        echo "   OK: the genesis matches allocations.csv."
    fi
fi

echo "Copying node_params.json"
cp config/node_params.json $qadenaconfig
#echo "Copying enclave_params.json"
#cp config/enclave_params.json $qadenaconfig
echo "Fixing up node_params.json..."
$qadenascripts/setPioneerID.sh $PIONEER1 $nodeparamsfile
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
$qadenabuildscripts/build.sh --title "FINAL BUILD" $build_sgx_flag $no_sgx_flag
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

    