#!/bin/zsh
#
# epdc_cli.sh -- deploy and wire the e-PDC register contract on a local Qadena node,
# mirroring enf-smart-contracts/enf_cli.sh.
#
# Quick start (local Qadena node running, devnet providers set up by testscripts/setup.sh):
#   ./epdc_cli.sh setup             # deployer wallet, upload, instantiate, attestors, register with API
#   ./epdc_cli.sh attestor-keys     # the EPDC_ATTESTOR_KEYS line for the API env
#   ./epdc_cli.sh get-attestors
#   ./epdc_cli.sh get-events
#
# Usually driven by testscripts/setup_epdc.sh (the chain half) and, once the app-server is up,
# `make setup-backend-if-needed` in the follow-the-money epdc stack (the registration half).
#
# WHO SIGNS WHAT:
#   EPDC            the deployer.  Instantiates the contract, so it is the register's OPERATOR --
#                   the only address RegisterAttestor / DeactivateAttestor accept.
#   EPDC (+ its credential and ephemeral wallets)
#                   the orchestrator: handed to the app-server by setup-backend, which signs every
#                   AppendEvent with them (one queue slot per wallet, so writes don't serialise
#                   on a single account sequence).
#   epdc-attestor-* three demo attestors (OPERATOR / DRAWEE / DISINTERESTED).  They never send a
#                   transaction; they countersign event digests, and the app-server holds their
#                   private keys only because this is a demo (EPDC_ATTESTOR_KEYS).  In production
#                   each institution signs on its own node and its key never leaves it.

SCRIPT_DIR=$(cd "$(dirname "$0")/../scripts"; pwd)
source "$SCRIPT_DIR/../scripts/setup_env.sh"

EPDC_SCRIPT_DIR=$(cd $(dirname $0); pwd)
STATE_FILE="./epdc_state.json"
WASM="$EPDC_SCRIPT_DIR/artifacts/epdc_register.wasm"

QADENA_NODE="tcp://localhost:26657"
FROM="EPDC"                          # the deployer / orchestrator user; override with -k
CONTRACT_OVERRIDE=""

# The devnet's generic providers, created by testscripts/setup_prerequisites.sh.  ENF uses its own
# (enfidentitysrvprv, enf-create-wallet-sponsor) because setup_enf.sh onboards them through the
# veritas steps; epdc does not onboard providers of its own (yet), so it uses the shared ones.
EPDC_IDENTITY_PROVIDER="${EPDC_IDENTITY_PROVIDER:-testidentitysrvprv}"
EPDC_CREATE_WALLET_SPONSOR="${EPDC_CREATE_WALLET_SPONSOR:-create-wallet-sponsor}"
# create_user.sh pays the identity provider's credential transactions from this foundation account
# (foundation-sponsored mode).  Its default, foundation-veritas-appsvr, exists only after a VERITAS
# deployment; the devnet's is foundation-appsvr (testscripts/setup_foundation_accounts.sh).
: ${VERITAS_FOUNDATION_APPSVR:=foundation-appsvr}
export VERITAS_FOUNDATION_APPSVR

# For `setup-backend` (registers the contract + signing keys with the running API).
EPDC_API_BASE="${EPDC_API_BASE:-http://localhost:3025}"  # the epdc stack's api port (override with -a)
APIVERSION="${APIVERSION:-v1}"
EPDC_EPH_COUNT="${EPDC_EPH_COUNT:-3}"   # ephemeral signing wallets for the orchestrator queue

# THE DEMO ATTESTORS' MNEMONICS ARE HARDCODED AND PUBLIC, like setup_enf.sh's: the same keys on
# every rebuild, so the EPDC_ATTESTOR_KEYS line in the API env stays valid across chain resets.
# That is only acceptable because these keys witness nothing real.  Never use them outside a devnet.
typeset -A ATTESTOR_MNEMONIC
ATTESTOR_MNEMONIC[OPERATOR]="habit lazy curve swap pave judge town eagle assault sudden arch verb arrow toss bomb video taste census cave blue friend grunt adapt decline"
ATTESTOR_MNEMONIC[DRAWEE]="replace alcohol ticket ride ugly test slab smoke multiply ring olympic column uphold swallow gesture broccoli pelican opera danger artefact grit pig estate kiss"
ATTESTOR_MNEMONIC[DISINTERESTED]="jealous member link another tennis wool smooth lonely vocal pepper child cream family case crop tuition wave mansion elite photo sand hunt about staff"
typeset -A ATTESTOR_NAME
ATTESTOR_NAME[OPERATOR]="Sagay Multi-Purpose Cooperative (operator)"
ATTESTOR_NAME[DRAWEE]="Drawee Bank (demo)"
ATTESTOR_NAME[DISINTERESTED]="Independent Witness (demo)"
ATTESTOR_CLASSES=(OPERATOR DRAWEE DISINTERESTED)
attestor_key() { echo "epdc-attestor-${(L)1}"; }

save_state() {
  [[ -f "$EPDC_SCRIPT_DIR/$STATE_FILE" ]] || echo '{}' > "$EPDC_SCRIPT_DIR/$STATE_FILE"
  jq --arg k "$1" --arg v "$2" '.[$k]=$v' "$EPDC_SCRIPT_DIR/$STATE_FILE" > tmp.$$.json && mv tmp.$$.json "$EPDC_SCRIPT_DIR/$STATE_FILE"
  echo "Saved $1: $2"
}
load_state() {
  [[ -f "$EPDC_SCRIPT_DIR/$STATE_FILE" ]] && jq -r --arg k "$1" '.[$k] // empty' "$EPDC_SCRIPT_DIR/$STATE_FILE"
}

contract_addr() {
  if [[ -n "$CONTRACT_OVERRIDE" ]]; then echo "$CONTRACT_OVERRIDE"; else load_state "contract_address"; fi
}

tx() { # broadcast a tx as $FROM and wait for it to commit; non-zero exit if it did not
  # `tx` MUST BE qadenad_alias's FIRST ARGUMENT. The alias picks its branch from $1, and only the
  # `tx`/`keys` branches supply --keyring-backend and the passphrase. enf_cli.sh puts --node/--gas
  # first, which lands in the passthrough branch: harmless on a `test` keyring, "too many failed
  # passphrase attempts" on the encrypted `file` keyring a current devnet uses.
  local label=$1; shift
  echo ">> $label"
  local resp=$(qadenad_alias "$@" --node $QADENA_NODE --gas $gas_auto --gas-adjustment $gas_adjustment --gas-prices $minimum_gas_prices --from $FROM -y -o json)
  wait_for_tx "$resp" "$label"
}

q() { # smart-query the contract
  qadenad_alias --node $QADENA_NODE query wasm contract-state smart "$(contract_addr)" "$1" -o json | jq
}

require_args() {
  local usage="$1" need="$2"; shift 2
  if (( $# < need )); then
    echo "Error: missing required argument(s). Usage: $0 $usage"; exit 1
  fi
  local i
  for (( i = 1; i <= need; i++ )); do
    [[ -n "${@[i]}" ]] || { echo "Error: argument $i is empty. Usage: $0 $usage"; exit 1; }
  done
}

setup_epdc() {
  local name="$FROM"
  if [[ -n "$(load_state "epdc_address")" ]] && qadenad_alias keys show "$name" > /dev/null 2>&1; then
    echo "EPDC user '$name' already created ($(load_state epdc_address))"
    return
  fi
  [[ -n "$qadenaproviderscripts" && -x "$qadenaproviderscripts/create_user.sh" ]] || {
    echo "create_user.sh not found (qadenaproviderscripts=$qadenaproviderscripts)"; exit 1; }
  [[ -n "$qadenatestscripts" && -x "$qadenatestscripts/grant_from_treasury.sh" ]] || {
    echo "grant_from_treasury.sh not found (qadenatestscripts=$qadenatestscripts)"; exit 1; }
  qadenad_alias keys show "$EPDC_IDENTITY_PROVIDER" > /dev/null 2>&1 || {
    echo "identity provider '$EPDC_IDENTITY_PROVIDER' is not in the keyring -- run testscripts/setup.sh first"; exit 1; }

  local eph_count="$EPDC_EPH_COUNT"
  if qadenad_alias keys show "$name" > /dev/null 2>&1; then
    echo "$name key already exists -- skipping create_user.sh"
  else
    echo "-------------------------"
    echo "Creating the EPDC deployer/orchestrator user '$name' (credentials issued by $EPDC_IDENTITY_PROVIDER)"
    echo "-------------------------"
    local mnemonic=$(qadenad_alias_raw keys mnemonic 2>/dev/null)
    # a/bf MUST NOT COLLIDE with another credential on this chain: a credential is unique on
    # (CredentialID, CredentialType) and CredentialID derives from these two.  In use elsewhere:
    # cadena 5555/7777, ENF 5561/7783, the devnet test users 1..11/5678.  A collision does not fail
    # loudly -- the wallets succeed and only the credential is rejected (see enf_cli.sh).
    #
    # THE OUTPUT IS INSPECTED, not just the exit status: create_user.sh returns 0 even when one of
    # the transactions it broadcasts is rejected on chain.
    local cu_log
    cu_log=$(mktemp)
    if ! "$qadenaproviderscripts/create_user.sh" \
      "$name" "$mnemonic" "pioneer1" "" \
      "EPDC" "" "Orchestrator" "1990-Jan-01" "PH" "PH" "M" \
      "no-reply+epdc-orchestrator@epdc.ph" "+6320000002" "5567" "7791" \
      "$EPDC_IDENTITY_PROVIDER" "" "" "" "$eph_count" "$EPDC_CREATE_WALLET_SPONSOR" 2>&1 | tee "$cu_log"; then
      rm -f "$cu_log"
      echo "create_user.sh failed for '$name'"; exit 1
    fi
    if grep -qE "failed with [0-9]+:|codespace qadena code|decoding bech32 failed|fee-grant not found|not allowed" "$cu_log"; then
      echo ""
      echo "create_user.sh reported a REJECTED transaction while creating '$name':"
      grep -E "failed with [0-9]+:|codespace qadena code|decoding bech32 failed|fee-grant not found|not allowed" "$cu_log" | head -5
      rm -f "$cu_log"
      exit 1
    fi
    rm -f "$cu_log"
  fi

  # FUNDED BY BANK SEND, like enf_cli.sh's contract half.  The deployer pays for upload/instantiate/
  # register_attestor and the ephemerals pay for AppendEvent themselves.  That is why the epdc env
  # leaves QADENA_FOUNDATION_APPSVR_ADDRESS empty: set, the app-server would name the foundation as
  # fee granter on every AppendEvent, which then needs a grant allowing MsgExecuteContract
  # (veritas_scripts/step_3.sh VERITAS_APPSVR_MSGS) -- the sponsored path, for a later pass.
  echo "-------------------------"
  echo "Funding $name (and its credential + eph wallets) from treasury"
  echo "-------------------------"
  local amount="100000qdn"
  local w
  for w in "$name" "$name-credential" $(for i in $(seq 1 $eph_count); do echo "$name-eph$i"; done); do
    qadenad_alias keys show "$w" > /dev/null 2>&1 || continue
    "$qadenatestscripts/grant_from_treasury.sh" "$(qadenad_alias keys show $w --address)" "$amount"
  done

  local addr=$(qadenad_alias keys show "$name" --address)
  echo "EPDC user address: $addr"
  save_state "epdc_address" "$addr"
}

cmd_upload() {
  [[ -f "$WASM" ]] || { echo "Missing $WASM -- run ./optimizer.sh first"; exit 1; }
  local resp=$(qadenad_alias tx wasm store "$WASM" --node $QADENA_NODE --gas $gas_auto --gas-adjustment $gas_adjustment --gas-prices $minimum_gas_prices --from $FROM -y -o json)

  local hash=$(echo "$resp" | jq -r '.txhash // empty' 2>/dev/null)
  local bcode=$(echo "$resp" | jq -r '.code // empty' 2>/dev/null)
  if [[ -z "$hash" ]]; then
    echo "upload: the store transaction was never broadcast (no txhash)."
    echo "$resp" | head -5
    exit 1
  fi
  if [[ -n "$bcode" && "$bcode" != "0" ]]; then
    echo "upload: rejected at CheckTx with code $bcode: $(echo "$resp" | jq -r '.raw_log // empty')"
    exit 1
  fi
  confirm_tx "$hash" 60 || { echo "upload: $hash was not confirmed on chain"; exit 1; }

  # Read the code_id back from the CONFIRMED transaction, not from the wait response.
  local code_id=$(qadenad_alias --node $QADENA_NODE query tx "$hash" -o json 2>/dev/null \
    | jq -r '.events[]? | select(.type=="store_code") | .attributes[]? | select(.key=="code_id") | .value' 2>/dev/null | tail -1)
  [[ -n "$code_id" ]] || { echo "upload: $hash committed but carried no store_code/code_id event."; exit 1; }
  save_state "code_id" "$code_id"
}

cmd_instantiate() {
  local code_id=$(load_state "code_id")
  [[ -n "$code_id" ]] || { echo "No code_id -- run upload first"; exit 1; }
  local admin=$(qadenad_alias keys show $FROM --address)
  # No --amount: a contract address is not a credentialed wallet, so an AML-scanned deposit would be
  # refused and take the instantiate with it (enf_cli.sh).  The register never holds funds anyway.
  # InstantiateMsg is {}; the SENDER becomes the operator.
  local resp=$(qadenad_alias tx wasm instantiate "$code_id" '{}' --node $QADENA_NODE --gas $gas_auto --gas-adjustment $gas_adjustment --gas-prices $minimum_gas_prices \
    --admin="$admin" --from $FROM --label "epdc-register-v1" -y -o json)
  wait_for_tx "$resp" "instantiate" || exit 1

  local addr=$(qadenad_alias --node $QADENA_NODE query wasm list-contract-by-code "$code_id" -o json 2>/dev/null | jq -r '.contracts[-1] // empty' 2>/dev/null)
  [[ -n "$addr" && "$addr" != "null" ]] || { echo "instantiate: committed but no contract is listed under code_id $code_id"; exit 1; }
  save_state "contract_address" "$addr"
  echo "Contract address: $addr"
  echo ">> Set EPDC_REGISTER_CONTRACT_ADDRESS=$addr in the API env (setup-backend also registers it)"
}

# ensure_attestor_key <CLASS> -- recover the fixed demo key into the keyring if it is not there.
ensure_attestor_key() {
  local class=$1 key=$(attestor_key $1)
  qadenad_alias keys show "$key" > /dev/null 2>&1 && return
  # `keys add --recover` reads the MNEMONIC first and the passphrase after, so the caller owns the
  # stream and must use _raw -- qadenad_alias would replace stdin with the passphrase.
  { echo "${ATTESTOR_MNEMONIC[$class]}"
    [ -z "${QADENA_KEYRING_PASS:-}" ] || { echo "$QADENA_KEYRING_PASS"; echo "$QADENA_KEYRING_PASS"; }
  } | qadenad_alias_raw keys add "$key" --recover > /dev/null 2>&1 \
    || { echo "could not recover attestor key $key"; exit 1; }
}

attestor_privhex() { # the key's raw secp256k1 scalar, hex -- `export --unsafe` asks y/N, then the passphrase
  { echo y; [ -z "${QADENA_KEYRING_PASS:-}" ] || echo "$QADENA_KEYRING_PASS"; } \
    | qadenad_alias_raw keys export "$(attestor_key $1)" --unarmored-hex --unsafe 2>/dev/null
}

register_attestors() {
  local addr_c="$(contract_addr)"
  [[ -n "$addr_c" ]] || { echo "No contract address in state -- run upload/instantiate first"; exit 1; }
  local roster=$(qadenad_alias --node $QADENA_NODE query wasm contract-state smart "$addr_c" '{"get_attestors":{}}' -o json 2>/dev/null)
  local class key addr pubhex
  for class in $ATTESTOR_CLASSES; do
    ensure_attestor_key $class
    key=$(attestor_key $class)
    addr=$(qadenad_alias keys show "$key" -a)
    if echo "$roster" | jq -e --arg a "$addr" '[.. | objects | select(.addr? == $a)] | length > 0' > /dev/null 2>&1; then
      echo "attestor $class ($addr) already on the roster"
      continue
    fi
    # 33-byte compressed secp256k1 pubkey, hex -- what the contract's secp256k1_verify takes.
    pubhex=$(qadenad_alias keys show "$key" -p | jq -r .key | base64 -d | xxd -p -c 66)
    [[ ${#pubhex} -eq 66 ]] || { echo "unexpected pubkey for $key: $pubhex"; exit 1; }
    tx "register_attestor $class" tx wasm execute "$addr_c" \
      "{\"register_attestor\":{\"addr\":\"$addr\",\"class\":\"$class\",\"name\":\"${ATTESTOR_NAME[$class]}\",\"pubkey_hex\":\"$pubhex\"}}" \
      || { echo "register_attestor $class failed"; exit 1; }
  done
}

# The EPDC_ATTESTOR_KEYS line for the API env: a JSON array of {addr, class, privkey_hex} matching
# the roster (api/services/epdc/attest.go).  Printed, not written: it carries private keys.
attestor_keys() {
  local class json="[]" key addr hex
  for class in $ATTESTOR_CLASSES; do
    ensure_attestor_key $class
    key=$(attestor_key $class)
    addr=$(qadenad_alias keys show "$key" -a)
    hex=$(attestor_privhex $class)
    [[ ${#hex} -eq 64 ]] || { echo "could not export $key (got ${#hex} hex chars)" >&2; exit 1; }
    json=$(echo "$json" | jq -c --arg a "$addr" --arg c "$class" --arg k "$hex" '. + [{addr:$a, class:$c, privkey_hex:$k}]')
  done
  echo "EPDC_ATTESTOR_KEYS='$json'"
}

setup_backend() {
  local addr="$(contract_addr)"
  [[ -n "$addr" ]] || { echo "No contract address in state -- run setup/instantiate first"; exit 1; }
  # Verify the contract is on chain before telling the app-server to use it: a phantom address
  # fails later and elsewhere, as "failed to decrypt private key: EOF" (enf_cli.sh).
  if ! qadenad_alias --node "$QADENA_NODE" query wasm contract "$addr" > /dev/null 2>&1; then
    echo "Contract $addr is not on this chain (node $QADENA_NODE)."
    echo "  epdc_state.json is stale -- most likely the chain was reinstalled."
    echo "  Run:  ./epdc_cli.sh clean  then  testscripts/setup_epdc.sh"
    exit 1
  fi
  [[ -n "$qadenatestscripts" && -x "$qadenatestscripts/extract_ephem_keys.sh" ]] || {
    echo "extract_ephem_keys.sh not found (qadenatestscripts=$qadenatestscripts)"; exit 1; }

  echo "Extracting signing keys for '$FROM' (base + credential + $EPDC_EPH_COUNT ephemerals)..."
  local ephem_keys=$("$qadenatestscripts/extract_ephem_keys.sh" --provider "$FROM#" --count "$EPDC_EPH_COUNT" \
    --include-base-provider --include-base-provider-credential --json 2>/dev/null)
  local epdc_username=$(echo "$ephem_keys" | jq -r ".names")
  local epdc_private_key=$(echo "$ephem_keys" | jq -r ".private_keys")
  [[ -n "$epdc_username" && "$epdc_username" != "null" && -n "$epdc_private_key" && "$epdc_private_key" != "null" ]] || {
    echo "Failed to extract keys for '$FROM' (is it set up? run setup-epdc first)"; exit 1; }

  local body=$(jq -nc --arg c "$addr" --arg u "$epdc_username" --arg k "$epdc_private_key" \
    '{contract_address:$c, epdc_username:$u, epdc_private_key:$k}')
  local url="$EPDC_API_BASE/$APIVERSION/epdc/setup_epdc"
  echo "POST $url  (contract=$addr, signer=$FROM)"
  # THE KEYS ARE ARMORED WITH THE KEYRING PASSPHRASE (extract_ephem_keys.sh), and the app-server
  # decrypts them with its ARMOR_PASS_PHRASE -- so the two must be equal, or this fails with
  # "failed to decrypt private key", which names the wrong culprit.
  local resp=$(curl -sS -X POST "$url" -H "Content-Type: application/json" -d "$body") \
    || { echo "Request to $url failed (is the epdc API running? override with -a <base_url>)"; exit 1; }
  echo "$resp" | jq 2>/dev/null || echo "$resp"
  if echo "$resp" | grep -qi "decrypt"; then
    echo ""
    echo "The app-server could not decrypt the keys: its ARMOR_PASS_PHRASE must equal this"
    echo "keyring's passphrase (the one in QADENA_KEYRING_PASS). Set it in stacks/epdc/.env and restart the api."
    exit 1
  fi
  echo "$resp" | jq -e '.status == "ok"' > /dev/null 2>&1 || exit 1
}

case_cmd() {
  local cmd=$1; shift
  case "$cmd" in
    setup)              setup_epdc; cmd_upload; cmd_instantiate; register_attestors; setup_backend ;;
    setup-epdc)         setup_epdc ;;
    upload)             cmd_upload ;;
    instantiate)        cmd_instantiate ;;
    register-attestors) register_attestors ;;
    attestor-keys)      attestor_keys ;;
    setup-backend)      setup_backend ;;
    contract-addr)      contract_addr ;;
    clean)              rm -f "$EPDC_SCRIPT_DIR/$STATE_FILE"; echo "state cleaned" ;;

    deactivate-attestor) require_args "deactivate-attestor <addr>" 1 "$@"
                         tx "deactivate_attestor" tx wasm execute "$(contract_addr)" "{\"deactivate_attestor\":{\"addr\":\"$1\"}}" ;;

    get-attestors)      q '{"get_attestors":{}}' ;;
    get-quorum-rules)   q '{"get_quorum_rules":{}}' ;;
    get-count)          q '{"get_count":{}}' ;;
    get-event)          require_args "get-event <id>" 1 "$@"
                        q "{\"get_event\":{\"id\":\"$1\"}}" ;;
    get-events)         # [start_after_seq] [limit]
                        q "{\"get_events\":{\"start_after\":${1:-null},\"limit\":${2:-null}}}" ;;
    get-events-by-instrument) require_args "get-events-by-instrument <instrument_ref> [start_after] [limit]" 1 "$@"
                        q "{\"get_events_by_instrument\":{\"instrument_ref\":\"$1\",\"start_after\":${2:-null},\"limit\":${3:-null}}}" ;;
    get-holder)         require_args "get-holder <instrument_ref>" 1 "$@"
                        q "{\"get_holder\":{\"instrument_ref\":\"$1\"}}" ;;

    *) echo "Usage: $0 [-n node] [-k key] [-c contract] [-a api_base] <command> [args]"
       echo "Commands: setup | setup-epdc | upload | instantiate | register-attestors | attestor-keys"
       echo "          setup-backend | contract-addr | clean"
       echo "          deactivate-attestor <addr>"
       echo "          get-attestors | get-quorum-rules | get-count"
       echo "          get-event <id> | get-events [start_after_seq] [limit]"
       echo "          get-events-by-instrument <instrument_ref> [start_after] [limit]"
       echo "          get-holder <instrument_ref>"
       exit 1 ;;
  esac
}

# Parse global options
while [[ "$1" == -* ]]; do
  case "$1" in
    -n|--node) QADENA_NODE="tcp://$2"; shift 2 ;;
    -k|--key)  FROM="$2"; shift 2 ;;
    -c|--contract) CONTRACT_OVERRIDE="$2"; shift 2 ;;
    -a|--api)  EPDC_API_BASE="$2"; shift 2 ;;
    *) echo "Unknown option $1"; exit 1 ;;
  esac
done

case_cmd "$@"
