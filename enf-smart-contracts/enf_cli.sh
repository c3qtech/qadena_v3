#!/bin/zsh
#
# enf_cli.sh — deploy and exercise the ENF Electronic Notarial Book smart contract on a local
# Qadena node, mirroring cadena-smart-contracts/cadena_cli.sh.
#
# Quick start (local Qadena node running):
#   ./enf_cli.sh setup                       # store wasm + instantiate, saves enf_state.json
#   ./enf_cli.sh register-enp 12345 enp@x.com "Atty. Jane Cruz" 2024-001
#   ./enf_cli.sh get-enp 12345
#   ./enf_cli.sh update-enp 12345 jane@x.com "Atty. Jane Cruz" 2026-009 enf-admin@x.com
#   ./enf_cli.sh get-enp-changes 12345
#   ./enf_cli.sh create-entry entry-1 12345
#   ./enf_cli.sh get-entry entry-1
#   ./enf_cli.sh get-entries
#
# After `setup`, copy the printed contract address into the API's ENF_NOTARIAL_CONTRACT_ADDRESS.

# Resolve the Qadena scripts (qadenad_alias, gas vars) the same way cadena_cli.sh does,
# relative to this script, which lives in the qadena_v3 repo.
SCRIPT_DIR=$(cd "$(dirname "$0")/../scripts"; pwd)
source "$SCRIPT_DIR/../scripts/setup_env.sh"

ENF_SCRIPT_DIR=$(cd $(dirname $0); pwd)
STATE_FILE="./enf_state.json"
WASM="$ENF_SCRIPT_DIR/artifacts/enf_notarial_book.wasm"

QADENA_NODE="tcp://localhost:26657"
FROM="ENF"                          # the ENF deployer user (created by setup-enf); override with -k
ENF_IDENTITY_PROVIDER="enfidentitysrvprv"  # identity provider that issues ENF's credentials
CONTRACT_OVERRIDE=""

# For `setup-backend` (registers the contract + signing keys with the running API).
ENF_API_BASE="${ENF_API_BASE:-http://localhost:3002}"  # ENF API base URL (override with -a)
APIVERSION="${APIVERSION:-v1}"
ENF_EPH_COUNT="${ENF_EPH_COUNT:-3}"  # number of ephemeral signing wallets (matches setup-enf)
# The create-wallet sponsor that pays to create the ENF deployer wallet. Must match the
# key setup_enf.sh made: it sets createwalletsponsorname="enf-create-wallet-sponsor",
# and the keyring holds per-product sponsors (enf-, ekycph-, sec-) with no bare
# "create-wallet-sponsor". Hardcoding the bare name here meant setup-enf could never
# work on a machine set up by setup_enf.sh: create-wallet failed with "Couldn't access
# private key create-wallet-sponsor", rolled back the keys it had just made ("Removed
# key ENF"), and every later step then ran with an empty address.
ENF_CREATE_WALLET_SPONSOR="${ENF_CREATE_WALLET_SPONSOR:-enf-create-wallet-sponsor}"

save_state() {
  [[ -f "$ENF_SCRIPT_DIR/$STATE_FILE" ]] || echo '{}' > "$ENF_SCRIPT_DIR/$STATE_FILE"
  jq --arg k "$1" --arg v "$2" '.[$k]=$v' "$ENF_SCRIPT_DIR/$STATE_FILE" > tmp.$$.json && mv tmp.$$.json "$ENF_SCRIPT_DIR/$STATE_FILE"
  echo "Saved $1: $2"
}
load_state() {
  [[ -f "$ENF_SCRIPT_DIR/$STATE_FILE" ]] && jq -r --arg k "$1" '.[$k] // empty' "$ENF_SCRIPT_DIR/$STATE_FILE"
}

contract_addr() {
  if [[ -n "$CONTRACT_OVERRIDE" ]]; then echo "$CONTRACT_OVERRIDE"; else load_state "contract_address"; fi
}

tx() { # broadcast a tx and wait for it to commit
  local label=$1; shift
  echo ">> $label"
  local resp=$(qadenad_alias --node $QADENA_NODE --gas $gas_auto --gas-adjustment $gas_adjustment --gas-prices $minimum_gas_prices "$@" --from $FROM -y -o json)
  local hash=$(echo "$resp" | jq -r '.txhash')
  qadenad_alias --node $QADENA_NODE query wait-tx "$hash" --timeout 30s -o json | jq '{code: .code, raw_log: .raw_log, events: [.events[] | select(.type|test("wasm|store_code|instantiate"))]}'
}

q() { # smart-query the contract
  qadenad_alias --node $QADENA_NODE query wasm contract-state smart "$(contract_addr)" "$1" -o json | jq
}

# require_args <usage> <count> <args...> — fail unless the first <count> args are all non-empty.
require_args() {
  local usage="$1" need="$2"; shift 2
  if (( $# < need )); then
    echo "Error: missing required argument(s). Usage: $0 $usage"; exit 1
  fi
  local n=0
  for a in "$@"; do
    n=$((n + 1)); (( n > need )) && break
    if [[ -z "$a" ]]; then
      echo "Error: argument $n is empty. Usage: $0 $usage"; exit 1
    fi
  done
}

# Create a brand-new ENF deployer user and fund it, mirroring cadena_cli.sh's setup_dbm(): a
# fresh keyring account onboarded via create_user.sh (wallet + eph wallets + personal-info/phone/
# email credentials issued by the ENF identity provider), then funded from treasury. The new user
# ($FROM) is a distinct key — NOT the enfidentitysrvprv provider key.
setup_enf() {
  local name="$FROM"
  if [[ -n "$(load_state "enf_address")" ]]; then
    echo "ENF user '$name' already created ($(load_state enf_address))"
    return
  fi
  [[ -n "$qadenaproviderscripts" && -x "$qadenaproviderscripts/create_user.sh" ]] || {
    echo "create_user.sh not found (qadenaproviderscripts=$qadenaproviderscripts)"; exit 1; }
  [[ -n "$qadenatestscripts" && -x "$qadenatestscripts/grant_from_treasury.sh" ]] || {
    echo "grant_from_treasury.sh not found (qadenatestscripts=$qadenatestscripts)"; exit 1; }

  local eph_count="$ENF_EPH_COUNT"
  if qadenad_alias keys show "$name" > /dev/null 2>&1; then
    echo "$name key already exists — skipping create_user.sh"
  else
    echo "-------------------------"
    echo "Creating new ENF deployer user '$name' (credentials issued by $ENF_IDENTITY_PROVIDER)"
    echo "-------------------------"
    local mnemonic=$(qadenad_alias keys mnemonic)
    # Args mirror cadena's setup_dbm() create_user.sh call; identity provider = ENF's.
    #
    # THE a/bf VALUES MUST DIFFER FROM CADENA'S.  A credential is unique on
    # (CredentialID, CredentialType) -- see msg_server_create_credential.go -- and CredentialID is
    # derived from these two.  cadena_cli.sh uses a="5555" bf="7777", and this call was written by
    # copying setup_dbm() verbatim, so it used them too.  The result: the ENF deployer and the
    # cadena DBM deployer cannot coexist on one chain.  On a chain where the cadena suite has run,
    # creating the ENF deployer fails with "codespace qadena code 1115: Credential already exists".
    #
    # It failed quietly: the wallets are created first and succeed, only the personal-info
    # credential collides, create_user.sh does not propagate the failure, and setup_enf.sh went on
    # to report "chain setup complete" with the ENF deployer missing its credential.
    #
    # THE OUTPUT IS INSPECTED, not just the exit status.  create_user.sh returns 0 even when one of
    # the transactions it broadcasts is rejected on chain, so checking $? alone catches nothing --
    # that is exactly how the collision above stayed invisible.  Tee it so a normal run still shows
    # progress, then fail on any rejected tx.
    local cu_log
    cu_log=$(mktemp)
    if ! "$qadenaproviderscripts/create_user.sh" \
      "$name" "$mnemonic" "pioneer1" "" \
      "ENF" "" "Deployer" "1990-Jan-01" "PH" "PH" "M" \
      "no-reply+enf-deployer@enf.ph" "+6320000001" "5561" "7783" \
      "$ENF_IDENTITY_PROVIDER" "" "" "" "$eph_count" "$ENF_CREATE_WALLET_SPONSOR" 2>&1 | tee "$cu_log"; then
      rm -f "$cu_log"
      echo "create_user.sh failed for '$name'"; exit 1
    fi
    if grep -qE "failed with [0-9]+:|codespace qadena code" "$cu_log"; then
      echo ""
      echo "create_user.sh reported a REJECTED transaction while creating '$name':"
      grep -E "failed with [0-9]+:|codespace qadena code" "$cu_log" | head -5
      echo ""
      echo "The deployer is not fully set up.  'Credential already exists' here means the a/bf"
      echo "values collide with another deployer on this chain -- see the comment above."
      rm -f "$cu_log"
      exit 1
    fi
    rm -f "$cu_log"
  fi

  echo "-------------------------"
  echo "Funding $name (and eph wallets) from treasury"
  echo "-------------------------"
  local amount="100000qdn"
  "$qadenatestscripts/grant_from_treasury.sh" "$(qadenad_alias keys show $name --address)" "$amount"
  for i in $(seq 1 $eph_count); do
    "$qadenatestscripts/grant_from_treasury.sh" "$(qadenad_alias keys show $name-eph$i --address)" "$amount"
  done

  local addr=$(qadenad_alias keys show "$name" --address)
  echo "ENF user address: $addr"
  echo "Balance:"
  qadenad_alias --node $QADENA_NODE query bank balances "$addr"
  save_state "enf_address" "$addr"
}

# Register the deployed contract + ENF signing keys with the running API via /enf/setup_enf
# (mirrors how Cadena's DBM is registered via /ftm/setup_cadena in test-ftm/init-cadena.sh). It
# uses extract_ephem_keys.sh to extract the base provider, its credential, and the ephemeral
# wallets as base64( JSON array ) `names` / `private_keys` — the format SetupENF expects (the
# keys are exported with the "dummy-passphrase" that must match the API's ARMOR_PASS_PHRASE).
setup_backend() {
  local addr="$(contract_addr)"
  [[ -n "$addr" ]] || { echo "No contract address in state — run setup/instantiate first"; exit 1; }

  # Verify the contract is actually on chain before telling the app-server to use it.
  # Registering a phantom address does not fail here -- it fails later and elsewhere:
  # the app-server tries to import the signing key for a contract that does not exist
  # and reports "failed to decrypt private key: EOF", which points at the keyring and
  # sends the investigation to entirely the wrong place.
  if ! qadenad_alias --node "$QADENA_NODE" query wasm contract "$addr" > /dev/null 2>&1; then
    echo "Contract $addr is not on this chain (node $QADENA_NODE)."
    echo "  enf_state.json is stale -- most likely the chain was reinstalled."
    echo "  Run:  ./enf_cli.sh clean  then  setup_enf.sh --with-contracts"
    exit 1
  fi
  [[ -n "$qadenatestscripts" && -x "$qadenatestscripts/extract_ephem_keys.sh" ]] || {
    echo "extract_ephem_keys.sh not found (qadenatestscripts=$qadenatestscripts)"; exit 1; }

  echo "Extracting signing keys for '$FROM' (base + credential + $ENF_EPH_COUNT ephemerals)..."
  local ephem_keys=$("$qadenatestscripts/extract_ephem_keys.sh" --provider "$FROM#" --count "$ENF_EPH_COUNT" \
    --include-base-provider --include-base-provider-credential --json 2>/dev/null)
  local enf_username=$(echo "$ephem_keys" | jq -r ".names")
  local enf_private_key=$(echo "$ephem_keys" | jq -r ".private_keys")
  [[ -n "$enf_username" && "$enf_username" != "null" && -n "$enf_private_key" && "$enf_private_key" != "null" ]] || {
    echo "Failed to extract keys for '$FROM' (is it set up? run setup-enf first)"; exit 1; }

  local body=$(jq -nc --arg c "$addr" --arg u "$enf_username" --arg k "$enf_private_key" \
    '{contract_address:$c, enf_username:$u, enf_private_key:$k}')
  local url="$ENF_API_BASE/$APIVERSION/enf/setup_enf"
  echo "POST $url  (contract=$addr, signer=$FROM)"
  curl -sS -X POST "$url" -H "Content-Type: application/json" -d "$body" | jq 2>/dev/null \
    || { echo "Request to $url failed (is the ENF API running? override with -a <base_url>)"; exit 1; }
}

# THIS IS WHERE THE "INTERMITTENT INSTANTIATE FAILURE" ACTUALLY CAME FROM.
#
# It used to be: broadcast, `query wait-tx`, jq the code_id out of that response, save it.  Neither
# the broadcast's own code nor wait-tx's exit status was checked.  `query wait-tx` waits on a
# WEBSOCKET EVENT, and when it loses the race it returns "timed out waiting for transaction to be
# included in a block" for a transaction that committed perfectly well.  Its response then has no
# store_code event, jq yields nothing, and the function saves an EMPTY code_id and returns 0.
#
# So upload reported success, and the failure surfaced one step later as
# "No code_id — run upload first" -> the suite reported "instantiate failed".  The error named the
# wrong command, which is why it read as a flaky instantiate for as long as it did.
#
# confirm_tx polls the CHAIN rather than trusting the event, which is the whole reason it exists.
cmd_upload() {
  [[ -f "$WASM" ]] || { echo "Missing $WASM — run ./optimizer.sh first"; exit 1; }
  local resp=$(qadenad_alias --node $QADENA_NODE --gas $gas_auto --gas-adjustment $gas_adjustment --gas-prices $minimum_gas_prices tx wasm store "$WASM" --from $FROM -y -o json)

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
  if [[ -z "$code_id" ]]; then
    echo "upload: $hash committed but carried no store_code/code_id event."
    exit 1
  fi
  save_state "code_id" "$code_id"
}

cmd_instantiate() {
  local code_id=$(load_state "code_id")
  [[ -n "$code_id" ]] || { echo "No code_id — run upload first"; exit 1; }
  local admin=$(qadenad_alias keys show $FROM --address)
  # No --amount.  Funding a contract at instantiate goes through bank's SendCoins and is AML-scanned
  # like any other transfer; a contract address is neither a module account nor a credentialed
  # wallet, so the deposit is refused and takes the whole instantiate with it.  The notarial book
  # keeps records and never held or paid out funds, so the deposit was doing nothing to begin with.
  local resp=$(qadenad_alias --node $QADENA_NODE --gas $gas_auto --gas-adjustment $gas_adjustment --gas-prices $minimum_gas_prices tx wasm instantiate "$code_id" '{}' \
    --admin="$admin" --from $FROM --label "enf-notarial-book-v1" -y -o json)

  # CHECKED.  wait_for_tx's status was previously discarded, so a lost websocket race fell straight
  # through to list-contract-by-code -- which happily returns the PREVIOUS contract for this code_id,
  # or null.  Either way the state file ended up naming something that was not just instantiated.
  wait_for_tx "$resp" "instantiate" || exit 1

  local addr=$(qadenad_alias --node $QADENA_NODE query wasm list-contract-by-code "$code_id" -o json 2>/dev/null | jq -r '.contracts[-1] // empty' 2>/dev/null)
  if [[ -z "$addr" || "$addr" == "null" ]]; then
    echo "instantiate: committed but no contract is listed under code_id $code_id"
    exit 1
  fi
  save_state "contract_address" "$addr"
  echo "Contract address: $addr"
  echo ">> Set ENF_NOTARIAL_CONTRACT_ADDRESS=$addr in the API env"
}

case_cmd() {
  local cmd=$1; shift
  case "$cmd" in
    setup)            setup_enf; cmd_upload; cmd_instantiate ; setup_backend ;;
    setup-enf)        setup_enf ;;
    setup-backend)    setup_backend ;;
    upload)           cmd_upload ;;
    instantiate)      cmd_instantiate ;;
    contract-addr)    contract_addr ;;
    clean)            rm -f "$ENF_SCRIPT_DIR/$STATE_FILE"; echo "state cleaned" ;;

    register-enp)     # <roll> <email> <full_name> <commission> — all required
      require_args "register-enp <roll> <email> <full_name> <commission>" 4 "$@"
      tx "register_enp" tx wasm execute "$(contract_addr)" \
        "{\"register_enp\":{\"roll_number\":\"$1\",\"email\":\"$2\",\"full_name\":\"$3\",\"commission_number\":\"$4\"}}" ;;
    update-enp)       # <roll> <email> <full_name> <commission> <changed_by> — all required
      require_args "update-enp <roll> <email> <full_name> <commission> <changed_by>" 5 "$@"
      tx "update_enp" tx wasm execute "$(contract_addr)" \
        "{\"update_enp\":{\"roll_number\":\"$1\",\"email\":\"$2\",\"full_name\":\"$3\",\"commission_number\":\"$4\",\"changed_by\":\"$5\"}}" ;;
    create-entry)     # <id> <roll> [status]  — minimal sample entry to test sequencing
      require_args "create-entry <id> <roll> [status]" 2 "$@"
      local entry_status=${3:-COMPLETED}
      tx "create_entry" tx wasm execute "$(contract_addr)" \
        "{\"create_entry\":{\"id\":\"$1\",\"enp\":{\"roll_number\":\"$2\",\"email\":\"enp@x.com\",\"full_name\":\"Atty. Test\",\"commission_number\":\"2024-001\"},\"entry_date\":1700000000,\"status\":\"$entry_status\",\"mode\":\"REN\",\"notarization_type\":\"ACKNOWLEDGMENT\",\"document_title\":\"Sample Deed\",\"document_type\":\"DEED_OF_SALE\",\"parties\":[{\"full_name\":\"Jane Doe\",\"role\":\"SIGNATORY\",\"email\":\"jane@x.com\"}],\"references\":{\"document_id\":\"doc-1\",\"document_checksum\":\"abc123\",\"certificate\":{\"id\":\"cert-1\",\"number\":\"ENF-2026-00001\",\"cert_type\":\"ACKNOWLEDGMENT\",\"notarized_at\":1700000000,\"content\":\"This instrument...\"}},\"cancellation_reason\":null,\"cancelled_by\":null}}" ;;

    get-enp)              require_args "get-enp <roll>" 1 "$@"
                          q "{\"get_enp\":{\"roll_number\":\"$1\"}}" ;;
    get-enp-by-email)     require_args "get-enp-by-email <email>" 1 "$@"
                          q "{\"get_enp_by_email\":{\"email\":\"$1\"}}" ;;
    get-enp-by-commission)require_args "get-enp-by-commission <commission>" 1 "$@"
                          q "{\"get_enp_by_commission\":{\"commission_number\":\"$1\"}}" ;;
    get-enps)             # [start_after_roll] [limit] — iterate the ENP registry
                          local sa=null; [[ -n "$1" ]] && sa="\"$1\""
                          q "{\"get_enps\":{\"start_after\":$sa,\"limit\":${2:-null}}}" ;;
    get-enp-changes)      require_args "get-enp-changes <roll> [start_after] [limit]" 1 "$@"
                          q "{\"get_enp_changes\":{\"roll_number\":\"$1\",\"start_after\":${2:-null},\"limit\":${3:-null}}}" ;;
    get-entry)            require_args "get-entry <id>" 1 "$@"
                          q "{\"get_entry\":{\"id\":\"$1\"}}" ;;
    get-entries)          # [start_after_enf_seq] [limit] — iterate all entries (global order)
                          q "{\"get_entries\":{\"start_after\":${1:-null},\"limit\":${2:-null}}}" ;;
    get-entries-by-enp)   require_args "get-entries-by-enp <roll> [start_after] [limit]" 1 "$@"
                          q "{\"get_entries_by_enp\":{\"roll_number\":\"$1\",\"start_after\":${2:-null},\"limit\":${3:-null}}}" ;;
    get-count)            q "{\"get_count\":{}}" ;;

    *) echo "Usage: $0 [-n node] [-k key] [-c contract] [-a api_base] <command> [args]"
       echo "Commands: setup | setup-enf | setup-backend | upload | instantiate | contract-addr | clean"
       echo "          register-enp <roll> <email> <full_name> <commission>"
       echo "          update-enp <roll> <email> <full_name> <commission> <changed_by>"
       echo "          create-entry <id> <roll> [status]"
       echo "          get-enp <roll> | get-enp-by-email <email> | get-enp-by-commission <comm>"
       echo "          get-enps [start_after_roll] [limit]            # iterate the ENP registry"
       echo "          get-enp-changes <roll> [start_after] [limit]"
       echo "          get-entry <id> | get-count"
       echo "          get-entries [start_after_enf_seq] [limit]      # iterate all entries"
       echo "          get-entries-by-enp <roll> [start_after] [limit]"
       exit 1 ;;
  esac
}

# Parse global options
while [[ "$1" == -* ]]; do
  case "$1" in
    -n|--node) QADENA_NODE="tcp://$2"; shift 2 ;;
    -k|--key)  FROM="$2"; shift 2 ;;
    -c|--contract) CONTRACT_OVERRIDE="$2"; shift 2 ;;
    -a|--api)  ENF_API_BASE="$2"; shift 2 ;;
    *) echo "Unknown option $1"; exit 1 ;;
  esac
done

case_cmd "$@"
