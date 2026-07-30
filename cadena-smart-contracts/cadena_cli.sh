#!/bin/zsh


# Compute hash
#year|department|agency|prexc_fpap_id|operunit|fundcd|uacs_sobj_cd|uacs_reg_id
# sample for the first record.  If a column is "nan", make sure to include it in the hash.  If the column is null, leave it blank, see below:
#echo -n '2020|01|001|100000000000000||nan|nan|nan' | shasum -a 256 | cut -d' ' -f1 
# hash is 48e51ef8c1c39a7e31f27ffdf7f93165dfa3818481731545e766ec1b195e12e2
# Query PAP by hash
#./cadena_cli.sh query-pap-by-composite-key <hash>

# get script dir (resolved relative to this script, which lives in the qadena_v3 repo)
SCRIPT_DIR=$(cd "$(dirname "$0")/../scripts"; pwd)
STATE_FILE="./cadena_state.json"

# Default Qadena node URL (can be overridden with --node option)
QADENA_NODE="tcp://localhost:26657"

QADENA_REST_NODE="http://localhost:1317"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

# store directory of this script
CADENA_SCRIPT_DIR=$(cd $(dirname $0); pwd)

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS] <command> [args...]"
    echo ""
    echo "Global Options:"
    echo "  -n, --node <ip:port>       Qadena node address (default: localhost:26657)"
    echo "  -c, --contract <address>   Cadena contract address (overrides state file)"
    echo ""
    echo "Commands:"
    echo "  upload-only      Upload contract only"
    echo "  instantiate-only Instantiate contract only (requires existing code ID)"
    echo "  gaa-only         Create GAA only (requires existing contract)"
    echo "  pap-only         Create PAP only (requires existing GAA)"
    echo "  paps-only        Create 10 PAPs with different IDs (requires existing GAA)"
    echo "  saro-only        Create SARO only (requires existing PAP)"
    echo "  nca-only         Create NCA only (requires existing SARO)"
    echo "  obligation-only  Create Obligation only (requires existing NCA)"
    echo "  dv-only          Create DV only (requires existing Obligation)"
    echo "  query-hierarchy [gaa_id] [paps_per_page] [pap_start_after] [saros_per_pap] [ncas_per_saro] [obligations_per_saro] [dvs_per_parent] [disbursements_per_dv]"
    echo "  query-gaas       Query existing GAA only"
    echo "  query-rest-gaas  Query GAAs using REST API (port 1317)"
    echo "  query-rest-gaa [year]  Query GAA by year using REST API (port 1317)"
    echo "  query-rest-pap <year> <dept> <agency> <prexc_fpap_id> <operunit> <fundcd> <uacs_sobj_cd> <uacs_reg_id>  Query PAP by composite key via REST"
    echo "  query-paps [gaa_id] [limit] [start_after]  Query PAPs by GAA with pagination"
    echo "  query-paps-num-idx [gaa_id] [limit] [start_idx]  Query PAPs by GAA with pagination by numeric index"
    echo "  query-pap-by-composite-key <hash>  Query PAP by composite key hash"
    echo "  query-disbursement-voucher  Query existing disbursement voucher only"
    echo "  disbursement-only      Create disbursement [recipient] [amount]"
    echo "  query-disbursement  Query disbursement by ID [disbursement_id]"
    echo "  query-disbursements-by-dv  Query disbursements by DV ID"
    echo "  query-address    Query address balance [address] [gaa_id]"
    echo "  help             Show this help message"
    echo "  query-token      Query CW20 token only"
    echo "  load-state       Load state file"
    echo "  full             Run complete flow (default)"
    echo "  clean            Clean state file"
    echo ""
    echo "PhilGEPS Commands:"
    echo "  philgeps-create [id] [amount]  Create a PhilGEPS procurement contract"
    echo "  query-philgeps-contract [id]   Query a specific PhilGEPS contract"
    echo "  query-rest-philgeps-contract [id]  Query PhilGEPS contract via REST API (port 1317)"
    echo "  query-philgeps-contracts [limit] [start_after]  Query PhilGEPS contracts with pagination"
    echo "  query-philgeps-contracts-idx [limit] [start_idx]  Query PhilGEPS contracts by numeric index"
    echo "  query-philgeps-state           Query PhilGEPS state (contract count)"
    echo "  query-philgeps-by-ref [reference_id]  Query PhilGEPS contract by reference_id"
    echo "  query-philgeps-by-contract-no [contract_no]  Query PhilGEPS contract by contract_no"
    echo "  query-rest-philgeps-by-ref <reference_id>  Query PhilGEPS by reference_id via REST"
    echo "  query-rest-philgeps-by-contract-no <contract_no>  Query PhilGEPS by contract_no via REST"
    echo ""
    echo "DPWH Commands:"
    echo "  dpwh-create [contract_id]      Create a DPWH infrastructure contract with sample data"
    echo "  query-dpwh-contract [id]       Query a specific DPWH contract"
    echo "  query-rest-dpwh-contract [id]           Query DPWH contract using REST API (port 1317)"
    echo "  query-dpwh-contract-full [id]  Query DPWH contract with all children (components, bidders, coordinates)"
    echo "  query-dpwh-contracts [limit] [start_after]  Query DPWH contracts with pagination"
    echo "  query-dpwh-contracts-idx [limit] [start_idx]  Query DPWH contracts by numeric index"
    echo "  query-dpwh-by-region [region] [limit] [start_after]  Query DPWH contracts by region"
    echo "  query-dpwh-by-status [status] [limit] [start_after]  Query DPWH contracts by status"
    echo "  query-dpwh-by-year [year] [limit] [start_after]  Query DPWH contracts by infra_year"
    echo "  query-dpwh-state               Query DPWH state (contract count)"
    echo "  query-dpwh-components [contract_id]  Query components for a DPWH contract"
    echo "  query-dpwh-bidders [contract_id]     Query bidders for a DPWH contract"
    echo "  query-dpwh-coordinates [contract_id] Query coordinates for a DPWH contract"
    echo ""
    echo "Examples:"
    echo "  $0 upload-only"
    echo "  $0 gaa-only"
    echo "  $0 paps-only                           # Create 10 PAPs"
    echo "  $0 query-paps                          # Query all PAPs"
    echo "  $0 query-paps gaa_2024                 # Query PAPs for specific GAA"
    echo "  $0 query-paps gaa_2024 5               # Query first 5 PAPs"
    echo "  $0 query-paps gaa_2024 5 paps_dpwh_001 # Query 5 PAPs after paps_dpwh_001"
    echo "  $0 query-paps-num-idx                  # Query all PAPs by numeric idx"
    echo "  $0 query-paps-num-idx gaa_2024         # Query PAPs for specific GAA by numeric idx"
    echo "  $0 query-paps-num-idx gaa_2024 5       # Query first 5 PAPs by numeric idx"
    echo "  $0 query-paps-num-idx gaa_2024 5 3     # Query 5 PAPs at idx 3 by numeric idx (indices start at 0)"
    echo "  $0 query-hierarchy                     # Query full hierarchy"
    echo "  $0 query-hierarchy gaa_2024 5          # Query hierarchy with 5 PAPs per page"
    echo "  $0 query-hierarchy gaa_2024 5 paps_dpwh_001 10 5 5 10 10  # Full pagination control"
    echo "  $0 full"
}

# Function to save state
save_state() {
    local key=$1
    local value=$2
    
    # Create state file if it doesn't exist
    if [[ ! -f "$CADENA_SCRIPT_DIR/$STATE_FILE" ]]; then
        echo '{}' > "$CADENA_SCRIPT_DIR/$STATE_FILE"
    fi
    
    # Update the state file
    jq --arg key "$key" --arg value "$value" '.[$key] = $value' "$CADENA_SCRIPT_DIR/$STATE_FILE" > tmp.$$.json && mv tmp.$$.json "$CADENA_SCRIPT_DIR/$STATE_FILE"
    echo "Saved $key: $value"
}

# Function to load state
load_state() {
    local key=$1

    if [[ -f "$CADENA_SCRIPT_DIR/$STATE_FILE" ]]; then
        jq -r --arg key "$key" '.[$key] // empty' "$CADENA_SCRIPT_DIR/$STATE_FILE"
    fi
}

# Function to clean state
clean_state() {
    if [[ -f "$CADENA_SCRIPT_DIR/$STATE_FILE" ]]; then
        rm "$CADENA_SCRIPT_DIR/$STATE_FILE"
        echo "State file cleaned"
    else
        echo "No state file to clean"
    fi
    exit 0
}

# Parse global options first
while [[ $# -gt 0 ]]; do
    case $1 in
        -n|--node)
            # if node has ":", set it to tcp://$2, otherwise, set it to tcp://$2:26657
            if [[ "$2" == *":"* ]]; then
                QADENA_NODE="tcp://$2"
                QADENA_REST_NODE="http://$2"
            else
                QADENA_NODE="tcp://$2:26657"
                QADENA_REST_NODE="http://$2:1317"
            fi
            echo "Setting Qadena node to $QADENA_NODE"
            shift 2
            ;;
        -c|--contract)
            CADENA_CONTRACT_ADDR="$2"
            echo "Setting Cadena contract address to $CADENA_CONTRACT_ADDR"
            shift 2
            ;;
        *)
            break
            ;;
    esac
done

# Function to get contract address (CLI option takes precedence over state file)
get_contract_addr() {
    if [[ -n "$CADENA_CONTRACT_ADDR" ]]; then
        echo "$CADENA_CONTRACT_ADDR"
    else
        load_state "contract_address"
    fi
}

# Parse command line arguments
OPERATION=${1:-help}

case $OPERATION in
    -h|--help|help)
        show_usage
        exit 0
        ;;
    clean)
        clean_state
        ;;
esac

# Function to setup DBM account
setup_dbm() {
    # if dbm_address is already in state, skip
    dbm_qadena_addr=$(load_state "dbm_address")
    if [[ -n "$dbm_qadena_addr" ]]; then
        echo "dbm_address already exists"
        return
    fi    

    name="DBM"

    if qadenad_alias keys show $name > /dev/null 2>&1; then
        echo "$name already exists"
        dbm_qadena_addr=$(qadenad_alias keys show $name --address)
        echo "-------------------------"
        echo "$name's current balance:"
        echo "-------------------------"
        qadenad_alias --node $QADENA_NODE query bank balances $(qadenad_alias keys show $name -a)
    else
        echo "-------------------------"
        echo "Setting up test DBM account(s)"
        echo "-------------------------"

        mnemonic="oyster derive ivory repair toy hurdle plug lunar surge slide fade shy struggle embrace involve ceiling extend focus stomach file depend buffalo dash sponsor"
        count=3
        a="5555"
        bf="7777"
        middlename=""
        gender="F"
        citizenship="PH"
        residency="PH"
        dsvsserviceprovider=""
        pioneer="pioneer1"
        identityprovider="testidentitysrvprv"
        acceptcredentialtypes=""
        acceptpassword=""
        requiresendertypes=""
        eph_count="$count"
        createwalletsponsor="create-wallet-sponsor"
        signeramount="1000000qdn"
        birthdate="1936-Apr-25"
        firstname="DBM"
        lastname="DBM"
        email="no-reply@dbm.gov.ph"
        phone="+63286573300"

        # compute per-account amount
        if [ $count -gt 0 ]; then
            echo "count is greater than 0"
            # Extract numeric prefix (digits)
            numeric_part=${signeramount%%[!0-9]*}

            # Extract suffix (non-digits after the number)
            token_suffix=${signeramount#$numeric_part}

            # Divide
            per_account_amount=$(( numeric_part / (count + 1) ))$token_suffix

            # Output
            echo "per_account_amount: $per_account_amount"
        else
            echo "count is 0"
            per_account_amount=$signeramount
        fi

        $qadenaproviderscripts/create_user.sh $name $mnemonic $pioneer "$dsvsserviceprovider" "$firstname" "$middlename" "$lastname" $birthdate $citizenship $residency $gender $email $phone $a $bf $identityprovider "$acceptcredentialtypes" "$acceptpassword" "$requiresendertypes" $eph_count "$createwalletsponsor"
        qadena_addr=$(qadenad_alias keys show $name --address)
        $qadenatestscripts/grant_from_treasury.sh $qadena_addr $per_account_amount
        # fund eph wallets
        for i in $(seq 1 $eph_count); do
            qadena_addr=$(qadenad_alias keys show $name-eph$i --address)
            $qadenatestscripts/grant_from_treasury.sh $qadena_addr $per_account_amount
        done

        dbm_qadena_addr=$(qadenad_alias keys show $name --address)
        
        echo "-------------------------"
        echo "$name's new balance:"
        echo "-------------------------"
        qadenad_alias --node $QADENA_NODE query bank balances $(qadenad_alias keys show DBM -a)
    fi
    save_state "dbm_address" "$dbm_qadena_addr"
}

# Function to upload CW20 contract
upload_cw20_contract() {
    # if cw20_code_id is already in state, skip
    cw20_code_id=$(load_state "cw20_code_id")
    if [[ -n "$cw20_code_id" ]]; then
        echo "cw20_code_id already exists"
        return
    fi    

    echo "========================="
    echo "UPLOADING CW20 CONTRACT"
    echo "========================="
    
    # Download CW20 base contract if not exists
    if [ ! -f "$CADENA_SCRIPT_DIR/cw20_base.wasm" ]; then
        echo "Downloading CW20 base contract..."
        curl -L -o $CADENA_SCRIPT_DIR/cw20_base.wasm "https://github.com/CosmWasm/cw-plus/releases/download/v1.1.2/cw20_base.wasm"
    fi
    
    RESP=$(qadenad_alias --node $QADENA_NODE --gas $gas_auto --gas-adjustment $gas_adjustment --gas-prices $minimum_gas_prices tx wasm store $CADENA_SCRIPT_DIR/cw20_base.wasm \
      --from DBM \
        -y \
        -o json)

    echo "RESP: $RESP"

    txhash=$(echo "$RESP"| jq -r '.txhash')



    RESP2=$(qadenad_alias --node $QADENA_NODE query wait-tx $txhash --timeout 30s --output json)


    # Extract code_id from the store_code event
    CW20_CODE_ID=$(echo "$RESP2" | jq -r '.events[] | select(.type=="store_code") | .attributes[] | select(.key=="code_id") | .value')
    echo "Saved CW20 code_id: $CW20_CODE_ID"
    save_state "cw20_code_id" "$CW20_CODE_ID"
    echo "CW20 contract uploaded successfully!"
}

# Function to upload contract
upload_contract() {
    # if code_id is already in state, skip
    code_id=$(load_state "code_id")
    if [[ -n "$code_id" ]]; then
        echo "code_id already exists"
        return
    fi    
    
    echo "========================="
    echo "UPLOADING CONTRACT"
    echo "========================="
    
    RESP=$(qadenad_alias --node $QADENA_NODE --gas $gas_auto --gas-adjustment $gas_adjustment --gas-prices $minimum_gas_prices tx wasm store $CADENA_SCRIPT_DIR/artifacts/cadena.wasm \
      --from DBM \
        -y \
        -o json)

    txhash=$(echo "$RESP"| jq -r '.txhash')

    RESP2=$(qadenad_alias --node $QADENA_NODE query wait-tx $txhash --timeout 30s --output json)


    CODE_ID=$(echo "$RESP2" | jq -r '.events[] | select(.type=="store_code") | .attributes[] | select(.key=="code_id") | .value')
    echo "Saved code_id: $CODE_ID"
    save_state "code_id" "$CODE_ID"
    echo "Contract uploaded successfully!"
}

# Function to instantiate contract
instantiate_contract() {
    # if contract_address is already in state, skip
    contract_address=$(load_state "contract_address")
    if [[ -n "$contract_address" ]]; then
        echo "contract_address already exists"
        return
    fi    
    
    echo "========================="
    echo "INSTANTIATING CONTRACT"
    echo "========================="
    
    CODE_ID=$(load_state "code_id")
    if [[ -z "$CODE_ID" ]]; then
        echo "Error: No code ID found. Please upload contract first."
        exit 1
    fi
    
    dbm_qadena_addr=$(load_state "dbm_address")
    if [[ -z "$dbm_qadena_addr" ]]; then
        echo "Error: No DBM address found. Please run setup first."
        exit 1
    fi

    # Define init parameters for the budget hierarchy contract
    INIT="{\"count\":0}"

    RESP=$(qadenad_alias --node $QADENA_NODE --gas $gas_auto --gas-adjustment $gas_adjustment --gas-prices $minimum_gas_prices tx wasm instantiate "$CODE_ID" "$INIT" \
      --admin="$dbm_qadena_addr" \
      --from DBM \
      --amount="1qdn" \
      --label "budget-hierarchy-v1.0.0" \
        -y \
        -o json)

    # wait for result
    qadenad_alias --node $QADENA_NODE query wait-tx $(echo "$RESP"| jq -r '.txhash') --timeout 30s

    CONTRACT=$(qadenad_alias --node $QADENA_NODE query wasm list-contract-by-code "$CODE_ID" -o json )
    echo "-------------------------"
    echo "Contracts: $CONTRACT"
    echo "-------------------------"

    # Print contract address
    CONTRACT_ADDR=$(echo "$CONTRACT" | jq -r '.contracts[-1]')
    echo "-------------------------"
    echo "Contract address: $CONTRACT_ADDR"
    echo "-------------------------"

    save_state "contract_address" "$CONTRACT_ADDR"
    
    qadenad_alias --node $QADENA_NODE query wasm contract $CONTRACT_ADDR -o json
    echo "Contract instantiated successfully!"
}

# Function to encode year in token symbol
encode_year_to_symbol() {
    local year=$1
    local last_two_digits=${year: -2}  # Get last 2 digits (e.g., 25 from 2025)
    
    # Convert to Roman numerals for common years
    case $last_two_digits in
        "20") echo "XX" ;;
        "21") echo "XXI" ;;
        "22") echo "XXII" ;;
        "23") echo "XXIII" ;;
        "24") echo "XXIV" ;;
        "25") echo "XXV" ;;
        "26") echo "XXVI" ;;
        "27") echo "XXVII" ;;
        "28") echo "XXVIII" ;;
        "29") echo "XXIX" ;;
        "30") echo "XXX" ;;
        *) 
            # Fallback: use letter encoding (A=1, B=2, etc.)
            local tens=$((last_two_digits / 10))
            local ones=$((last_two_digits % 10))
            local tens_letter=$(printf "\\$(printf '%03o' $((65 + tens)))")  # A=1, B=2, etc.
            local ones_letter=$(printf "\\$(printf '%03o' $((65 + ones)))")
            echo "${tens_letter}${ones_letter}"
            ;;
    esac
}

# Function to create GAA
create_gaa() {
    echo "========================="
    echo "CREATING GAA"
    echo "========================="
    
    CONTRACT_ADDR=$(get_contract_addr)
    if [[ -z "$CONTRACT_ADDR" ]]; then
        echo "Error: No contract address found. Please instantiate contract first."
        exit 1
    fi

    CW20_CODE_ID=$(load_state "cw20_code_id")
    if [[ -z "$CW20_CODE_ID" ]]; then
        echo "Error: No CW20 code ID found. Please upload CW20 contract first."
        exit 1
    fi

    # Set GAA year (can be changed as needed)
    GAA_YEAR=2025
    GAA_ID="gaa_${GAA_YEAR}"
    
    # Generate year-encoded token symbol
    YEAR_CODE=$(encode_year_to_symbol $GAA_YEAR)
    TOKEN_SYMBOL="GAA${YEAR_CODE}"
    
    GAA_MSG="{\"create_g_a_a\":{\"id\":\"$GAA_ID\",\"year\":$GAA_YEAR,\"total_amount\":\"5450000000000\",\"status\":\"Active\",\"token_name\":\"GAA $GAA_YEAR Peso\",\"token_symbol\":\"$TOKEN_SYMBOL\",\"token_decimals\":6,\"cw20_code_id\":$CW20_CODE_ID}}"
    
    echo "Creating GAA with token symbol: $TOKEN_SYMBOL"

    RESP=$(qadenad_alias --node $QADENA_NODE --gas $gas_auto --gas-adjustment $gas_adjustment --gas-prices $minimum_gas_prices tx wasm execute "$CONTRACT_ADDR" "$GAA_MSG" \
      --from DBM \
        -y \
        -o json)

    qadenad_alias --node $QADENA_NODE query wait-tx $(echo "$RESP"| jq -r '.txhash') --timeout 30s

    # Query the created GAA
    echo "Querying GAA..."
    qadenad_alias --node $QADENA_NODE query wasm contract-state smart "$CONTRACT_ADDR" "{\"get_g_a_a\":{\"id\":\"$GAA_ID\"}}" -o json | jq
    
    # Query token info
    echo "Querying Token Info..."
    qadenad_alias --node $QADENA_NODE query wasm contract-state smart "$CONTRACT_ADDR" "{\"get_token_info\":{\"gaa_id\":\"$GAA_ID\"}}" -o json | jq
    
    # Query token balance for the creator (DBM)
    DBM_ADDR=$(qadenad_alias keys show DBM --address)
    echo "Querying Token Balance for DBM ($DBM_ADDR)..."
    qadenad_alias --node $QADENA_NODE query wasm contract-state smart "$CONTRACT_ADDR" "{\"get_token_balance\":{\"gaa_id\":\"$GAA_ID\",\"address\":\"$DBM_ADDR\"}}" -o json | jq
    
    save_state "gaa_id" "$GAA_ID"
    
    # Debug: Check GAA state after creation
    echo "DEBUG: Checking GAA state after creation..."
    qadenad_alias --node $QADENA_NODE query wasm contract-state smart "$CONTRACT_ADDR" "{\"get_g_a_a\":{\"id\":\"$GAA_ID\"}}" -o json | jq '.data'
    
    echo "GAA created successfully!"
}

# Function to get all GAAs
get_all_gaas() {
    echo "========================="
    echo "QUERYING ALL GAAs"
    echo "========================="
    
    CONTRACT_ADDR=$(get_contract_addr)
    if [[ -z "$CONTRACT_ADDR" ]]; then
        echo "Error: No contract address found. Please instantiate contract first."
        exit 1
    fi
    
    echo "Fetching all GAAs from contract..."
    qadenad_alias --node $QADENA_NODE query wasm contract-state smart "$CONTRACT_ADDR" '{"get_g_a_as":{"start_after":null,"limit":null}}' -o json | jq
}

# Function to get all GAAs using REST API (port 1317)
get_all_gaas_rest() {
    echo "========================="
    echo "QUERYING ALL GAAs (REST)"
    echo "========================="
    
    CONTRACT_ADDR=$(get_contract_addr)
    if [[ -z "$CONTRACT_ADDR" ]]; then
        echo "Error: No contract address found. Please instantiate contract first."
        exit 1
    fi
    
    # Base64 encode the query message
    QUERY_MSG='{"get_g_a_as":{"start_after":null,"limit":null}}'
    QUERY_B64=$(echo -n "$QUERY_MSG" | base64 | tr -d '\n')
    
    echo "Fetching all GAAs from contract via REST..."
    echo "REST endpoint: $QADENA_REST_NODE"
    curl -s "${QADENA_REST_NODE}/cosmwasm/wasm/v1/contract/${CONTRACT_ADDR}/smart/${QUERY_B64}" | jq
}

# Function to get a single GAA by ID using REST API (port 1317)
get_gaa_rest() {
    echo "========================="
    echo "QUERYING GAA BY YEAR (REST)"
    echo "========================="
    
    CONTRACT_ADDR=$(get_contract_addr)
    if [[ -z "$CONTRACT_ADDR" ]]; then
        echo "Error: No contract address found. Please instantiate contract first."
        exit 1
    fi
    
    YEAR="$1"
    if [[ -z "$YEAR" ]]; then
        # Try to load from state if not provided
        YEAR=$(load_state "year")
        if [[ -z "$YEAR" ]]; then
            echo "Error: Year is required. Usage: query-rest-gaa <year>"
            exit 1
        fi
        echo "Using Year from state: $YEAR"
    else
        echo "Using provided Year: $YEAR"
    fi
    
    # Base64 encode the query message
    QUERY_MSG="{\"get_g_a_a_by_year\":{\"year\":$YEAR}}"
    QUERY_B64=$(echo -n "$QUERY_MSG" | base64 | tr -d '\n')
    
    echo "Fetching GAA from contract via REST..."
    echo "REST endpoint: $QADENA_REST_NODE"
    curl -s "${QADENA_REST_NODE}/cosmwasm/wasm/v1/contract/${CONTRACT_ADDR}/smart/${QUERY_B64}" | jq
}

# Function to query PAP by composite key using REST API (port 1317)
# Composite key: year|department|agency|prexc_fpap_id|operunit|fundcd|uacs_sobj_cd|uacs_reg_id
# Usage: query_pap_rest <year> <department> <agency> <prexc_fpap_id> <operunit> <fundcd> <uacs_sobj_cd> <uacs_reg_id>
# Note: Use "nan" for nan values, leave empty for null values
query_pap_rest() {
    echo "========================="
    echo "QUERYING PAP BY COMPOSITE KEY (REST)"
    echo "========================="
    
    CONTRACT_ADDR=$(get_contract_addr)
    if [[ -z "$CONTRACT_ADDR" ]]; then
        echo "Error: No contract address found. Please instantiate contract first."
        exit 1
    fi
    
    # Get parameters - all 8 fields required
    YEAR="${1:-}"
    DEPARTMENT="${2:-}"
    AGENCY="${3:-}"
    PREXC_FPAP_ID="${4:-}"
    OPERUNIT="${5:-}"
    FUNDCD="${6:-}"
    UACS_SOBJ_CD="${7:-}"
    UACS_REG_ID="${8:-}"
    
    if [[ -z "$YEAR" ]]; then
        echo "Error: At least year is required."
        echo "Usage: query-rest-pap <year> <department> <agency> <prexc_fpap_id> <operunit> <fundcd> <uacs_sobj_cd> <uacs_reg_id>"
        echo ""
        echo "Example:"
        echo "  ./cadena_cli.sh query-rest-pap 2025 01 001 100000000000000 '' nan nan nan"
        echo ""
        echo "Note: Use 'nan' for nan values, leave empty ('') for null values"
        exit 1
    fi
    
    # Build composite key string: year|department|agency|prexc_fpap_id|operunit|fundcd|uacs_sobj_cd|uacs_reg_id
    COMPOSITE_KEY="${YEAR}|${DEPARTMENT}|${AGENCY}|${PREXC_FPAP_ID}|${OPERUNIT}|${FUNDCD}|${UACS_SOBJ_CD}|${UACS_REG_ID}"
    echo "Composite key: $COMPOSITE_KEY"
    
    # Compute SHA256 hash
    COMPOSITE_KEY_HASH=$(echo -n "$COMPOSITE_KEY" | shasum -a 256 | cut -d' ' -f1)
    echo "Composite key hash: $COMPOSITE_KEY_HASH"
    
    # Build query message and base64 encode
    QUERY_MSG="{\"get_p_a_p_by_composite_key\":{\"composite_key_hash\":\"$COMPOSITE_KEY_HASH\"}}"
    QUERY_B64=$(echo -n "$QUERY_MSG" | base64 | tr -d '\n')
    
    echo ""
    echo "Fetching PAP from contract via REST..."
    echo "REST endpoint: $QADENA_REST_NODE"
    curl -s "${QADENA_REST_NODE}/cosmwasm/wasm/v1/contract/${CONTRACT_ADDR}/smart/${QUERY_B64}" | jq
    
    echo ""
    echo "Query completed successfully!"
}

# Function to create PAP
create_pap() {
    echo "========================="
    echo "CREATING PAP"
    echo "========================="
    
    CONTRACT_ADDR=$(get_contract_addr)
    if [[ -z "$CONTRACT_ADDR" ]]; then
        echo "Error: No contract address found. Please instantiate contract first."
        exit 1
    fi

    GAA_ID=$(load_state "gaa_id")
    if [[ -z "$GAA_ID" ]]; then
        echo "Error: No GAA ID found. Please create GAA first."
        exit 1
    fi
    
    PAP_MSG="{\"create_p_a_p\":{\"id\":\"pap_dpwh_001\",\"gaa_id\":\"$GAA_ID\",\"uacs_sobj_dsc\":\"DPWH Infrastructure\",\"uacs_dpt_dsc\":\"Department of Public Works and Highways\",\"amount\":\"1000000000000\",\"uacs_reg_id\":\"NCR\",\"uacs_operdiv_id\":\"DIV-01\",\"uacs_div_dsc\":\"Central Office\",\"fund_cd\":\"101\",\"uacs_fundsubcat_dsc\":\"Regular Agency Fund\",\"uacs_exp_cd\":\"5060000000\",\"uacs_exp_dsc\":\"Capital Outlays\",\"uacs_sobj_cd\":\"5060405001\"}}"

    RESP=$(qadenad_alias --node $QADENA_NODE --gas $gas_auto --gas-adjustment $gas_adjustment --gas-prices $minimum_gas_prices tx wasm execute "$CONTRACT_ADDR" "$PAP_MSG" \
      --from DBM \
        -y \
        -o json)

    qadenad_alias --node $QADENA_NODE query wait-tx $(echo "$RESP"| jq -r '.txhash') --timeout 30s

    # Query PAPs by GAA
    echo "Querying PAPs by GAA..."
    qadenad_alias --node $QADENA_NODE query wasm contract-state smart "$CONTRACT_ADDR" "{\"get_p_a_ps_by_g_a_a\":{\"gaa_id\":\"$GAA_ID\",\"start_after\":null,\"limit\":null}}" -o json | jq
    
    save_state "pap_id" "pap_dpwh_001"
    echo "PAP created successfully!"
}

# Function to create multiple PAPs (10 PAPs)
create_paps() {
    echo "========================="
    echo "CREATING 10 PAPs"
    echo "========================="
    
    CONTRACT_ADDR=$(get_contract_addr)
    if [[ -z "$CONTRACT_ADDR" ]]; then
        echo "Error: No contract address found. Please instantiate contract first."
        exit 1
    fi

    GAA_ID=$(load_state "gaa_id")
    if [[ -z "$GAA_ID" ]]; then
        echo "Error: No GAA ID found. Please create GAA first."
        exit 1
    fi
    
    # Array of department names and descriptions (zsh arrays are 1-indexed)
    departments=("DPWH" "DepEd" "DOH" "DILG" "DA" "DSWD" "DOTr" "DND" "DENR" "DTI")
    descriptions=("Infrastructure Development" "Education Programs" "Healthcare Services" "Local Government Support" "Agricultural Development" "Social Welfare Programs" "Transportation Projects" "National Defense" "Environmental Protection" "Trade and Industry")
    
    # Base amount: 100 billion pesos each
    BASE_AMOUNT="100000000000"
    
    for i in {1..10}; do
        PAP_ID=$(printf "paps_%s_%03d" "${departments[$i]:l}" "$i")
        DEPT="${departments[$i]}"
        DESC="${descriptions[$i]}"
        
        echo "Creating PAP $i/10: $PAP_ID ($DEPT - $DESC)..."
        
        PAP_MSG="{\"create_p_a_p\":{\"id\":\"$PAP_ID\",\"gaa_id\":\"$GAA_ID\",\"uacs_sobj_dsc\":\"$DESC\",\"uacs_dpt_dsc\":\"$DEPT\",\"amount\":\"$BASE_AMOUNT\",\"sorder\":$i,\"department\":\"$DEPT\",\"uacs_reg_id\":\"NCR\",\"uacs_operdiv_id\":\"DIV-0$i\",\"uacs_div_dsc\":\"Division $i\",\"fund_cd\":\"10$i\",\"uacs_fundsubcat_dsc\":\"Regular Agency Fund\",\"uacs_exp_cd\":\"506000000$i\",\"uacs_exp_dsc\":\"Capital Outlays\",\"uacs_sobj_cd\":\"506040500$i\"}}"

        RESP=$(qadenad_alias --node $QADENA_NODE --gas $gas_auto --gas-adjustment $gas_adjustment --gas-prices $minimum_gas_prices tx wasm execute "$CONTRACT_ADDR" "$PAP_MSG" \
          --from DBM \
            -y \
            -o json)

        qadenad_alias --node $QADENA_NODE query wait-tx $(echo "$RESP"| jq -r '.txhash') --timeout 30s
        
        echo "✓ PAP $i created: $PAP_ID"
        sleep 1
    done

    # Query all PAPs by GAA
    echo ""
    echo "Querying all PAPs by GAA..."
    qadenad_alias --node $QADENA_NODE query wasm contract-state smart "$CONTRACT_ADDR" "{\"get_p_a_ps_by_g_a_a\":{\"gaa_id\":\"$GAA_ID\",\"start_after\":null,\"limit\":null}}" -o json | jq
    
    save_state "pap_id" "pap_dpwh_001"
    echo ""
    echo "========================="
    echo "All 10 PAPs created successfully!"
    echo "========================="
}

# Function to create SARO
create_saro() {
    echo "========================="
    echo "CREATING SARO"
    echo "========================="
    
    CONTRACT_ADDR=$(get_contract_addr)
    PAP_ID=$(load_state "pap_id")
    
    if [[ -z "$CONTRACT_ADDR" ]]; then
        echo "Error: No contract address found. Please instantiate contract first."
        exit 1
    fi
    
    if [[ -z "$PAP_ID" ]]; then
        echo "Error: No PAP ID found. Please create PAP first."
        exit 1
    fi

    SARO_MSG='{"create_s_a_r_o":{"id":"saro_001","pap_id":"pap_dpwh_001","saro_number":"SARO-BMB-A-24-0001","amount":"500000000000","release_date":"2024-01-15"}}'

    RESP=$(qadenad_alias --node $QADENA_NODE --gas $gas_auto --gas-adjustment $gas_adjustment --gas-prices $minimum_gas_prices tx wasm execute "$CONTRACT_ADDR" "$SARO_MSG" \
      --from DBM \
        -y \
        -o json)

    qadenad_alias --node $QADENA_NODE query wait-tx $(echo "$RESP"| jq -r '.txhash') --timeout 30s

    # Query SAROs by PAP
    echo "Querying SAROs by PAP..."
    qadenad_alias --node $QADENA_NODE query wasm contract-state smart "$CONTRACT_ADDR" '{"get_s_a_r_os_by_p_a_p":{"pap_id":"pap_dpwh_001","start_after":null,"limit":null}}' -o json | jq
    
    save_state "saro_id" "saro_001"
    echo "SARO created successfully!"
}

# Function to create Obligation
create_obligation() {
    echo "=========================="
    echo "CREATING OBLIGATION"
    echo "=========================="
    
    CONTRACT_ADDR=$(get_contract_addr)
    SARO_ID=$(load_state "saro_id")
    
    if [[ -z "$CONTRACT_ADDR" ]]; then
        echo "Error: No contract address found. Please instantiate contract first."
        exit 1
    fi
    
    if [[ -z "$SARO_ID" ]]; then
        echo "Error: No SARO ID found. Please create SARO first."
        exit 1
    fi

    OBLIGATION_MSG='{"create_obligation":{"id":"obl_001","saro_id":"saro_001","obligation_number":"OBL-DPWH-24-0001","amount":"250000000000","description":"Highway construction project","payee":"ABC Construction Corp","obligation_date":1706745600}}'

    RESP=$(qadenad_alias --node $QADENA_NODE --gas $gas_auto --gas-adjustment $gas_adjustment --gas-prices $minimum_gas_prices tx wasm execute "$CONTRACT_ADDR" "$OBLIGATION_MSG" \
      --from DBM \
        -y \
        -o json)

    qadenad_alias --node $QADENA_NODE query wait-tx $(echo "$RESP"| jq -r '.txhash') --timeout 30s

    # Query Obligations by SARO
    echo "Querying Obligations by SARO..."
    qadenad_alias --node $QADENA_NODE query wasm contract-state smart "$CONTRACT_ADDR" '{"get_obligations_by_s_a_r_o":{"saro_id":"saro_001"}}' -o json | jq
    
    save_state "obligation_id" "obl_001"
    echo "Obligation created successfully!"
}

# Function to create NCA
create_nca() {
    echo "=========================="
    echo "CREATING NCA"
    echo "=========================="
    
    CONTRACT_ADDR=$(get_contract_addr)
    SARO_ID=$(load_state "saro_id")
    
    if [[ -z "$CONTRACT_ADDR" ]]; then
        echo "Error: No contract address found. Please instantiate contract first."
        exit 1
    fi
    
    if [[ -z "$SARO_ID" ]]; then
        echo "Error: No SARO ID found. Please create SARO first."
        exit 1
    fi

    NCA_MSG='{"create_n_c_a":{"id":"nca_001","saro_ids":["saro_001"],"nca_number":"NCA-BMB-A-24-0001","amount":"100000000000","issue_date":1706745600}}'

    RESP=$(qadenad_alias --node $QADENA_NODE --gas $gas_auto --gas-adjustment $gas_adjustment --gas-prices $minimum_gas_prices tx wasm execute "$CONTRACT_ADDR" "$NCA_MSG" \
      --from DBM \
        -y \
        -o json)

    qadenad_alias --node $QADENA_NODE query wait-tx $(echo "$RESP"| jq -r '.txhash') --timeout 30s

    # Query NCAs by SARO
    echo "Querying NCAs by SARO..."
    qadenad_alias --node $QADENA_NODE query wasm contract-state smart "$CONTRACT_ADDR" '{"get_n_c_as_by_s_a_r_o":{"saro_id":"saro_001"}}' -o json | jq
    
    save_state "nca_id" "nca_001"
    echo "NCA created successfully!"
}

# Function to create DisbursementVoucher
create_disbursement_voucher() {
    echo "========================="
    echo "CREATING DISBURSEMENT VOUCHER"
    echo "========================="
    
    CONTRACT_ADDR=$(get_contract_addr)
    OBLIGATION_ID=$(load_state "obligation_id")
    NCA_ID=$(load_state "nca_id")
    
    if [[ -z "$CONTRACT_ADDR" ]]; then
        echo "Error: No contract address found. Please instantiate contract first."
        exit 1
    fi
    
    if [[ -z "$OBLIGATION_ID" ]]; then
        echo "Error: No Obligation ID found. Please create Obligation first."
        exit 1
    fi
    
    if [[ -z "$NCA_ID" ]]; then
        echo "Error: No NCA ID found. Please create NCA first."
        exit 1
    fi

    DV_MSG='{"create_disbursement_voucher":{"id":"dv_001","obligation_id":"obl_001","nca_id":"nca_001","dv_number":"DV-BMB-A-24-0001","amount":"50000000000","description":"Payment for highway construction","payee":"ABC Construction Corp","disbursement_voucher_date":1711929600}}'

    RESP=$(qadenad_alias --node $QADENA_NODE --gas $gas_auto --gas-adjustment $gas_adjustment --gas-prices $minimum_gas_prices tx wasm execute "$CONTRACT_ADDR" "$DV_MSG" \
      --from DBM \
        -y \
        -o json)

    qadenad_alias --node $QADENA_NODE query wait-tx $(echo "$RESP"| jq -r '.txhash') --timeout 30s

    # Query DVs by Obligation
    echo "Querying DVs by Obligation..."
    qadenad_alias --node $QADENA_NODE query wasm contract-state smart "$CONTRACT_ADDR" '{"get_disbursement_vouchers_by_obligation":{"obligation_id":"obl_001"}}' -o json | jq
    
    # Query DVs by NCA
    echo "Querying DVs by NCA..."
    qadenad_alias --node $QADENA_NODE query wasm contract-state smart "$CONTRACT_ADDR" '{"get_disbursement_vouchers_by_n_c_a":{"nca_id":"nca_001"}}' -o json | jq
    
    save_state "dv_id" "dv_001"
    echo "DisbursementVoucher created successfully!"
}

# Function to query hierarchy
# Usage: query_hierarchy [gaa_id] [paps_per_page] [pap_start_after] [saros_per_pap] [ncas_per_saro] [obligations_per_saro] [dvs_per_parent] [disbursements_per_dv]
query_hierarchy() {
    echo "========================="
    echo "QUERYING BUDGET HIERARCHY"
    echo "========================="
    
    CONTRACT_ADDR=$(get_contract_addr)
    
    # Use provided GAA_ID parameter or load from state
    if [[ -n "$1" ]]; then
        GAA_ID="$1"
        echo "Using provided GAA ID: $GAA_ID"
    else
        GAA_ID=$(load_state "gaa_id")
        echo "Using GAA ID from state: $GAA_ID"
    fi
    
    # Get pagination parameters
    if [[ -n "$2" ]]; then
        PAPS_PER_PAGE="$2"
        echo "PAPs per page: $PAPS_PER_PAGE"
    else
        PAPS_PER_PAGE="null"
    fi
    
    if [[ -n "$3" ]]; then
        PAP_START_AFTER="\"$3\""
        echo "PAP start after: $3"
    else
        PAP_START_AFTER="null"
    fi
    
    if [[ -n "$4" ]]; then
        SAROS_PER_PAP="$4"
        echo "SAROs per PAP: $SAROS_PER_PAP"
    else
        SAROS_PER_PAP="null"
    fi
    
    if [[ -n "$5" ]]; then
        NCAS_PER_SARO="$5"
        echo "NCAs per SARO: $NCAS_PER_SARO"
    else
        NCAS_PER_SARO="null"
    fi
    
    if [[ -n "$6" ]]; then
        OBLIGATIONS_PER_SARO="$6"
        echo "Obligations per SARO: $OBLIGATIONS_PER_SARO"
    else
        OBLIGATIONS_PER_SARO="null"
    fi
    
    if [[ -n "$7" ]]; then
        DVS_PER_PARENT="$7"
        echo "DVs per parent: $DVS_PER_PARENT"
    else
        DVS_PER_PARENT="null"
    fi
    
    if [[ -n "$8" ]]; then
        DISBURSEMENTS_PER_DV="$8"
        echo "Disbursements per DV: $DISBURSEMENTS_PER_DV"
    else
        DISBURSEMENTS_PER_DV="null"
    fi
    
    if [[ -z "$CONTRACT_ADDR" ]]; then
        echo "Error: No contract address found. Please instantiate contract first."
        exit 1
    fi
    
    if [[ -z "$GAA_ID" ]]; then
        echo "Error: No GAA ID provided or found in state. Please create GAA first or provide GAA ID as parameter."
        exit 1
    fi

    echo ""
    echo "Querying Complete Budget Hierarchy for GAA: $GAA_ID..."
    # Note: Query gas limits are set at the node level, not per-query
    qadenad_alias --node $QADENA_NODE query wasm contract-state smart "$CONTRACT_ADDR" "{\"get_budget_hierarchy\":{\"gaa_id\":\"$GAA_ID\",\"pap_start_after\":$PAP_START_AFTER,\"paps_per_page\":$PAPS_PER_PAGE,\"saros_per_pap\":$SAROS_PER_PAP,\"ncas_per_saro\":$NCAS_PER_SARO,\"obligations_per_saro\":$OBLIGATIONS_PER_SARO,\"dvs_per_parent\":$DVS_PER_PARENT,\"disbursements_per_dv\":$DISBURSEMENTS_PER_DV}}" -o json | jq
    
    echo ""
    echo "Query completed successfully!"
}

# Function to query PAPs by GAA
# Usage: query_paps [gaa_id] [limit] [start_after]
query_paps() {
    echo "========================="
    echo "QUERYING PAPs BY GAA"
    echo "========================="
    
    CONTRACT_ADDR=$(get_contract_addr)
    
    # Use provided GAA_ID parameter or load from state
    if [[ -n "$1" ]]; then
        GAA_ID="$1"
        echo "Using provided GAA ID: $GAA_ID"
    else
        GAA_ID=$(load_state "gaa_id")
        echo "Using GAA ID from state: $GAA_ID"
    fi
    
    # Get limit (count) parameter
    if [[ -n "$2" ]]; then
        LIMIT="$2"
        echo "Limit (count): $LIMIT"
    else
        LIMIT="null"
        echo "Limit: all (no limit)"
    fi
    
    # Get start_after (starting position) parameter
    if [[ -n "$3" ]]; then
        START_AFTER="\"$3\""
        echo "Start after: $3"
    else
        START_AFTER="null"
        echo "Start after: beginning (no offset)"
    fi
    
    if [[ -z "$CONTRACT_ADDR" ]]; then
        echo "Error: No contract address found. Please instantiate contract first."
        exit 1
    fi
    
    if [[ -z "$GAA_ID" ]]; then
        echo "Error: No GAA ID provided or found in state. Please create GAA first or provide GAA ID as parameter."
        exit 1
    fi

    echo ""
    echo "Querying PAPs for GAA: $GAA_ID..."
    qadenad_alias --node $QADENA_NODE query wasm contract-state smart "$CONTRACT_ADDR" "{\"get_p_a_ps_by_g_a_a\":{\"gaa_id\":\"$GAA_ID\",\"start_after\":$START_AFTER,\"limit\":$LIMIT}}" -o json | jq
    
    echo ""
    echo "Query completed successfully!"
}

# Function to query PAPs by GAA
# Usage: query_paps_num_idx [gaa_id] [limit] [start_idx]
query_paps_num_idx() {
    echo "========================="
    echo "QUERYING PAPs BY GAA (numeric idx)"
    echo "========================="
    
    CONTRACT_ADDR=$(get_contract_addr)
    
    # Use provided GAA_ID parameter or load from state
    if [[ -n "$1" ]]; then
        GAA_ID="$1"
        echo "Using provided GAA ID: $GAA_ID"
    else
        GAA_ID=$(load_state "gaa_id")
        echo "Using GAA ID from state: $GAA_ID"
    fi
    
    # Get limit (count) parameter
    if [[ -n "$2" ]]; then
        LIMIT="$2"
        echo "Limit (count): $LIMIT"
    else
        LIMIT="null"
        echo "Limit: all (no limit)"
    fi
    
    # Get start_idx (starting position) parameter
    if [[ -n "$3" ]]; then
        START_IDX=$3
        echo "Start idx: $3"
    else
        START_IDX=0
        echo "Start idx: 0 (no offset provided)"
    fi
    
    if [[ -z "$CONTRACT_ADDR" ]]; then
        echo "Error: No contract address found. Please instantiate contract first."
        exit 1
    fi
    
    if [[ -z "$GAA_ID" ]]; then
        echo "Error: No GAA ID provided or found in state. Please create GAA first or provide GAA ID as parameter."
        exit 1
    fi

    echo ""
    echo "Querying PAPs for GAA: $GAA_ID..."
    qadenad_alias --node $QADENA_NODE query wasm contract-state smart "$CONTRACT_ADDR" "{\"get_p_a_ps_by_g_a_a_num_idx\":{\"gaa_id\":\"$GAA_ID\",\"start_idx\":$START_IDX,\"limit\":$LIMIT}}" -o json | jq
    
    echo ""
    echo "Query completed successfully!"
}

# Function to query PAP by composite key hash
# Usage: query_pap_by_composite_key <composite_key_hash>
# The composite key hash is SHA256 of: year|department|agency|prexc_fpap_id|operunit|fundcd|uacs_sobj_cd|uacs_reg_id
query_pap_by_composite_key() {
    echo "========================="
    echo "QUERYING PAP BY COMPOSITE KEY HASH"
    echo "========================="
    
    CONTRACT_ADDR=$(get_contract_addr)
    
    if [[ -z "$1" ]]; then
        echo "Error: Composite key hash is required."
        echo "Usage: query_pap_by_composite_key <composite_key_hash>"
        echo ""
        echo "To compute the hash, concatenate these fields with '|' separator:"
        echo "  year|department|agency|prexc_fpap_id|operunit|fundcd|uacs_sobj_cd|uacs_reg_id"
        echo "Then compute SHA256 hash of the result."
        echo ""
        echo "Example using bash:"
        echo "  echo -n '2020|01|001|100000000000000||nan|nan|nan' | shasum -a 256 | cut -d' ' -f1"
        exit 1
    fi
    
    COMPOSITE_KEY_HASH="$1"
    echo "Composite key hash: $COMPOSITE_KEY_HASH"
    
    if [[ -z "$CONTRACT_ADDR" ]]; then
        echo "Error: No contract address found. Please instantiate contract first."
        exit 1
    fi

    echo ""
    echo "Querying PAP by composite key hash..."
    qadenad_alias --node $QADENA_NODE query wasm contract-state smart "$CONTRACT_ADDR" "{\"get_p_a_p_by_composite_key\":{\"composite_key_hash\":\"$COMPOSITE_KEY_HASH\"}}" -o json | jq
    
    echo ""
    echo "Query completed successfully!"
}

# Function to query disbursement voucher
query_disbursement_voucher() {
    echo "========================="
    echo "QUERYING DISBURSEMENT VOUCHER"
    echo "========================="
    
    CONTRACT_ADDR=$(get_contract_addr)
    DV_ID=$(load_state "dv_id")
    
    if [[ -z "$CONTRACT_ADDR" ]]; then
        echo "Error: No contract address found. Please instantiate contract first."
        exit 1
    fi
    
    if [[ -z "$DV_ID" ]]; then
        echo "Error: No DV ID found. Please create DV first."
        exit 1
    fi
    
    echo "Querying Disbursement Voucher for DV: $DV_ID"
    echo "========================="
    # QueryMsg::GetDisbursementVoucher keys on all three levels -- obligation_id, nca_id, dv_id.
    # It was sending a bare `id`, which failed with:
    #   unknown field `id`, expected one of `obligation_id`, `nca_id`, `dv_id`
    OBL_ID=$(load_state "obligation_id"); OBL_ID=${OBL_ID:-obl_001}
    NCA_ID=$(load_state "nca_id");        NCA_ID=${NCA_ID:-nca_001}
    qadenad_alias --node $QADENA_NODE query wasm contract-state smart "$CONTRACT_ADDR" "{\"get_disbursement_voucher\":{\"obligation_id\":\"$OBL_ID\",\"nca_id\":\"$NCA_ID\",\"dv_id\":\"$DV_ID\"}}" -o json | jq
}

# Function to create disbursement
create_disbursement() {
    echo "========================="
    echo "CREATING DISBURSEMENT"
    echo "========================="
    
    CONTRACT_ADDR=$(get_contract_addr)
    DV_ID=$(load_state "dv_id")

    DISB_ID="disb_001"
    
    if [[ -z "$CONTRACT_ADDR" ]]; then
        echo "Error: No contract address found. Please instantiate contract first."
        exit 1
    fi
    
    if [[ -z "$DV_ID" ]]; then
        echo "Error: No DV ID found. Please create DV first."
        exit 1
    fi
    
    # Get recipient address from command line argument or use default
    RECIPIENT=${1:-"qadena1sa6ujnwdrf2q3mdpcjf0a87wx7wt3rjxaayjrhlzs3yxamlm7gjqvrnacs"}
    AMOUNT=${2:-"25000000000"}  # Default 25 billion (half of typical DV amount)
    
    echo "Creating disbursement for DV: $DV_ID to recipient: $RECIPIENT"
    
    # disbursement_date is REQUIRED by ExecuteMsg::CreateDisbursement (u64, not Option), and its
    # absence made every disbursement fail with "missing field `disbursement_date`".  The remaining
    # fields are Option and default to None, but are filled in here to mirror the DV message above.
    DISB_DATE=${DISB_DATE:-1711929600}
    TRANSFER_MSG="{\"create_disbursement\":{\"id\":\"$DISB_ID\",\"disbursement_voucher_id\":\"$DV_ID\",\"disbursement_number\":\"DISB-0001\",\"recipient_qadena_address\":\"$RECIPIENT\",\"amount\":\"$AMOUNT\",\"disbursement_date\":$DISB_DATE,\"description\":\"Payment for highway construction\",\"payee\":\"ABC Construction Corp\",\"payment_method\":\"BANK_TRANSFER\",\"reference_number\":\"REF-DISB-0001\",\"status\":\"Completed\"}}"

    RESP=$(qadenad_alias --node $QADENA_NODE --gas $gas_auto --gas-adjustment $gas_adjustment --gas-prices $minimum_gas_prices tx wasm execute "$CONTRACT_ADDR" "$TRANSFER_MSG" \
      --from DBM \
        -y \
        -o json)

    qadenad_alias --node $QADENA_NODE query wait-tx $(echo "$RESP"| jq -r '.txhash') --timeout 30s
    
    echo "Disbursement created successfully!"
    echo "Transferred amount: $AMOUNT"
    echo "Recipient: $RECIPIENT"
}

# Function to query address balance
query_address() {
    echo "========================="
    echo "QUERYING ADDRESS BALANCE"
    echo "========================="
    
    CONTRACT_ADDR=$(get_contract_addr)

    # Use provided GAA_ID parameter or load from state
    if [[ -n "$2" ]]; then
        GAA_ID="$2"
        echo "Using provided GAA ID: $GAA_ID"
    else
        GAA_ID=$(load_state "gaa_id")
        echo "Using GAA ID from state: $GAA_ID"
    fi

    if [[ -z "$CONTRACT_ADDR" ]]; then
        echo "Error: No contract address found. Please instantiate contract first."
        exit 1
    fi
    
    if [[ -z "$GAA_ID" ]]; then
        echo "Error: No GAA ID found. Please create GAA first."
        exit 1
    fi
    
    # Get address from command line argument or use default
    ADDRESS=${1:-"qadena1sa6ujnwdrf2q3mdpcjf0a87wx7wt3rjxaayjrhlzs3yxamlm7gjqvrnacs"}
    
    echo "Querying balance for address: $ADDRESS"
    echo "========================="
    qadenad_alias --node $QADENA_NODE query wasm contract-state smart "$CONTRACT_ADDR" "{\"get_token_balance\":{\"gaa_id\":\"$GAA_ID\",\"address\":\"$ADDRESS\"}}" -o json | jq
}

# Function to query disbursement by ID
query_disbursement() {
    echo "========================="
    echo "QUERYING DISBURSEMENT"
    echo "========================="
    
    CONTRACT_ADDR=$(get_contract_addr)
    if [[ -z "$CONTRACT_ADDR" ]]; then
        echo "Error: No contract address found. Please instantiate contract first."
        exit 1
    fi
    
    # Get disbursement ID from command line argument or use a default pattern
    DISBURSEMENT_ID=${1:-"disbursement-dv_test-$(date +%s)"}
    
    echo "Querying Disbursement: $DISBURSEMENT_ID"
    echo "========================="
    qadenad_alias --node $QADENA_NODE query wasm contract-state smart "$CONTRACT_ADDR" "{\"get_disbursement\":{\"id\":\"$DISBURSEMENT_ID\"}}" -o json | jq
}

# Function to query disbursements by DV ID
query_disbursements_by_dv() {
    echo "========================="
    echo "QUERYING DISBURSEMENTS BY DV"
    echo "========================="
    
    CONTRACT_ADDR=$(get_contract_addr)
    DV_ID=$(load_state "dv_id")
    
    if [[ -z "$CONTRACT_ADDR" ]]; then
        echo "Error: No contract address found. Please instantiate contract first."
        exit 1
    fi
    
    if [[ -z "$DV_ID" ]]; then
        echo "Error: No DV ID found. Please create DV first."
        exit 1
    fi
    
    echo "Querying Disbursements for DV: $DV_ID"
    echo "========================="
    qadenad_alias --node $QADENA_NODE query wasm contract-state smart "$CONTRACT_ADDR" "{\"get_disbursements_by_d_v\":{\"dv_id\":\"$DV_ID\"}}" -o json | jq
}

# Function to query token information
query_token() {
    echo "========================="
    echo "QUERYING TOKEN INFO"
    echo "========================="
    
    CONTRACT_ADDR=$(get_contract_addr)
    if [[ -z "$CONTRACT_ADDR" ]]; then
        echo "Error: No contract address found. Please instantiate contract first."
        exit 1
    fi
    
    GAA_ID=$(load_state "gaa_id")
    if [[ -z "$GAA_ID" ]]; then
        echo "Error: No GAA ID found. Please create GAA first."
        exit 1
    fi
    
    echo "Querying Token Info for GAA: $GAA_ID"
    echo "========================="
    qadenad_alias --node $QADENA_NODE query wasm contract-state smart "$CONTRACT_ADDR" "{\"get_token_info\":{\"gaa_id\":\"$GAA_ID\"}}" -o json | jq
    
    echo ""
    echo "Querying Token Balances:"
    echo "========================="
    
    # Query balance for DBM (contract creator)
    DBM_ADDR=$(qadenad_alias keys show DBM --address)
    echo "DBM Balance ($DBM_ADDR):"
    qadenad_alias --node $QADENA_NODE query wasm contract-state smart "$CONTRACT_ADDR" "{\"get_token_balance\":{\"gaa_id\":\"$GAA_ID\",\"address\":\"$DBM_ADDR\"}}" -o json | jq
    
    echo ""
    echo "Contract Balance (contract address):"
    qadenad_alias --node $QADENA_NODE query wasm contract-state smart "$CONTRACT_ADDR" "{\"get_token_balance\":{\"gaa_id\":\"$GAA_ID\",\"address\":\"$CONTRACT_ADDR\"}}" -o json | jq
    
    echo "Token query completed successfully!"
}

# Function to create PhilGEPS procurement contract
create_philgeps_contract() {
    echo "========================="
    echo "CREATING PHILGEPS CONTRACT"
    echo "========================="
    
    CONTRACT_ADDR=$(get_contract_addr)
    if [[ -z "$CONTRACT_ADDR" ]]; then
        echo "Error: No contract address found. Please instantiate contract first."
        exit 1
    fi
    
    # Get parameters from command line or use defaults
    CONTRACT_ID=${1:-"philgeps_$(date +%s)"}
    AMOUNT=${2:-"1000000000"}  # Default 10 million pesos (in centavos)
    
    echo "Creating PhilGEPS contract: $CONTRACT_ID with amount: $AMOUNT"
    
    PHILGEPS_MSG="{\"create_procurement_contract\":{\"id\":\"$CONTRACT_ID\",\"reference_id\":\"REF-$CONTRACT_ID\",\"contract_no\":\"CN-$CONTRACT_ID\",\"award_title\":\"Test Procurement Contract\",\"notice_title\":\"Test Notice\",\"awardee_name\":\"Test Awardee Corp\",\"organization_name\":\"Test Government Agency\",\"area_of_delivery\":\"NCR\",\"business_category\":\"Goods\",\"contract_amount\":\"$AMOUNT\",\"award_date\":\"2024-01-15\",\"award_status\":\"Awarded\"}}"

    RESP=$(qadenad_alias --node $QADENA_NODE --gas $gas_auto --gas-adjustment $gas_adjustment --gas-prices $minimum_gas_prices tx wasm execute "$CONTRACT_ADDR" "$PHILGEPS_MSG" \
      --from DBM \
        -y \
        -o json)

    qadenad_alias --node $QADENA_NODE query wait-tx $(echo "$RESP"| jq -r '.txhash') --timeout 30s
    
    save_state "philgeps_contract_id" "$CONTRACT_ID"
    echo "PhilGEPS contract created successfully!"
}

# Function to query a specific PhilGEPS contract
query_philgeps_contract() {
    echo "========================="
    echo "QUERYING PHILGEPS CONTRACT"
    echo "========================="
    
    CONTRACT_ADDR=$(get_contract_addr)
    if [[ -z "$CONTRACT_ADDR" ]]; then
        echo "Error: No contract address found. Please instantiate contract first."
        exit 1
    fi
    
    # Get contract ID from command line or state
    if [[ -n "$1" ]]; then
        PHILGEPS_ID="$1"
    else
        PHILGEPS_ID=$(load_state "philgeps_contract_id")
    fi
    
    if [[ -z "$PHILGEPS_ID" ]]; then
        echo "Error: No PhilGEPS contract ID provided or found in state."
        exit 1
    fi
    
    echo "Querying PhilGEPS contract: $PHILGEPS_ID"
    echo "========================="
    qadenad_alias --node $QADENA_NODE query wasm contract-state smart "$CONTRACT_ADDR" "{\"get_procurement_contract\":{\"id\":\"$PHILGEPS_ID\"}}" -o json | jq
}

# Function to query a specific PhilGEPS contract using REST API (port 1317)
query_philgeps_contract_rest() {
    echo "========================="
    echo "QUERYING PHILGEPS CONTRACT (REST)"
    echo "========================="
    
    CONTRACT_ADDR=$(get_contract_addr)
    if [[ -z "$CONTRACT_ADDR" ]]; then
        echo "Error: No contract address found. Please instantiate contract first."
        exit 1
    fi
    
    # Get contract ID from command line or state
    if [[ -n "$1" ]]; then
        PHILGEPS_ID="$1"
    else
        PHILGEPS_ID=$(load_state "philgeps_contract_id")
    fi
    
    if [[ -z "$PHILGEPS_ID" ]]; then
        echo "Error: No PhilGEPS contract ID provided or found in state."
        echo "Usage: query-rest-philgeps-contract <id>"
        exit 1
    fi
    
    echo "Querying PhilGEPS contract: $PHILGEPS_ID"
    
    # Base64 encode the query message
    QUERY_MSG="{\"get_procurement_contract\":{\"id\":\"$PHILGEPS_ID\"}}"
    QUERY_B64=$(echo -n "$QUERY_MSG" | base64 | tr -d '\n')
    
    echo "REST endpoint: $QADENA_REST_NODE"
    curl -s "${QADENA_REST_NODE}/cosmwasm/wasm/v1/contract/${CONTRACT_ADDR}/smart/${QUERY_B64}" | jq
}

# Function to query PhilGEPS contracts with pagination
query_philgeps_contracts() {
    echo "========================="
    echo "QUERYING PHILGEPS CONTRACTS"
    echo "========================="
    
    CONTRACT_ADDR=$(get_contract_addr)
    if [[ -z "$CONTRACT_ADDR" ]]; then
        echo "Error: No contract address found. Please instantiate contract first."
        exit 1
    fi
    
    # Get pagination parameters
    if [[ -n "$1" ]]; then
        LIMIT="$1"
        echo "Limit: $LIMIT"
    else
        LIMIT="null"
        echo "Limit: all (no limit)"
    fi
    
    if [[ -n "$2" ]]; then
        START_AFTER="\"$2\""
        echo "Start after: $2"
    else
        START_AFTER="null"
        echo "Start after: beginning"
    fi
    
    echo ""
    echo "Querying PhilGEPS contracts..."
    qadenad_alias --node $QADENA_NODE query wasm contract-state smart "$CONTRACT_ADDR" "{\"get_procurement_contracts\":{\"start_after\":$START_AFTER,\"limit\":$LIMIT}}" -o json | jq
    
    echo ""
    echo "Query completed successfully!"
}

# Function to query PhilGEPS contracts by numeric index
query_philgeps_contracts_by_idx() {
    echo "========================="
    echo "QUERYING PHILGEPS CONTRACTS BY INDEX"
    echo "========================="
    
    CONTRACT_ADDR=$(get_contract_addr)
    if [[ -z "$CONTRACT_ADDR" ]]; then
        echo "Error: No contract address found. Please instantiate contract first."
        exit 1
    fi
    
    # Get pagination parameters
    if [[ -n "$1" ]]; then
        LIMIT="$1"
        echo "Limit: $LIMIT"
    else
        LIMIT="null"
        echo "Limit: all (no limit)"
    fi
    
    if [[ -n "$2" ]]; then
        START_IDX="$2"
        echo "Start index: $START_IDX"
    else
        START_IDX="null"
        echo "Start index: 0 (beginning)"
    fi
    
    echo ""
    echo "Querying PhilGEPS contracts by numeric index..."
    qadenad_alias --node $QADENA_NODE query wasm contract-state smart "$CONTRACT_ADDR" "{\"get_procurement_contracts_by_num_idx\":{\"start_idx\":$START_IDX,\"limit\":$LIMIT}}" -o json | jq
    
    echo ""
    echo "Query completed successfully!"
}

# Function to query PhilGEPS state (contract count)
query_philgeps_state() {
    echo "========================="
    echo "QUERYING PHILGEPS STATE"
    echo "========================="
    
    CONTRACT_ADDR=$(get_contract_addr)
    if [[ -z "$CONTRACT_ADDR" ]]; then
        echo "Error: No contract address found. Please instantiate contract first."
        exit 1
    fi
    
    echo "Querying PhilGEPS state..."
    qadenad_alias --node $QADENA_NODE query wasm contract-state smart "$CONTRACT_ADDR" '{"get_phil_g_e_p_s_state":{}}' -o json | jq
    
    echo ""
    echo "Query completed successfully!"
}

# Function to query PhilGEPS contract by reference_id
query_philgeps_by_reference_id() {
    echo "========================="
    echo "QUERYING PHILGEPS BY REFERENCE ID"
    echo "========================="
    
    CONTRACT_ADDR=$(get_contract_addr)
    if [[ -z "$CONTRACT_ADDR" ]]; then
        echo "Error: No contract address found. Please instantiate contract first."
        exit 1
    fi
    
    REFERENCE_ID="$1"
    if [[ -z "$REFERENCE_ID" ]]; then
        echo "Error: reference_id is required."
        exit 1
    fi
    
    echo "Querying PhilGEPS contract by reference_id: $REFERENCE_ID"
    echo "========================="
    qadenad_alias --node $QADENA_NODE query wasm contract-state smart "$CONTRACT_ADDR" "{\"get_procurement_contract_by_reference_id\":{\"reference_id\":\"$REFERENCE_ID\"}}" -o json | jq
}

# Function to query PhilGEPS contract by contract_no
query_philgeps_by_contract_no() {
    echo "========================="
    echo "QUERYING PHILGEPS BY CONTRACT NO"
    echo "========================="
    
    CONTRACT_ADDR=$(get_contract_addr)
    if [[ -z "$CONTRACT_ADDR" ]]; then
        echo "Error: No contract address found. Please instantiate contract first."
        exit 1
    fi
    
    CONTRACT_NO="$1"
    if [[ -z "$CONTRACT_NO" ]]; then
        echo "Error: contract_no is required."
        exit 1
    fi
    
    echo "Querying PhilGEPS contract by contract_no: $CONTRACT_NO"
    echo "========================="
    qadenad_alias --node $QADENA_NODE query wasm contract-state smart "$CONTRACT_ADDR" "{\"get_procurement_contract_by_contract_no\":{\"contract_no\":\"$CONTRACT_NO\"}}" -o json | jq
}

# Function to query PhilGEPS contract by reference_id using REST API (port 1317)
query_philgeps_by_reference_id_rest() {
    echo "========================="
    echo "QUERYING PHILGEPS BY REFERENCE ID (REST)"
    echo "========================="
    
    CONTRACT_ADDR=$(get_contract_addr)
    if [[ -z "$CONTRACT_ADDR" ]]; then
        echo "Error: No contract address found. Please instantiate contract first."
        exit 1
    fi
    
    REFERENCE_ID="$1"
    if [[ -z "$REFERENCE_ID" ]]; then
        echo "Error: reference_id is required."
        echo "Usage: query-rest-philgeps-by-ref <reference_id>"
        exit 1
    fi
    
    echo "Querying PhilGEPS contract by reference_id: $REFERENCE_ID"
    
    # Base64 encode the query message
    QUERY_MSG="{\"get_procurement_contract_by_reference_id\":{\"reference_id\":\"$REFERENCE_ID\"}}"
    QUERY_B64=$(echo -n "$QUERY_MSG" | base64 | tr -d '\n')
    
    echo "REST endpoint: $QADENA_REST_NODE"
    curl -s "${QADENA_REST_NODE}/cosmwasm/wasm/v1/contract/${CONTRACT_ADDR}/smart/${QUERY_B64}" | jq
}

# Function to query PhilGEPS contract by contract_no using REST API (port 1317)
query_philgeps_by_contract_no_rest() {
    echo "========================="
    echo "QUERYING PHILGEPS BY CONTRACT NO (REST)"
    echo "========================="
    
    CONTRACT_ADDR=$(get_contract_addr)
    if [[ -z "$CONTRACT_ADDR" ]]; then
        echo "Error: No contract address found. Please instantiate contract first."
        exit 1
    fi
    
    CONTRACT_NO="$1"
    if [[ -z "$CONTRACT_NO" ]]; then
        echo "Error: contract_no is required."
        echo "Usage: query-rest-philgeps-by-contract-no <contract_no>"
        exit 1
    fi
    
    echo "Querying PhilGEPS contract by contract_no: $CONTRACT_NO"
    
    # Base64 encode the query message
    QUERY_MSG="{\"get_procurement_contract_by_contract_no\":{\"contract_no\":\"$CONTRACT_NO\"}}"
    QUERY_B64=$(echo -n "$QUERY_MSG" | base64 | tr -d '\n')
    
    echo "REST endpoint: $QADENA_REST_NODE"
    curl -s "${QADENA_REST_NODE}/cosmwasm/wasm/v1/contract/${CONTRACT_ADDR}/smart/${QUERY_B64}" | jq
}

# ==========================================
# DPWH FUNCTIONS
# ==========================================

# Function to create DPWH infrastructure contract
create_dpwh_contract() {
    echo "========================="
    echo "CREATING DPWH CONTRACT"
    echo "========================="
    
    CONTRACT_ADDR=$(get_contract_addr)
    if [[ -z "$CONTRACT_ADDR" ]]; then
        echo "Error: No contract address found. Please instantiate contract first."
        exit 1
    fi
    
    # Get contract ID from command line or generate one
    DPWH_CONTRACT_ID=${1:-"dpwh_$(date +%s)"}
    
    echo "Creating DPWH contract: $DPWH_CONTRACT_ID"
    
    # Create a sample DPWH contract with components, bidders, and coordinates
    DPWH_MSG="{\"create_d_p_w_h_contract\":{
        \"contract_id\":\"$DPWH_CONTRACT_ID\",
        \"description\":\"Road Widening and Improvement Project - Test\",
        \"category\":\"Infrastructure\",
        \"status\":\"Ongoing\",
        \"budget\":\"500000000\",
        \"amount_paid\":\"150000000\",
        \"progress\":50,
        \"region\":\"NCR\",
        \"province\":\"Metro Manila\",
        \"infra_type\":\"Road\",
        \"latitude\":\"14.5995\",
        \"longitude\":\"120.9842\",
        \"verified\":true,
        \"infra_type_1\":\"National Road\",
        \"contractor\":\"ABC Construction Corp\",
        \"start_date\":1704067200,
        \"completion_date\":1735689600,
        \"infra_year\":\"2024\",
        \"contract_effectivity_date\":1704067200,
        \"expiry_date\":1735689600,
        \"program_name\":\"Build Better More\",
        \"source_of_funds\":\"GAA 2024\",
        \"contract_name\":\"DPWH-NCR-2024-001\",
        \"award_amount\":\"500000000\",
        \"components\":[
            {
                \"component_id\":\"COMP-001\",
                \"description\":\"Main Road Section\",
                \"infra_type\":\"Road\",
                \"type_of_work\":\"Widening\",
                \"region\":\"NCR\",
                \"province\":\"Metro Manila\",
                \"latitude\":\"14.5995\",
                \"longitude\":\"120.9842\",
                \"coordinate_source\":\"GPS\",
                \"location_verified\":true
            },
            {
                \"component_id\":\"COMP-002\",
                \"description\":\"Drainage System\",
                \"infra_type\":\"Drainage\",
                \"type_of_work\":\"Construction\",
                \"region\":\"NCR\",
                \"province\":\"Metro Manila\",
                \"latitude\":\"14.6000\",
                \"longitude\":\"120.9850\",
                \"coordinate_source\":\"GPS\",
                \"location_verified\":true
            }
        ],
        \"bidders\":[
            {
                \"name\":\"ABC Construction Corp\",
                \"pcab_id\":\"PCAB-12345\",
                \"participation\":100,
                \"is_winner\":true
            },
            {
                \"name\":\"XYZ Builders Inc\",
                \"pcab_id\":\"PCAB-67890\",
                \"participation\":0,
                \"is_winner\":false
            }
        ],
        \"coordinates\":[
            {
                \"component_id\":\"COMP-001\",
                \"description\":\"Start Point\",
                \"latitude\":\"14.5990\",
                \"longitude\":\"120.9840\",
                \"source\":\"GPS\",
                \"location_verified\":true
            },
            {
                \"component_id\":\"COMP-001\",
                \"description\":\"End Point\",
                \"latitude\":\"14.6000\",
                \"longitude\":\"120.9850\",
                \"source\":\"GPS\",
                \"location_verified\":true
            }
        ]
    }}"

    # Remove newlines for the command
    DPWH_MSG=$(echo "$DPWH_MSG" | tr -d '\n' | tr -s ' ')

    RESP=$(qadenad_alias --node $QADENA_NODE --gas $gas_auto --gas-adjustment $gas_adjustment --gas-prices $minimum_gas_prices tx wasm execute "$CONTRACT_ADDR" "$DPWH_MSG" \
      --from DBM \
        -y \
        -o json)

    qadenad_alias --node $QADENA_NODE query wait-tx $(echo "$RESP"| jq -r '.txhash') --timeout 30s
    
    save_state "dpwh_contract_id" "$DPWH_CONTRACT_ID"
    echo "DPWH contract created successfully!"
}

# Function to query a specific DPWH contract
query_dpwh_contract() {
    echo "========================="
    echo "QUERYING DPWH CONTRACT"
    echo "========================="
    
    CONTRACT_ADDR=$(get_contract_addr)
    if [[ -z "$CONTRACT_ADDR" ]]; then
        echo "Error: No contract address found. Please instantiate contract first."
        exit 1
    fi
    
    # Get contract ID from command line or state
    if [[ -n "$1" ]]; then
        DPWH_ID="$1"
    else
        DPWH_ID=$(load_state "dpwh_contract_id")
    fi
    
    if [[ -z "$DPWH_ID" ]]; then
        echo "Error: No DPWH contract ID provided or found in state."
        exit 1
    fi
    
    echo "Querying DPWH contract: $DPWH_ID"
    echo "========================="
    qadenad_alias --node $QADENA_NODE query wasm contract-state smart "$CONTRACT_ADDR" "{\"get_d_p_w_h_contract\":{\"contract_id\":\"$DPWH_ID\"}}" -o json | jq
}

# Function to query a specific DPWH contract using REST API (port 1317)
query_dpwh_contract_rest() {
    echo "========================="
    echo "QUERYING DPWH CONTRACT (REST)"
    echo "========================="
    
    CONTRACT_ADDR=$(get_contract_addr)
    if [[ -z "$CONTRACT_ADDR" ]]; then
        echo "Error: No contract address found. Please instantiate contract first."
        exit 1
    fi
    
    # Get contract ID from command line or state
    if [[ -n "$1" ]]; then
        DPWH_ID="$1"
    else
        DPWH_ID=$(load_state "dpwh_contract_id")
    fi
    
    if [[ -z "$DPWH_ID" ]]; then
        echo "Error: No DPWH contract ID provided or found in state."
        echo "Usage: query-rest-dpwh-contract <contract_id>"
        exit 1
    fi
    
    echo "Querying DPWH contract: $DPWH_ID"
    
    # Base64 encode the query message
    QUERY_MSG="{\"get_d_p_w_h_contract\":{\"contract_id\":\"$DPWH_ID\"}}"
    QUERY_B64=$(echo -n "$QUERY_MSG" | base64 | tr -d '\n')
    
    echo "REST endpoint: $QADENA_REST_NODE"
    curl -s "${QADENA_REST_NODE}/cosmwasm/wasm/v1/contract/${CONTRACT_ADDR}/smart/${QUERY_B64}" | jq
}

# Function to query DPWH contract with all children
query_dpwh_contract_full() {
    echo "========================="
    echo "QUERYING DPWH CONTRACT (FULL)"
    echo "========================="
    
    CONTRACT_ADDR=$(get_contract_addr)
    if [[ -z "$CONTRACT_ADDR" ]]; then
        echo "Error: No contract address found. Please instantiate contract first."
        exit 1
    fi
    
    # Get contract ID from command line or state
    if [[ -n "$1" ]]; then
        DPWH_ID="$1"
    else
        DPWH_ID=$(load_state "dpwh_contract_id")
    fi
    
    if [[ -z "$DPWH_ID" ]]; then
        echo "Error: No DPWH contract ID provided or found in state."
        exit 1
    fi
    
    echo "Querying DPWH contract with children: $DPWH_ID"
    echo "========================="
    qadenad_alias --node $QADENA_NODE query wasm contract-state smart "$CONTRACT_ADDR" "{\"get_d_p_w_h_contract_full\":{\"contract_id\":\"$DPWH_ID\"}}" -o json | jq
}

# Function to query DPWH contracts with pagination
query_dpwh_contracts() {
    echo "========================="
    echo "QUERYING DPWH CONTRACTS"
    echo "========================="
    
    CONTRACT_ADDR=$(get_contract_addr)
    if [[ -z "$CONTRACT_ADDR" ]]; then
        echo "Error: No contract address found. Please instantiate contract first."
        exit 1
    fi
    
    # Get pagination parameters
    if [[ -n "$1" ]]; then
        LIMIT="$1"
        echo "Limit: $LIMIT"
    else
        LIMIT="null"
        echo "Limit: all (no limit)"
    fi
    
    if [[ -n "$2" ]]; then
        START_AFTER="\"$2\""
        echo "Start after: $2"
    else
        START_AFTER="null"
        echo "Start after: beginning"
    fi
    
    echo ""
    echo "Querying DPWH contracts..."
    qadenad_alias --node $QADENA_NODE query wasm contract-state smart "$CONTRACT_ADDR" "{\"get_d_p_w_h_contracts\":{\"start_after\":$START_AFTER,\"limit\":$LIMIT}}" -o json | jq
    
    echo ""
    echo "Query completed successfully!"
}

# Function to query DPWH contracts by numeric index
query_dpwh_contracts_by_idx() {
    echo "========================="
    echo "QUERYING DPWH CONTRACTS BY INDEX"
    echo "========================="
    
    CONTRACT_ADDR=$(get_contract_addr)
    if [[ -z "$CONTRACT_ADDR" ]]; then
        echo "Error: No contract address found. Please instantiate contract first."
        exit 1
    fi
    
    # Get pagination parameters
    if [[ -n "$1" ]]; then
        LIMIT="$1"
        echo "Limit: $LIMIT"
    else
        LIMIT="null"
        echo "Limit: all (no limit)"
    fi
    
    if [[ -n "$2" ]]; then
        START_IDX="$2"
        echo "Start index: $START_IDX"
    else
        START_IDX="null"
        echo "Start index: 0 (beginning)"
    fi
    
    echo ""
    echo "Querying DPWH contracts by numeric index..."
    qadenad_alias --node $QADENA_NODE query wasm contract-state smart "$CONTRACT_ADDR" "{\"get_d_p_w_h_contracts_by_num_idx\":{\"start_idx\":$START_IDX,\"limit\":$LIMIT}}" -o json | jq
    
    echo ""
    echo "Query completed successfully!"
}

# Function to query DPWH contracts by region
query_dpwh_by_region() {
    echo "========================="
    echo "QUERYING DPWH BY REGION"
    echo "========================="
    
    CONTRACT_ADDR=$(get_contract_addr)
    if [[ -z "$CONTRACT_ADDR" ]]; then
        echo "Error: No contract address found. Please instantiate contract first."
        exit 1
    fi
    
    REGION="$1"
    if [[ -z "$REGION" ]]; then
        echo "Error: region is required."
        exit 1
    fi
    
    # Get pagination parameters
    if [[ -n "$2" ]]; then
        LIMIT="$2"
        echo "Limit: $LIMIT"
    else
        LIMIT="null"
    fi
    
    if [[ -n "$3" ]]; then
        START_AFTER="\"$3\""
        echo "Start after: $3"
    else
        START_AFTER="null"
    fi
    
    echo "Querying DPWH contracts by region: $REGION"
    echo "========================="
    qadenad_alias --node $QADENA_NODE query wasm contract-state smart "$CONTRACT_ADDR" "{\"get_d_p_w_h_contracts_by_region\":{\"region\":\"$REGION\",\"start_after\":$START_AFTER,\"limit\":$LIMIT}}" -o json | jq
}

# Function to query DPWH contracts by status
query_dpwh_by_status() {
    echo "========================="
    echo "QUERYING DPWH BY STATUS"
    echo "========================="
    
    CONTRACT_ADDR=$(get_contract_addr)
    if [[ -z "$CONTRACT_ADDR" ]]; then
        echo "Error: No contract address found. Please instantiate contract first."
        exit 1
    fi
    
    STATUS="$1"
    if [[ -z "$STATUS" ]]; then
        echo "Error: status is required."
        exit 1
    fi
    
    # Get pagination parameters
    if [[ -n "$2" ]]; then
        LIMIT="$2"
        echo "Limit: $LIMIT"
    else
        LIMIT="null"
    fi
    
    if [[ -n "$3" ]]; then
        START_AFTER="\"$3\""
        echo "Start after: $3"
    else
        START_AFTER="null"
    fi
    
    echo "Querying DPWH contracts by status: $STATUS"
    echo "========================="
    qadenad_alias --node $QADENA_NODE query wasm contract-state smart "$CONTRACT_ADDR" "{\"get_d_p_w_h_contracts_by_status\":{\"status\":\"$STATUS\",\"start_after\":$START_AFTER,\"limit\":$LIMIT}}" -o json | jq
}

# Function to query DPWH contracts by year
query_dpwh_by_year() {
    echo "========================="
    echo "QUERYING DPWH BY YEAR"
    echo "========================="
    
    CONTRACT_ADDR=$(get_contract_addr)
    if [[ -z "$CONTRACT_ADDR" ]]; then
        echo "Error: No contract address found. Please instantiate contract first."
        exit 1
    fi
    
    YEAR="$1"
    if [[ -z "$YEAR" ]]; then
        echo "Error: infra_year is required."
        exit 1
    fi
    
    # Get pagination parameters
    if [[ -n "$2" ]]; then
        LIMIT="$2"
        echo "Limit: $LIMIT"
    else
        LIMIT="null"
    fi
    
    if [[ -n "$3" ]]; then
        START_AFTER="\"$3\""
        echo "Start after: $3"
    else
        START_AFTER="null"
    fi
    
    echo "Querying DPWH contracts by year: $YEAR"
    echo "========================="
    qadenad_alias --node $QADENA_NODE query wasm contract-state smart "$CONTRACT_ADDR" "{\"get_d_p_w_h_contracts_by_year\":{\"infra_year\":\"$YEAR\",\"start_after\":$START_AFTER,\"limit\":$LIMIT}}" -o json | jq
}

# Function to query DPWH state (contract count)
query_dpwh_state() {
    echo "========================="
    echo "QUERYING DPWH STATE"
    echo "========================="
    
    CONTRACT_ADDR=$(get_contract_addr)
    if [[ -z "$CONTRACT_ADDR" ]]; then
        echo "Error: No contract address found. Please instantiate contract first."
        exit 1
    fi
    
    echo "Querying DPWH state..."
    qadenad_alias --node $QADENA_NODE query wasm contract-state smart "$CONTRACT_ADDR" '{"get_d_p_w_h_state":{}}' -o json | jq
    
    echo ""
    echo "Query completed successfully!"
}

# Function to query DPWH components
query_dpwh_components() {
    echo "========================="
    echo "QUERYING DPWH COMPONENTS"
    echo "========================="
    
    CONTRACT_ADDR=$(get_contract_addr)
    if [[ -z "$CONTRACT_ADDR" ]]; then
        echo "Error: No contract address found. Please instantiate contract first."
        exit 1
    fi
    
    # Get contract ID from command line or state
    if [[ -n "$1" ]]; then
        DPWH_ID="$1"
    else
        DPWH_ID=$(load_state "dpwh_contract_id")
    fi
    
    if [[ -z "$DPWH_ID" ]]; then
        echo "Error: No DPWH contract ID provided or found in state."
        exit 1
    fi
    
    echo "Querying components for DPWH contract: $DPWH_ID"
    echo "========================="
    qadenad_alias --node $QADENA_NODE query wasm contract-state smart "$CONTRACT_ADDR" "{\"get_d_p_w_h_components\":{\"contract_id\":\"$DPWH_ID\"}}" -o json | jq
}

# Function to query DPWH bidders
query_dpwh_bidders() {
    echo "========================="
    echo "QUERYING DPWH BIDDERS"
    echo "========================="
    
    CONTRACT_ADDR=$(get_contract_addr)
    if [[ -z "$CONTRACT_ADDR" ]]; then
        echo "Error: No contract address found. Please instantiate contract first."
        exit 1
    fi
    
    # Get contract ID from command line or state
    if [[ -n "$1" ]]; then
        DPWH_ID="$1"
    else
        DPWH_ID=$(load_state "dpwh_contract_id")
    fi
    
    if [[ -z "$DPWH_ID" ]]; then
        echo "Error: No DPWH contract ID provided or found in state."
        exit 1
    fi
    
    echo "Querying bidders for DPWH contract: $DPWH_ID"
    echo "========================="
    qadenad_alias --node $QADENA_NODE query wasm contract-state smart "$CONTRACT_ADDR" "{\"get_d_p_w_h_bidders\":{\"contract_id\":\"$DPWH_ID\"}}" -o json | jq
}

# Function to query DPWH coordinates
query_dpwh_coordinates() {
    echo "========================="
    echo "QUERYING DPWH COORDINATES"
    echo "========================="
    
    CONTRACT_ADDR=$(get_contract_addr)
    if [[ -z "$CONTRACT_ADDR" ]]; then
        echo "Error: No contract address found. Please instantiate contract first."
        exit 1
    fi
    
    # Get contract ID from command line or state
    if [[ -n "$1" ]]; then
        DPWH_ID="$1"
    else
        DPWH_ID=$(load_state "dpwh_contract_id")
    fi
    
    if [[ -z "$DPWH_ID" ]]; then
        echo "Error: No DPWH contract ID provided or found in state."
        exit 1
    fi
    
    echo "Querying coordinates for DPWH contract: $DPWH_ID"
    echo "========================="
    qadenad_alias --node $QADENA_NODE query wasm contract-state smart "$CONTRACT_ADDR" "{\"get_d_p_w_h_coordinates\":{\"contract_id\":\"$DPWH_ID\"}}" -o json | jq
}

# Main execution logic
case $OPERATION in
    upload-only)
        setup_dbm
        upload_cw20_contract
        upload_contract
        ;;
    instantiate-only)
        setup_dbm
        upload_cw20_contract
        upload_contract
        instantiate_contract
        ;;
    gaa-only)
        setup_dbm
        create_gaa
        ;;
    pap-only)
        setup_dbm
        create_pap
        ;;
    paps-only)
        setup_dbm
        create_paps
        ;;
    saro-only)
        setup_dbm
        create_saro
        ;;
    nca-only)
        setup_dbm
        create_nca
        ;;
    obligation-only)
        setup_dbm
        create_obligation
        ;;
    dv-only)
        setup_dbm
        create_disbursement_voucher
        ;;
    disbursement-only)
        setup_dbm
        create_disbursement  "$2" "$3"
        ;;
    query-hierarchy)
        query_hierarchy "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9"
        ;;
    query-paps)
        query_paps "$2" "$3" "$4"
        ;;
    query-paps-num-idx)
        query_paps_num_idx "$2" "$3" "$4"
        ;;
    query-pap-by-composite-key)
        query_pap_by_composite_key "$2"
        ;;
    query-disbursement-voucher)
        query_disbursement_voucher
        ;;
    query-disbursement)
        query_disbursement "$2"  # Pass disbursement ID as argument
        ;;
    query-disbursements-by-dv)
        query_disbursements_by_dv
        ;;
    query-address)
        query_address "$2"  "$3" # Pass address, gaa_id as argument
        ;;
    query-token)
        query_token
        ;;
    load-state)
        load_state "$2"  # Pass key as argument
        ;;
    query-gaas)
        get_all_gaas
        ;;
    query-rest-gaas)
        get_all_gaas_rest
        ;;
    query-rest-gaa)
        get_gaa_rest "$2"
        ;;
    query-rest-pap)
        query_pap_rest "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9"
        ;;
    philgeps-create)
        setup_dbm
        create_philgeps_contract "$2" "$3"
        ;;
    query-philgeps-contract)
        query_philgeps_contract "$2"
        ;;
    query-rest-philgeps-contract)
        query_philgeps_contract_rest "$2"
        ;;
    query-philgeps-contracts)
        query_philgeps_contracts "$2" "$3"
        ;;
    query-philgeps-contracts-idx)
        query_philgeps_contracts_by_idx "$2" "$3"
        ;;
    query-philgeps-state)
        query_philgeps_state
        ;;
    query-philgeps-by-ref)
        query_philgeps_by_reference_id "$2"
        ;;
    query-philgeps-by-contract-no)
        query_philgeps_by_contract_no "$2"
        ;;
    query-rest-philgeps-by-ref)
        query_philgeps_by_reference_id_rest "$2"
        ;;
    query-rest-philgeps-by-contract-no)
        query_philgeps_by_contract_no_rest "$2"
        ;;
    # DPWH commands
    dpwh-create)
        setup_dbm
        create_dpwh_contract "$2"
        ;;
    query-dpwh-contract)
        query_dpwh_contract "$2"
        ;;
    query-rest-dpwh-contract)
        query_dpwh_contract_rest "$2"
        ;;
    query-dpwh-contract-full)
        query_dpwh_contract_full "$2"
        ;;
    query-dpwh-contracts)
        query_dpwh_contracts "$2" "$3"
        ;;
    query-dpwh-contracts-idx)
        query_dpwh_contracts_by_idx "$2" "$3"
        ;;
    query-dpwh-by-region)
        query_dpwh_by_region "$2" "$3" "$4"
        ;;
    query-dpwh-by-status)
        query_dpwh_by_status "$2" "$3" "$4"
        ;;
    query-dpwh-by-year)
        query_dpwh_by_year "$2" "$3" "$4"
        ;;
    query-dpwh-state)
        query_dpwh_state
        ;;
    query-dpwh-components)
        query_dpwh_components "$2"
        ;;
    query-dpwh-bidders)
        query_dpwh_bidders "$2"
        ;;
    query-dpwh-coordinates)
        query_dpwh_coordinates "$2"
        ;;
    full)
        setup_dbm
        upload_cw20_contract
        upload_contract
        instantiate_contract
        create_gaa
        create_pap
        create_saro
        create_obligation
        create_nca
        create_disbursement_voucher
        create_disbursement
        query_hierarchy
        query_disbursements_by_dv
        query_address
        echo "========================="
        echo "BUDGET HIERARCHY TEST COMPLETE!"
        echo "========================="
        ;;
    *)
        echo "Error: Unknown operation '$OPERATION'"
        show_usage
        exit 1
        ;;
esac

