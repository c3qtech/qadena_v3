#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

cd $qadenabuild

qadenad_alias keys add alice
qadenad_alias keys add bob

$qadenatestscripts/grant_from_treasury.sh alice 10qdn
$qadenatestscripts/grant_from_treasury.sh bob 10qdn

echo "-------------------------"
echo "Alice balance:"
echo "-------------------------"
qadenad_alias query bank balances $(qadenad_alias keys show alice -a)
echo "-------------------------"
echo "Bob balance:"
echo "-------------------------"
qadenad_alias query bank balances $(qadenad_alias keys show bob -a)

# Upload the contract
RESP=$(qadenad_alias --gas $gas_auto --gas-adjustment $gas_adjustment --gas-prices $minimum_gas_prices tx wasm store $qadenatestdata/hackatom.wasm \
  --from alice \
    -y \
    -o json)

# wait for result
qadenad_alias query wait-tx $(echo "$RESP"| jq -r '.txhash') --timeout 30s

# Fetch the transaction details
RESP=$(qadenad_alias query tx $(echo "$RESP"| jq -r '.txhash') -o json)
 
# Extract the code ID
CODE_ID=$(echo "$RESP" | jq -r '.events[]| select(.type=="store_code").attributes[]| select(.key=="code_id").value')
 
# Print code id
echo "-------------------------"
echo "Code id: $CODE_ID"
echo "-------------------------"

# Retrieve the address of Alice's account
ALICE_ADDR=$(qadenad_alias keys show alice -a)
 
# Retrieve the address of Bob's account
BOB_ADDR=$(qadenad_alias keys show bob -a)
 
# Define init parameters for the contract
INIT="{\"verifier\":\"$ALICE_ADDR\", \"beneficiary\":\"$BOB_ADDR\"}"

RESP=$(qadenad_alias --gas $gas_auto --gas-adjustment $gas_adjustment --gas-prices $minimum_gas_prices tx wasm instantiate "$CODE_ID" "$INIT" \
  --admin="$ALICE_ADDR" \
  --from alice \
  --amount="1qdn" \
  --label "local0.1.0" \
    -y \
    -o json)

# wait for result
qadenad_alias query wait-tx $(echo "$RESP"| jq -r '.txhash') --timeout 30s

CONTRACT=$(qadenad_alias query wasm list-contract-by-code "$CODE_ID" -o json )
echo "-------------------------"
echo "Contracts: $CONTRACT"
echo "-------------------------"

# Print contract address
CONTRACT_ADDR=$(echo "$CONTRACT" | jq -r '.contracts[-1]')
echo "-------------------------"
echo "Contract address: $CONTRACT_ADDR"
echo "-------------------------"

# show balance
echo "-------------------------"
echo "Alice balance:"
echo "-------------------------"
qadenad_alias query bank balances $(qadenad_alias keys show alice -a)
echo "-------------------------"
echo "Bob balance:"
echo "-------------------------"
qadenad_alias query bank balances $(qadenad_alias keys show bob -a)

qadenad_alias query wasm contract $CONTRACT_ADDR -o json

# Define the message to send to the contract, in this case a "release" command
MSG='{"release":{}}'
 
# Execute the contract with the specified message
RESP=$(qadenad_alias --gas $gas_auto --gas-adjustment $gas_adjustment --gas-prices $minimum_gas_prices  tx wasm execute "$CONTRACT_ADDR" "$MSG" \
  --from alice \
    -y \
    -o json)
   
# wait for result
qadenad_alias query wait-tx $(echo "$RESP"| jq -r '.txhash') --timeout 30s

# show balance
echo "-------------------------"
echo "Alice balance:"
echo "-------------------------"
qadenad_alias query bank balances $(qadenad_alias keys show alice -a)
echo "-------------------------"
echo "Bob balance:"
echo "-------------------------"
qadenad_alias query bank balances $(qadenad_alias keys show bob -a)

 
