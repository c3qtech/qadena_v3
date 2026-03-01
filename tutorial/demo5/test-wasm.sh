. ../funcs.sh

alice_qadena_addr=$(run_cmd_capture "qadenad keys show alice --address")
bob_qadena_addr=$(run_cmd_capture "qadenad keys show bob --address")

if [ -z "$alice_qadena_addr" ] || [ -z "$bob_qadena_addr" ]; then
  run_cmd "qadenad keys add alice"
  run_cmd "qadenad keys add bob"

  alice_qadena_addr=$(run_cmd_capture "qadenad keys show alice --address")
  echo "alice_qadena_addr: $alice_qadena_addr"
  bob_qadena_addr=$(run_cmd_capture "qadenad keys show bob --address")
  echo "bob_qadena_addr: $bob_qadena_addr"


  run_cmd ../../testscripts/grant_from_treasury.sh $alice_qadena_addr 10qdn
  run_cmd ../../testscripts/grant_from_treasury.sh $bob_qadena_addr 10qdn

fi


echo "-------------------------"
echo "Alice balance:"
echo "-------------------------"

run_cmd "qadenad query bank balances $alice_qadena_addr"
echo "-------------------------"
echo "Bob balance:"
echo "-------------------------"
run_cmd "qadenad query bank balances $bob_qadena_addr"

gas_auto="auto"
gas_adjustment="1.5"
minimum_gas_prices="500000000aqdn"

# Upload the contract
RESP=$(run_cmd_capture "qadenad --gas $gas_auto --gas-adjustment $gas_adjustment --gas-prices $minimum_gas_prices tx wasm store hackatom.wasm --from alice -y -o json")

# wait for result
TXHASH=$(echo "$RESP" | jq -r '.txhash')
run_cmd "qadenad query wait-tx $TXHASH --timeout 30s"

# Fetch the transaction details
RESP=$(run_cmd_capture "qadenad query tx $TXHASH -o json")
 
# Extract the code ID
CODE_ID=$(echo "$RESP" | jq -r '.events[]| select(.type=="store_code").attributes[]| select(.key=="code_id").value')
 
# Print code id
echo "-------------------------"
echo "Code id: $CODE_ID"
echo "-------------------------"

# Retrieve the address of Alice's account
ALICE_ADDR=$(run_cmd_capture "qadenad keys show alice -a")
echo "ALICE_ADDR: $ALICE_ADDR"
 
# Retrieve the address of Bob's account
BOB_ADDR=$(run_cmd_capture "qadenad keys show bob -a")
echo "BOB_ADDR: $BOB_ADDR"
 
# Define init parameters for the contract
INIT="{\"verifier\":\"$ALICE_ADDR\", \"beneficiary\":\"$BOB_ADDR\"}"

RESP=$(run_cmd_capture "qadenad --gas $gas_auto --gas-adjustment $gas_adjustment --gas-prices $minimum_gas_prices tx wasm instantiate \"$CODE_ID\" '$INIT' --admin=\"$ALICE_ADDR\" --from alice --amount=\"1qdn\" --label \"local0.1.0\" -y -o json")

# wait for result
TXHASH=$(echo "$RESP" | jq -r '.txhash')
run_cmd "qadenad query wait-tx $TXHASH --timeout 30s"

CONTRACT=$(run_cmd_capture "qadenad query wasm list-contract-by-code \"$CODE_ID\" -o json")
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
run_cmd "qadenad query bank balances $ALICE_ADDR"
echo "-------------------------"
echo "Bob balance:"
echo "-------------------------"
run_cmd "qadenad query bank balances $BOB_ADDR"

run_cmd "qadenad query wasm contract $CONTRACT_ADDR -o json"

# Define the message to send to the contract, in this case a "release" command
MSG='{"release":{}}'
 
# Execute the contract with the specified message
echo "using qadena execute-wasm"
RESP=$(run_cmd_capture "qadenad --gas $gas_auto --gas-adjustment $gas_adjustment --gas-prices $minimum_gas_prices tx qadena execute-wasm \"$CONTRACT_ADDR\" '$MSG' --from alice -y -o json")

echo "response: $RESP"
   
# show balance
echo "-------------------------"
echo "Alice balance:"
echo "-------------------------"
run_cmd "qadenad query bank balances $ALICE_ADDR"
echo "-------------------------"
echo "Bob balance:"
echo "-------------------------"
run_cmd "qadenad query bank balances $BOB_ADDR"

 
