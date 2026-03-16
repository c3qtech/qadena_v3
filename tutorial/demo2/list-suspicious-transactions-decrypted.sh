. ../funcs.sh



reg_privk=$(run_cmd_capture "sed -E 's/^[^{]*//' ~/qadena/enclave_config/enclave_params*.json | jq -r '.SharedEnclaveParams.RegulatorPrivK' | head -n 1")

echo
echo "Regulator private key (extracted from enclave config since this is a demo installation): $reg_privk"
echo

if [ -z "$reg_privk" ] || [ "$reg_privk" = "null" ]; then
  echo "ERROR: couldn't extract RegulatorPrivK from ~/qadena/enclave_config/enclave_params*.json"
  exit 1
fi

run_cmd "qadenad query qadena list-suspicious-transaction $reg_privk"
