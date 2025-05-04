#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

# parse --all flag
all_flag=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --all)
      all_flag=1
      shift
      ;;
    --help)
      echo "Usage: $0 user@hostname_or_ip [--all]"
      exit 0
      ;;
    *)
      break
      ;;
  esac
done

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 user@hostname_or_ip"
    exit 1
fi

if [ $all_flag -eq 0 ]; then
    echo "zipping qadena, excluding config, data, keyring-test, enclave_config, and enclave_data..."
    cd $QADENAHOME/..
    rm -f /tmp/qadena.zip
    zip -r /tmp/qadena.zip qadena -x "qadena/config/*" -x "qadena/data/*" -x "qadena/keyring-test/*" -x "qadena/enclave_config/*" -x "qadena/enclave_data/*"
    zip -ur /tmp/qadena.zip qadena/config/config.yml qadena/config/node_params.json
    echo "Transferring qadena..."
    scp /tmp/qadena.zip $1:
else
    echo "Zipping qadena (all)..."
    cd $QADENAHOME/..
    rm -f /tmp/qadena_all.zip
    zip -r /tmp/qadena_all.zip qadena
    echo "Transferring qadena (all)..."
    scp /tmp/qadena_all.zip $1:
fi

