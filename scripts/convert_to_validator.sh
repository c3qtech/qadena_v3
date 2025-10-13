#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

# if REAL_ENCLAVE, check if running as root
if [[ $REAL_ENCLAVE -eq 1 ]]; then
    if [[ $(id -u) -ne 0 ]]; then
        echo "run.sh:  Error: qadenad_enclave must be run as root"
        exit 1
    fi
fi


VALIDATOR=$1

if [[ $VALIDATOR == "" ]] ; then
    VALIDATOR="10000"
fi

IS_UP=0
for i in {120..1}
do
  STATUS=$(qadenad_alias status 2> /dev/null)
  RET=$?
  if [[ $(echo $STATUS | jq -r '.sync_info.catching_up') == "false" ]]; then
      echo "QADENAD Full node is synchronized!"
      IS_UP=1
      break
  else
      if [[ $RET != 0 ]] ; then
        echo "Failed to get qadenad status"
        exit 1
      fi
      echo "QADENAD Full node not yet synchronized, waiting...$i"
      sleep 3
  fi
done

if [ $IS_UP -eq 0 ] ; then
    echo "Couldn't wait for node to be synchronized."
    exit 1
fi

PIONEER=`qadenad_alias status | jq -r '.node_info.moniker'`

if [[ $PIONEER == "" ]] ; then
    exit 1
fi

VOTING_POWER=`qadenad_alias status | jq -r '.validator_info.voting_power'`

if [[ $VOTING_POWER -ne 0 ]] ; then
    echo "$PIONEER is already a validator!"
    exit 1
fi

echo "PIONEER $PIONEER"

PIONEERADDRESS=`qadenad_alias keys show $PIONEER -a --keyring-backend test`

VALIDATOR_AQDN=`echo "$VALIDATOR * 1000000000000000000" | bc`

echo "I will attempt to detect when $PIONEERADDRESS has at least ${VALIDATOR}qdn."

IS_UP=0
for i in {120..1}
do
    BALANCE_JSON=`qadenad_alias query bank balances $PIONEERADDRESS --output json`
	BALANCE=`echo $BALANCE_JSON | jq -r '.balances[] | select(.denom=="aqdn") | .amount'`
    ret=`bc <<< "$BALANCE >= $VALIDATOR_AQDN"`
    if [[ $ret = 1 ]] ; then
      BALANCE_QDN=`echo "$BALANCE / 1000000000000000000" | bc`
      echo "$PIONEER has enough balance (${BALANCE_QDN}qdn) to become a validator!"
      IS_UP=1
      break
    else
        BALANCE_QDN=`echo "$BALANCE / 1000000000000000000" | bc`
        echo "$PIONEER balance is ${BALANCE_QDN}qdn, not enough to become a validator (need to send ${VALIDATOR}qdn).  Waiting...$i"
        echo "    $QADENAHOME/bin/qadenad --home $QADENAHOME tx bank send treasury $PIONEERADDRESS ${VALIDATOR}qdn --yes"
        sleep 3
    fi
done

if [ $IS_UP -eq 0 ] ; then
    echo "Couldn't find balance for $PIONEERADDRESS"
    exit 1
fi

# create validator json
validator_pubkey=`qadenad_alias tendermint show-validator`
validator_amount="${VALIDATOR}qdn"
validator_moniker="$PIONEER"
validator_commission_rate="0.10"
validator_commission_max_rate="0.20"
validator_commission_max_change_rate="0.01"
validator_self_delegation="1"

jq -n \
  --argjson pubkey "$validator_pubkey" \
  --arg amount "$validator_amount" \
  --arg moniker "$validator_moniker" \
  --arg commission_rate "$validator_commission_rate" \
  --arg commission_max_rate "$validator_commission_max_rate" \
  --arg commission_max_change_rate "$validator_commission_max_change_rate" \
  --arg min_self_delegation "$validator_self_delegation" '
{
    "pubkey": $pubkey,
    "amount": $amount,
    "moniker": $moniker,
    "commission-rate": $commission_rate,
    "commission-max-rate": $commission_max_rate,
    "commission-max-change-rate": $commission_max_change_rate,
    "min-self-delegation": $min_self_delegation
}' > validator.gen.json

minimum_gas_prices=`dasel -f $QADENAHOME/config/config.yml 'validators.first().app.minimum-gas-prices'`

qadenad_alias tx staking create-validator validator.gen.json  --from "$PIONEER" --gas-prices $minimum_gas_prices --gas auto --gas-adjustment $gas_adjustment --yes

if [[ $? != 0 ]] ; then
    echo "Failed to 'create-validator' for $PIONEER"
    exit 1
fi

echo "Waiting for $PIONEER in the validator list."

IS_UP=0
for i in {120..1}
do
    VALUE=$(qadenad_alias status 2>&1 | jq '.validator_info.pub_key.value')
    temp="${VALUE%\"}"
    temp="${temp#\"}"
    pubk=$temp
    echo "pubk $pubk"
  if qadenad_alias query tendermint-validator-set | grep $pubk  > /dev/null ; then
      echo "$PIONEER is a potential validator!"
      IS_UP=1
      break
  else
      echo "Not a validator yet, waiting...$i"
      sleep 1
  fi
done


if [ $IS_UP -eq 0 ] ; then
    echo "Couldn't wait for $PIONEER to be added as a potential validator."
    exit 1
fi
