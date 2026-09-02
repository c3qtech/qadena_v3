#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

# Root only when an ego enclave will actually run: SGX hardware AND a signed binary.
needs_root_if_real_enclave "convert_to_validator.sh" "$qadenabin/qadenad_enclave"

VALIDATOR_STAKE="100000"
# Set by --foundation-sponsored: the granter address that pays this node's FEES.  It does not pay
# the self-bond -- see the note above the create-validator call.
FOUNDATION_GRANTER=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --validator-stake)
      if [[ -n "$2" && "$2" != --* ]]; then
        VALIDATOR_STAKE="$2"
        shift 2
      else
        echo "Error: --validator-stake requires an argument"
        exit 1
      fi
      ;;
    --foundation-sponsored)
      if [[ -n "$2" && "$2" != --* ]]; then
        FOUNDATION_GRANTER="$2"
        shift 2
      else
        FOUNDATION_GRANTER="any"
        shift
      fi
      ;;
    --help)
      echo "Usage: convert_to_validator.sh [--validator-stake <validator-stake> (in QDN)]"
      echo "                               [--foundation-sponsored [<granter-address>]]"
      echo ""
      echo "  --foundation-sponsored  pay this node's transaction FEES from a fee grant instead of"
      echo "                          from its own balance.  With no address, the granter is"
      echo "                          discovered from the grants already on chain for this node."
      echo "                          The SELF-BOND is still the node's own: a fee grant cannot"
      echo "                          supply staked principal, so the balance poll below still"
      echo "                          applies -- someone must have funded the stake."
      exit 0
      ;;      
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done


if [[ $VALIDATOR_STAKE == "" ]] ; then
    echo "Error: --validator-stake requires an argument (in QDN)"
    exit 1
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

# THE FLOOR COMES FROM config.yml, ALREADY IN aqdn.
#
# It is stored there as a bare integer in the BASE unit because IGNITE reads the same key for
# pioneer1's gentx and x/staking's CLI rejects anything else.  So there is no conversion to do here
# -- and no conversion to get wrong.  One value, one unit, read by ignite, by the genesis validator
# and by every joiner.  Hardcoded "1" before this.
#
# Falls back to 1aqdn when the key is absent, so an older config.yml still converts a node rather
# than failing -- the previous behaviour, not a new floor.
min_self_delegation_aqdn=`dasel -f $QADENAHOME/config/config.yml 'validators.first().app.min-self-delegation' 2>/dev/null | tr -d '"'`
if [[ -z "$min_self_delegation_aqdn" || "$min_self_delegation_aqdn" == "null" ]] ; then
    echo "convert_to_validator.sh: no validators.first().app.min-self-delegation in config.yml; using 1aqdn"
    validator_self_delegation="1"
    min_self_delegation_qdn=""
else
    validator_self_delegation="$min_self_delegation_aqdn"
    min_self_delegation_qdn=`echo "$min_self_delegation_aqdn / 1000000000000000000" | bc`
    echo "convert_to_validator.sh: min self-delegation ${min_self_delegation_aqdn}aqdn (${min_self_delegation_qdn}qdn)"
fi

# A SPONSORED NODE BONDS EXACTLY THE FLOOR, and no more.
#
# Its stake is sent by the sponsor (testscripts/foundation_sponsor_node.sh --self-bond for a single-key
# granter; the same --self-bond through a members' ceremony on a launch chain), so bonding the
# unsponsored default would mean moving eleven times as much QDN for no gain: what decides voting
# power on this fleet is the treasury delegation setup_prerequisites splits across all bonded
# validators right after, which is millions of QDN and dwarfs either figure.  Bond the minimum the
# chain will accept and let the delegation do the rest.
if [[ -n "$FOUNDATION_GRANTER" && -n "$min_self_delegation_qdn" && "$min_self_delegation_qdn" != "null" ]] ; then
    if [[ "$VALIDATOR_STAKE" != "$min_self_delegation_qdn" ]] ; then
        echo "convert_to_validator.sh: sponsored -- bonding the ${min_self_delegation_qdn}qdn floor instead of ${VALIDATOR_STAKE}qdn"
    fi
    VALIDATOR_STAKE="$min_self_delegation_qdn"
fi

VALIDATOR_STAKE_AQDN=`echo "$VALIDATOR_STAKE * 1000000000000000000" | bc`

echo "I will attempt to detect when $PIONEERADDRESS has at least ${VALIDATOR_STAKE}qdn."

IS_UP=0
for i in {120..1}
do
    BALANCE_JSON=`qadenad_alias query bank balances $PIONEERADDRESS --output json`
	BALANCE=`echo $BALANCE_JSON | jq -r '.balances[] | select(.denom=="aqdn") | .amount'`
    ret=`bc <<< "$BALANCE >= $VALIDATOR_STAKE_AQDN"`
    if [[ $ret = 1 ]] ; then
      BALANCE_QDN=`echo "$BALANCE / 1000000000000000000" | bc`
      echo "$PIONEER has enough balance (${BALANCE_QDN}qdn) to become a validator!"
      IS_UP=1
      break
    else
        BALANCE_QDN=`echo "$BALANCE / 1000000000000000000" | bc`
        echo "$PIONEER balance is ${BALANCE_QDN}qdn, not enough to become a validator (need to send ${VALIDATOR_STAKE}qdn).  Waiting...$i"
        echo "    $QADENAHOME/bin/qadenad --home $QADENAHOME tx bank send treasury $PIONEERADDRESS ${VALIDATOR_STAKE}qdn --yes"
        sleep 3
    fi
done

if [ $IS_UP -eq 0 ] ; then
    echo "Couldn't find balance for $PIONEERADDRESS"
    exit 1
fi

# create validator json
validator_pubkey=`qadenad_alias cometbft show-validator`
validator_amount="${VALIDATOR_STAKE}qdn"
validator_moniker="$PIONEER"
validator_commission_rate="0.10"
validator_commission_max_rate="0.20"
validator_commission_max_change_rate="0.01"
# THE SELF-BOND MUST BE AT LEAST THE FLOOR, or the chain rejects the message outright:
# MsgCreateValidator.Validate refuses Value.Amount < MinSelfDelegation.  Caught here, where the
# numbers are readable, rather than as an "invalid request" after the tx is built.
validator_stake_aqdn_check=`echo "$VALIDATOR_STAKE * 1000000000000000000" | bc`
if [[ `bc <<< "$validator_stake_aqdn_check < $validator_self_delegation"` == 1 ]] ; then
    echo "convert_to_validator.sh: Error: --validator-stake ${VALIDATOR_STAKE}qdn is below the"
    echo "  min-self-delegation of ${min_self_delegation_qdn}qdn in config.yml.  create-validator"
    echo "  would be rejected (Value.Amount < MinSelfDelegation).  Raise the stake or lower the floor."
    exit 1
fi

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

# THE FEES CAN BE SPONSORED; THE STAKE CANNOT.  x/feegrant separates who SIGNS from who PAYS FEES,
# and that is all it separates -- the self-bond is principal moving from this node's balance into
# its own delegation, so no grant can supply it.  Hence the balance poll above still runs under
# --foundation-sponsored: something must have funded the stake first.
#
# This is a stock SDK CLI path, so it does NOT go through x/qadena/client/tx and does not get the
# automatic granter discovery the enclave's broadcasts have.  The flag is passed explicitly here.
granter_flag=()
if [[ -n "$FOUNDATION_GRANTER" ]] ; then
    if [[ "$FOUNDATION_GRANTER" == "any" ]] ; then
        GRANT_JSON=`qadenad_alias query feegrant grants-by-grantee $PIONEERADDRESS --output json 2>/dev/null`
        FOUNDATION_GRANTER=`echo $GRANT_JSON | jq -r '.allowances[0].granter // ""' 2>/dev/null`
    fi
    if [[ -n "$FOUNDATION_GRANTER" && "$FOUNDATION_GRANTER" != "null" ]] ; then
        echo "convert_to_validator.sh: fees paid by $FOUNDATION_GRANTER (self-bond is still this node's own)"
        granter_flag=(--fee-granter "$FOUNDATION_GRANTER")
    else
        echo "convert_to_validator.sh: --foundation-sponsored, but no fee grant found for $PIONEERADDRESS; paying our own fees"
    fi
fi

qadenad_alias tx staking create-validator validator.gen.json  --from "$PIONEER" "${granter_flag[@]}" --gas-prices $minimum_gas_prices --gas auto --gas-adjustment $gas_adjustment --yes

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
