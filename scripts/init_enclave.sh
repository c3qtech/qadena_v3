#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

VALUE=`qadenad_alias status | jq '.node_info.moniker'`
temp="${VALUE%\"}"
temp="${temp#\"}"
echo "init_enclave.sh: PIONEER=$temp"
PIONEER=$temp

JARID="jar1"
REGULATORID="regulator1"

if [[ $1 == "help" ]] ; then
    echo "init_enclave.sh: Usage:  init_enclave.sh [jar-id] [regulator-id]"
    echo "init_enclave.sh:  jar-id default: $JARID"
    echo "init_enclave.sh:  regulator-id default: $REGULATORID"
    exit 1
fi

if [[ $1 != "" ]] ; then
    JARID=$1
fi

if [[ $2 != "" ]] ; then
    REGULATORID=$2
fi


if [[ $PIONEER == "" ]] ; then
    echo "init_enclave.sh: Unable to get the pioneer's moniker"
    exit 1
fi


EXT_ADDR=`$qadenascripts/get_external_address.sh`

if [[ $EXT_ADDR == "" ]] ; then
    echo "init_enclave.sh: Error, config.toml's external_address is not defined.  Try running init.sh"
    exit 1
fi

if use_real_enclave "$qadenabin/qadenad_enclave" ; then
    echo "init_enclave.sh: Real enclave detected"

    # EGO REPORTS FAILURE ON STDOUT, not stderr -- `ego signerid missing-file` prints
    # "ERROR: reading key file: ..." to stdout, exits 1, and puts only its INFO banner on stderr.
    # Backtick capture therefore swallows the failure into the variable, and the line below used to
    # announce "Extracted signer id ...: ERROR: reading key file: ...".  A log full of the word
    # "Extracted" is how a missing public.pem stayed invisible.  Check the status, say what happened.
    SIGNER_ID=`ego signerid $QADENAHOME/config/public.pem` || SIGNER_ID=""
    if [[ -z "$SIGNER_ID" || "$SIGNER_ID" == ERROR:* ]]; then
        # STOP HERE.  Carrying on produces a command line that is wrong in a way that names nothing:
        # the arguments below are unquoted, so an empty SIGNER_ID makes --enclave-signer-id swallow
        # --enclave-unique-id as its value, every positional shifts left, and cobra reports
        # "accepts 4 arg(s), received 5".  Nothing in that message mentions public.pem.
        echo "init_enclave.sh: FAILED to read a signer id from $QADENAHOME/config/public.pem"
        echo "init_enclave.sh: ($SIGNER_ID)"
        echo "init_enclave.sh:"
        echo "init_enclave.sh: That file is installed with the binaries and is not node state."
        echo "init_enclave.sh: Reinstall it:  scripts/install_release.sh <package>"
        echo "init_enclave.sh: or copy it from cmd/qadenad_enclave/public.pem in a build tree."
        exit 1
    else
        echo "init_enclave.sh: Extracted signer id from $QADENAHOME/config/public.pem: $SIGNER_ID"
    fi

    UNIQUE_ID=`ego uniqueid $qadenabin/qadenad_enclave` || UNIQUE_ID=""
    if [[ -z "$UNIQUE_ID" || "$UNIQUE_ID" == ERROR:* ]]; then
        echo "init_enclave.sh: FAILED to read a unique id from $qadenabin/qadenad_enclave"
        echo "init_enclave.sh: ($UNIQUE_ID)"
        echo "init_enclave.sh: is that an ego-signed enclave?  A debug build has no measurement."
        exit 1
    else
        echo "init_enclave.sh: Extracted unique id from $qadenabin/qadenad_enclave: $UNIQUE_ID"
    fi
else
    SIGNER_ID="*"
    UNIQUE_ID="*"
fi

# QUOTED.  Unquoted, an empty or multi-word id silently reshapes the whole command line -- the flag
# takes the next flag as its value and the positionals shift, so the error names an argument count
# rather than the thing that was actually missing.
qadenad_alias enclave init-enclave --enclave-signer-id "$SIGNER_ID" --enclave-unique-id "$UNIQUE_ID" "$PIONEER" "$EXT_ADDR" "$JARID" "$REGULATORID"
RET=$?
if [[ $RET != 0 ]] ; then
    echo "init_enclave.sh: qadenad enclave init-enclave failed, need to kill qadenad, qadenad_enclave and signer_enclave"
    pkill -INT -f "qadenad"
    pkill -INT -f "qadenad_enclave"
    pkill -INT -f "signer_enclave"
    exit 1
fi

exit 0
