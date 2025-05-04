#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"


if $qadenatestscripts/setup_wallets.sh ; then
    echo "Wallets setup successfully"
else
    echo "Failed to setup wallets"
    exit 1
fi

if $qadenatestscripts/setup_credentials.sh ; then
    echo "Credentials setup successfully"
else
    echo "Failed to setup credentials"
    exit 1
fi

if $qadenatestscripts/setup_bind_credentials.sh ; then
    echo "Bind credentials setup successfully"
else
    echo "Failed to setup bind_credentials"
    exit 1
fi


if $qadenatestscripts/setup_protect_key.sh ; then
    echo "Protect key setup successfully"
else
    echo "Failed to setup protect key"
    exit 1
fi

if $qadenatestscripts/setup_dsvs.sh ; then
    echo "DSVS setup successfully"
else
    echo "Failed to setup DSVS"
    exit 1
fi

