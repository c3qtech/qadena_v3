#!/bin/zsh

# Copy ssh keys to remote server

# parameters user@hostname_or_ip

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 user@hostname_or_ip"
    exit 1
fi

ssh-copy-id $1

scp setup_qadena_build.sh $1:

scp -r installers/ $1:

