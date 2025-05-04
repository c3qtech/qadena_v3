#!/bin/zsh

if [[ "$(uname -s)" == "Darwin" ]] ; then
    if=$(route -n get 1.1.1.1 2>/dev/null | awk '/interface: / {print $2}')

else
    if=$(ip route get 1.1.1.1 | awk '{print $5; exit}')
fi

if [ -n "$if" ]; then
    ip=$(ifconfig $if | awk '/inet /&&!/127.0.0.1/{print $2}')
    echo "$ip"
else
    echo "Couldn't find default IP"
    exit 1
fi
