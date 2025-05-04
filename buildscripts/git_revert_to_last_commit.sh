#!/bin/zsh

echo "WARNING!  This will remove *all* changes to local files in this repository and revert it to the last commit"
read REPLY\?"Are you sure? (y/N)"
if [[ $REPLY == "y" ]] ; then
    git checkout -f && git clean -fd
fi
