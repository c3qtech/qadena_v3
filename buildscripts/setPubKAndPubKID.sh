#!/bin/zsh

SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

genesisfile=$2
echo "setPubKAndPubKID $1 $genesisfile"
pubkid=$(qadenad_alias keys show $1 -a --keyring-backend test)
pubk=$(qadenad_alias keys show $1 -p --keyring-backend test)
#privkhex=$(qadenad query qadena export-private-key $1)
privkhex=$(echo "y" | qadenad_alias keys export $1 --unarmored-hex --unsafe --keyring-backend test)

if [[ $pubkid == "" || $pubk == "" || $privkhex == "" ]] ; then
    echo "FAILED TO GET KEYS"
    exit 1
fi

pubk=$(echo $pubk |  awk -F'"' '{print $8}')

#echo "changing pubkid=$pubkid pubk=$pubk"
#echo ${1}PubK

replacepubkid="s#${1}PubKID#${pubkid}#g"
replacepubk="s#${1}PubK_pubk#${pubk}#g"
replaceprivkhex="s#${1}PrivKHex#${privkhex}#g"
echo "replacepubkid $replacepubkid"

echo "$(uname -s)"
if [[ "$(uname -s)" == "Darwin" ]] then
  sed -i '' $replacepubkid $genesisfile
  sed -i '' $replacepubk $genesisfile
  sed -i '' $replaceprivkhex $genesisfile
elif [[ "$(uname -s)" == "Linux" ]] then
  sed -i "$replacepubkid" $genesisfile
  sed -i "$replacepubk" $genesisfile
  sed -i "$replaceprivkhex" $genesisfile
fi
