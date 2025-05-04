#!/bin/zsh

file=$2
pioneerid=$1
echo "setPioneerID $pioneerid $file"

replacepioneerid="s#PioneerID#${pioneerid}#g"
echo "replacepioneerid $replacepioneerid"

echo "$(uname -s)"
if [[ "$(uname -s)" == "Darwin" ]] then
  sed -i '' $replacepioneerid $file
elif [[ "$(uname -s)" == "Linux" ]] then
  sed -i "$replacepioneerid" $file
fi
