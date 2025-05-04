#!/bin/zsh

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <json_file>"
    exit 1
fi

json_file="$1"

if [[ ! -f "$json_file" ]]; then
    echo "Error: JSON file '$json_file' not found."
    exit 1
fi

url="http://localhost/bulk-submit-kyc"

curl -X POST \
    -H "Content-Type: application/json" \
    --data-binary "@$json_file" \
    "$url"
