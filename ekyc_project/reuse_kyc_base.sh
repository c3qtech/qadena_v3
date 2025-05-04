#!/bin/zsh

provider=$1
phone=$2
from_provider=$3
last_name=$4
findpc=$5

echo "Begin KYC"

response=$(curl -s -f -X POST "http://localhost:80/ekyc/2.0.0/begin-kyc" \
-H "Content-Type: application/json" \
-d "{
    \"provider-name\": \"$provider\",
    \"phone-number\": \"$phone\"
}")

# Check if curl command was successful
if [ $? -eq 0 ]; then
    echo "Request succeeded"
else
    echo "Request failed"
    exit 1
fi

echo "Begin KYC $response"

# check if there is an error using jq

error=`echo $response | jq -r 'if .error then .error else "" end'`

if [ "$error" != "" ]; then
    echo "Error: $error"
    exit 1
fi

sessionid=`echo $response | jq -r 'if .["session-id"] then .["session-id"] else "" end'`

echo "Authenticate KYC"

response=$(curl -s -f -X POST "http://localhost:80/ekyc/2.0.0/authenticate-kyc" \
-H "Content-Type: application/json" \
-d "{
    \"from-provider-name\": \"$from_provider\",
    \"session-id\": \"$sessionid\",
    \"otp\": \"111111\",
    \"pin\": \"not used\",
    \"last-name\": \"$last_name\"
}")

# Check if curl command was successful
if [ $? -eq 0 ]; then
    echo "Request succeeded"
else
    echo "Request failed"
    exit 1
fi


echo "Authenticate KYC $response"

error=`echo $response | jq -r 'if .error then .error else "" end'`

if [ "$error" != "" ]; then
    echo "Error: $error"
    exit 1
fi

sessionid=`echo $response | jq -r 'if .["session-id"] then .["session-id"] else "" end'`

reusable=`echo $response | jq '.reusable'`

from_provider_name=`echo $response | jq -r '.["from-provider-name"]'`

#echo $from_provider_name
#echo $provider

if [ "$from_provider_name" = $provider ]; then
    echo "This credential already exists for the provider $provider."
    exit 1
fi


#exit 1

if [ "$reusable" = "false" ]; then
    echo "Not reusable"
    exit 1
fi

if [ "$findpc" = "" ]; then
    echo "Confirm KYC"
    response=$(curl -s -f -X POST "http://localhost:80/ekyc/2.0.0/confirm-reuse-kyc" \
    -H "Content-Type: application/json" \
    -d "{
        \"session-id\": \"$sessionid\"
    }")
else
    echo "Confirm KYC with user-supplised FindPC"
    response=$(curl -s -f -X POST "http://localhost:80/ekyc/2.0.0/confirm-reuse-kyc" \
    -H "Content-Type: application/json" \
    -d "{
        \"session-id\": \"$sessionid\",
        \"user-claim-pc\": \"$findpc\"
    }")
fi

# Check if curl command was successful
if [ $? -eq 0 ]; then
    echo "Request succeeded"
else
    echo "Request failed"
    exit 1
fi

echo "Confirm Reuse KYC $response"

error=`echo $response | jq -r 'if .error then .error else "" end'`

if [ "$error" != "" ]; then
    echo "Error: $error"
    exit 1
fi

echo "Success"





