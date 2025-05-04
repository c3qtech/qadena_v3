#!/bin/zsh

provider=$1
phone=$2
from_provider=$3
last_name=$4

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

reusable=`echo $response | jq -r 'if .["reusable"] then .["reusable"] else "" end'`

if [ "$reusable" = "true" ]; then
    echo "Reusable, stop."
    exit 1
fi

response=$(curl -s -f -X POST "http://localhost:80/ekyc/2.0.0/confirm-new-kyc" \
    -H "Content-Type: application/json" \
    -d "{
        \"session-id\": \"$sessionid\"
    }")

# Check if curl command was successful
if [ $? -eq 0 ]; then
    echo "Request succeeded"
else
    echo "Request failed"
    exit 1
fi

echo "Confirm New KYC $response"

error=`echo $response | jq -r 'if .error then .error else "" end'`

if [ "$error" != "" ]; then
    echo "Error: $error"
    exit 1
fi

referenceid=`echo $response | jq -r 'if .["referenceID"] then .["referenceID"] else "" end'`

echo "Reference ID: $referenceid"

if [ "$referenceid" = "" ]; then
    echo "Reference ID is empty"
    exit 1
fi

response=$(curl -s -f -X GET "http://localhost:80/ekyc/2.0.0/collect-new-kyc/$referenceid")

# Check if curl command was successful
if [ $? -eq 0 ]; then
    echo "Request succeeded"
else
    echo "Request failed"
    exit 1
fi


echo "HTML response"
echo $response





