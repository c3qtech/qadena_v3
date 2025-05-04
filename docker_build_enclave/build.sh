#!/bin/zsh

# get scripts dir which is current dir ../scripts

SCRIPT_DIR="$(cd ../scripts && pwd)"

source "$SCRIPT_DIR/setup_env.sh"

rm -rf output
mkdir output
#chmod 777 output
cd ..

if docker buildx ls | grep -q '^enclave-builder'; then
  echo "✅ enclave-builder already exists"
else
  echo "⚠️ enclave-builder not found, creating..."
  docker buildx create --name enclave-builder --use --driver docker-container
  docker buildx inspect --bootstrap
fi


docker buildx build \
  --builder enclave-builder \
  -f docker_build_enclave/Dockerfile \
  --progress=plain \
  --output type=local,dest=./docker_build_enclave/output \
  .


if [ $? -ne 0 ] ; then
    echo "FAILED TO DO DOCKER BUILD"
    exit 1
fi
enclave_path="$(pwd)/cmd/qadenad_enclave"
cp docker_build_enclave/output/qadenad_enclave $enclave_path
#cp docker_build_enclave/output/qadenad_enclave.unsigned $enclave_path
cp docker_build_enclave/output/reproducible_build_signer_id.txt $enclave_path
cp docker_build_enclave/output/reproducible_build_unique_id.txt $enclave_path

if [ $? -ne 0 ] ; then
    echo "FAILED TO COPY CHAIN"
    exit 1
fi


