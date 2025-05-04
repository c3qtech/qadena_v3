#!/bin/zsh

# get script dir
SCRIPT_DIR="$(cd ../scripts && pwd)"

source "$SCRIPT_DIR/setup_env.sh"

rm -rf output
mkdir output
cd ..

if docker buildx ls | grep -q '^chain-builder'; then
  echo "✅ chain-builder already exists"
else
  echo "⚠️ chain-builder not found, creating..."
  docker buildx create --name chain-builder --use --driver docker-container
  docker buildx inspect --bootstrap
fi

docker buildx build \
  --builder chain-builder \
  -f docker_build_chain/Dockerfile \
  --progress=plain \
  --output type=local,dest=./docker_build_chain/output \
  .

#DOCKER_BUILDKIT=1 docker build --output type=local,dest=./docker_build_chain/output,uid=0,gid=0 -f docker_build_chain/Dockerfile --progress=plain .

if [ $? -ne 0 ] ; then
    echo "FAILED TO DO DOCKER BUILD"
    exit 1
fi
cp docker_build_chain/output/qadenad $qadenabuild/cmd/qadenad/qadenad
if [ $? -ne 0 ] ; then
    echo "FAILED TO COPY CHAIN"
    exit 1
fi


