docker buildx rm enclave-builder
docker buildx rm chain-builder
docker ps -a --filter name=buildx_buildkit_ --format '{{.Names}}' | xargs -r docker rm -f
docker volume ls --filter name=buildx_buildkit_ --format '{{.Name}}' | xargs -r docker volume rm
