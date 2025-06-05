#!/bin/sh

# need to "sudo" this file
if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root (use sudo)"
  exit 1
fi

# zsh
apt-get install -y zsh

# git
apt-get install -y git

# get the installers from git

git clone https://github.com/c3qtech/qadena_installers.git installers


# go
rm -rf /usr/local/go && tar -C /usr/local -xzf installers/go1.23.4.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
echo "Original user's home: $USER_HOME"

LINE="export PATH=\$PATH:$USER_HOME/go/bin:/usr/local/go/bin"
FILE="$USER_HOME/.profile"

if ! grep -qxF "$LINE" "$FILE"; then
  echo "$LINE" >> "$FILE"
  echo "✅ Added to .profile"
else
  echo "ℹ️ Already in .profile"
fi

# curl
apt-get install -y curl

# rotatelogs
apt install -y apache2-utils


# sgx
mkdir -p /etc/apt/keyrings
wget -qO- https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | tee /etc/apt/keyrings/intel-sgx-keyring.asc > /dev/null
echo "deb [signed-by=/etc/apt/keyrings/intel-sgx-keyring.asc arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/intel-sgx.list
apt update
apt install -y libsgx-dcap-default-qpl

# ego
(cd installers; apt install -y ./ego_1.7.0_amd64_ubuntu-22.04.deb)
apt install -y build-essential libssl-dev

# ignite
(cd installers; tar -xvf ./ignite_28.8.2_linux_amd64.tar.gz -C /usr/local/bin)

apt-get install -y jq

# Add Docker's official GPG key:
apt-get update
apt-get install ca-certificates curl
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to Apt sources:
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" | \
  tee /etc/apt/sources.list.d/docker.list > /dev/null
apt-get update

VERSION_STRING=5:28.0.4-1~ubuntu.22.04~jammy
apt-get install -y docker-ce=$VERSION_STRING docker-ce-cli=$VERSION_STRING containerd.io docker-buildx-plugin docker-compose-plugin

groupadd docker
usermod -aG docker $SUDO_USER

(cd installers; gunzip dasel.gz; cp -f dasel /usr/local/bin)

#git clone https://github.com/c3qtech/qadena_v2.git
#chown -R "$SUDO_UID:$SUDO_GID" qadena_v2
#cd qadena_v2
#git config credential.helper store

echo "Now you need to:"
echo "  exit"
echo "...then log back in..."
echo "  cd qadena_v2"
echo "  ./init.sh   OR   ./build.sh"