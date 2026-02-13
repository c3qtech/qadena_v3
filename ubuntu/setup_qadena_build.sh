#!/bin/sh

DASEL_VERSION=2.8.1
# Get the first 'go x.y.z' directive from go.mod
GO_VERSION=$(awk '$1 == "go" { print $2; exit }' go.mod)
IGNITE_VERSION=29.8.0

echo "Required GO_VERSION: $GO_VERSION"
echo "Required IGNITE_VERSION: $IGNITE_VERSION"
echo "Required DASEL_VERSION: $DASEL_VERSION"

PATH=$PATH:/usr/local/go/bin

# need to "sudo" this file
if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root (use sudo)"
  exit 1
fi

# set noninteractive for apt
export DEBIAN_FRONTEND=noninteractive

# zsh
# check if zsh is installed
if ! command -v zsh &> /dev/null; then
    apt-get install -y zsh
fi

# check if git is installed
if ! command -v git &> /dev/null; then
    apt-get install -y git
fi

# remove installers if exists
rm -rf installers
mkdir installers
 
# go-lang
# wget https://go.dev/dl/go1.23.12.linux-arm64.tar.gz
# wget https://go.dev/dl/go1.23.12.linux-amd64.tar.gz

# figure out based on the cpu and download the correct go version, get this from go.mod

# check installed go version
INSTALLED_GO_VERSION=""
if command -v go > /dev/null 2>&1; then
    # "go version" prints like: "go version go1.23.7 linux/amd64"
    INSTALLED_GO_VERSION=$(go version 2>/dev/null | awk '{print $3}' | sed 's/^go//')
fi

if [ -z "$INSTALLED_GO_VERSION" ] || [ "$INSTALLED_GO_VERSION" != "$GO_VERSION" ]; then

    # put it in installers
    if [ "$(uname -m)" = "aarch64" ]; then
        (cd installers; wget https://go.dev/dl/go${GO_VERSION}.linux-arm64.tar.gz; rm -rf /usr/local/go && tar -C /usr/local -xzf go${GO_VERSION}.linux-arm64.tar.gz)
    elif [ "$(uname -m)" = "arm64" ]; then
        (cd installers; wget https://go.dev/dl/go${GO_VERSION}.darwin-arm64.tar.gz; rm -rf /usr/local/go && tar -C /usr/local -xzf go${GO_VERSION}.darwin-arm64.tar.gz)
    else
        (cd installers; wget https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz; rm -rf /usr/local/go && tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz)
    fi

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

fi

# check if curl exists
if ! command -v curl &> /dev/null; then
    apt-get install -y curl
fi

# check if rotatelogs exists
if ! command -v rotatelogs &> /dev/null; then
    apt install -y apache2-utils
fi


# sgx if on intel
if [ "$(uname -m)" = "x86_64" ]; then
    mkdir -p /etc/apt/keyrings
    wget -qO- https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | tee /etc/apt/keyrings/intel-sgx-keyring.asc > /dev/null
    echo "deb [signed-by=/etc/apt/keyrings/intel-sgx-keyring.asc arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/intel-sgx.list
    apt update
    apt install -y libsgx-dcap-default-qpl

    # check if running in Azure using "curl -H Metadata:true "http://169.254.169.254/metadata/instance?api-version=2021-02-01""
    if curl -m 4 -H Metadata:true "http://169.254.169.254/metadata/instance?api-version=2021-02-01" > /dev/null 2>&1 ; then
        echo "Running in Azure, installing a default sgx_default_qcnl.conf that points to Azure PCCS"
        cp azure_sgx_default_qcnl.conf /etc/sgx_default_qcnl.conf
    else
        echo "Not running in Azure, not installing a default sgx_default_qcnl.conf"
    fi

    # ego
    (cd installers; apt install -y ./ego_1.7.0_amd64_ubuntu-22.04.deb)
    apt install -y build-essential libssl-dev
fi


# ignite
# wget https://github.com/ignite/cli/releases/download/v28.8.2/ignite_28.8.2_linux_arm64.tar.gz

# check installed version by parsing "Ignite CLI version:" line
INSTALLED_IGNITE=""
if command -v ignite &> /dev/null; then
    INSTALLED_IGNITE=$(ignite version 2>&1 | grep "Ignite CLI version:" | awk '{print $NF}')
    echo "Installed Ignite CLI version: $INSTALLED_IGNITE"
fi

if [ "$INSTALLED_IGNITE" != "v${IGNITE_VERSION}" ] && [ "$INSTALLED_IGNITE" != "v${IGNITE_VERSION}-dev" ]; then
    # detect OS
    case "$(uname -s)" in
        Darwin) IGNITE_OS="darwin" ;;
        Linux)  IGNITE_OS="linux" ;;
        *)      echo "Unsupported OS: $(uname -s)"; exit 1 ;;
    esac

    # detect arch
    case "$(uname -m)" in
        x86_64)       IGNITE_ARCH="amd64" ;;
        aarch64|arm64) IGNITE_ARCH="arm64" ;;
        *)            echo "Unsupported arch: $(uname -m)"; exit 1 ;;
    esac

    IGNITE_TAR="ignite_${IGNITE_VERSION}_${IGNITE_OS}_${IGNITE_ARCH}.tar.gz"
    echo "Installing ignite $IGNITE_VERSION (current: $INSTALLED_IGNITE) - $IGNITE_TAR"
    (cd installers; wget https://github.com/ignite/cli/releases/download/v${IGNITE_VERSION}/${IGNITE_TAR})
    (cd installers; tar -xvf ./${IGNITE_TAR} -C /usr/local/bin)
else
    echo "Ignite $INSTALLED_IGNITE already installed"
fi

# check if jq installed
if ! command -v jq &> /dev/null; then
    apt-get install -y jq
fi

# check if ifconfig installed
if ! command -v ifconfig &> /dev/null; then
    apt-get install -y net-tools
fi

# check if rotatelogs installed
if ! command -v rotatelogs &> /dev/null; then

    apt-get install -y apache2-utils
fi

# if Linux, check if docker installed
if [ "$(uname -s)" = "Linux" ]; then
    if ! command -v docker &> /dev/null; then
        apt-get update
        apt-get install -y ca-certificates curl
        install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc

    # Add the repository to Apt sources:
    echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
    $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" | \
    tee /etc/apt/sources.list.d/docker.list > /dev/null
    apt-get update

    # check if ubuntu 22 or 24
    if command -v lsb_release >/dev/null 2>&1; then
        DISTRO=$(lsb_release -is)
        VERSION=$(lsb_release -rs)
        
        if [ "$DISTRO" = "Ubuntu" ]; then
            if [ "$VERSION" = "22.04" ]; then
                echo "Ubuntu 22.04 detected"
                VERSION_STRING=5:28.0.4-1~ubuntu.22.04~jammy
            elif [ "$VERSION" = "24.04" ]; then
                echo "Ubuntu 24.04 detected"
                VERSION_STRING=5:28.0.4-1~ubuntu.24.04~noble
            else
                echo "Ubuntu detected, but not version 22.04 or 24.04"
            fi
        else
            echo "Not Ubuntu"
        fi
    else
        echo "lsb_release not installed, cannot determine distribution"
    fi


    apt-get install -y docker-ce=$VERSION_STRING docker-ce-cli=$VERSION_STRING containerd.io docker-buildx-plugin docker-compose-plugin
    # check if the above failed
    if [ $? -ne 0 ]; then
        echo "Failed to install docker"
        exit 1
    fi

    groupadd docker
    usermod -aG docker $SUDO_USER
fi

# dasel
# go install github.com/tomwright/dasel/v2/cmd/dasel@master
# cp ~/go/bin/dasel /usr/local/bin

# check if dasel version is correct (relaxed: accept any 2.8.x)
INSTALLED_DASEL="$(dasel --version 2>/dev/null || true)"

if ! command -v dasel >/dev/null 2>&1 \
  || ! printf '%s\n' "$INSTALLED_DASEL" | grep -Eq "(^|[^0-9])${DASEL_VERSION//./\\.}([^0-9]|$)"; then

  # Ensure go is available
  command -v go >/dev/null 2>&1 || { echo "go not found in PATH"; exit 1; }

  go install "github.com/tomwright/dasel/v2/cmd/dasel@v${DASEL_VERSION}"

  # Put it somewhere global
  install -m 0755 "$HOME/go/bin/dasel" /usr/local/bin/dasel
fi

echo "Now you need to:"
echo "  exit"
echo "...then log back in..."
echo "  cd qadena_v3"
echo "  buildscripts/init.sh   OR   buildscripts/build.sh"
echo "...then when done..."
echo "  scripts/run.sh"
