#!/bin/sh

DASEL_VERSION=2.8.1
# Get the first 'go x.y.z' directive from go.mod

if [ ! -f go.mod ]; then
    echo "Error: go.mod not found in current directory."
    echo "This script must be run from the main Qadena directory (repo root) where go.mod is located."
    exit 1
fi

GO_VERSION=$(awk -F: '/^[[:space:]]*\/\/[[:space:]]*VERSION[[:space:]]*:/ { gsub(/[[:space:]]/, "", $2); print $2; exit }' go.mod)
if [ -z "$GO_VERSION" ]; then
    GO_VERSION=$(awk '$1 == "go" { print $2; exit }' go.mod)
fi
# The version whose GENERATED OUTPUT the committed .pb.go files match.  Measured 2026-08-18: the
# Mac ran module v29.7.0 and regenerated clean, M1 ran v29.8.0 and rewrote nine .pb.go files
# (v29.8.0 drops a `var X_serviceDesc = _X_serviceDesc` alias per service file).  Changing this
# means regenerating and committing the result, deliberately -- not discovering it mid-build.
IGNITE_VERSION=29.7.0

EGO_GO_VERSION=go1.25.6

echo "Required GO_VERSION: $GO_VERSION"
echo "Required IGNITE_VERSION: $IGNITE_VERSION"
echo "Required DASEL_VERSION: $DASEL_VERSION"
echo "Required EGO_GO_VERSION: $EGO_GO_VERSION"

PATH=$PATH:/usr/local/go/bin

apt update

# need to "sudo" this file
if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root (use sudo)"
  exit 1
fi

# set noninteractive for apt
export DEBIAN_FRONTEND=noninteractive

# zsh
# check if zsh is installed
if ! command -v zsh > /dev/null 2>&1; then
    echo "Installing zsh"
    apt-get install -y zsh
else
    echo "zsh already installed"
fi

# check if git is installed
if ! command -v git > /dev/null 2>&1; then
    echo "Installing git"
    apt-get install -y git
else
    echo "git already installed"
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


    USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    echo "Original user's home: $USER_HOME"

    export PATH=$PATH:/usr/local/go/bin:$USER_HOME/go/bin


    LINE="export PATH=\$PATH:$USER_HOME/go/bin:/usr/local/go/bin"
    FILE="$USER_HOME/.profile"

    if ! grep -qxF "$LINE" "$FILE"; then
    echo "$LINE" >> "$FILE"
    echo "✅ Added to .profile"
    else
    echo "ℹ️ Already in .profile"
    fi

else
    echo "Go $INSTALLED_GO_VERSION already installed"
    export PATH=$PATH:$USER_HOME/go/bin:/usr/local/go/bin
fi



# check if curl exists
if ! command -v curl > /dev/null 2>&1; then
    apt-get install -y curl
fi

# check if rotatelogs exists
if ! command -v rotatelogs > /dev/null 2>&1; then
    apt install -y apache2-utils
fi


# sgx if on intel
if [ "$(uname -m)" = "x86_64" ]; then
    mkdir -p /etc/apt/keyrings
    wget -qO- https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | tee /etc/apt/keyrings/intel-sgx-keyring.asc > /dev/null
    echo "deb [signed-by=/etc/apt/keyrings/intel-sgx-keyring.asc arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/intel-sgx.list
    apt update
    rm -f /etc/sgx_default_qcnl.conf
    apt install -y libsgx-dcap-default-qpl

    # DEVICE ACCESS FOR THE BUILD USER -- this is what makes running the node as root unnecessary.
    #
    # /dev/sgx_enclave is mode 660 root:sgx, and /dev/sgx_provision is root:sgx_prv -- a DIFFERENT
    # group, which is the part that catches people out.  Missing the first, an enclave cannot be
    # created at all.  Missing only the second, the node starts and runs perfectly and then fails
    # REMOTE ATTESTATION, far from anything that names a permission.
    #
    # The group is read from the device when it exists, rather than assumed, because the names are
    # set by whichever driver package created it.
    if [ -n "$SUDO_USER" ]; then
        sgx_groups=""
        for dev in /dev/sgx_enclave /dev/sgx_provision; do
            if [ -e "$dev" ]; then
                sgx_groups="$sgx_groups $(stat -c %G "$dev" 2>/dev/null)"
            fi
        done
        # No devices yet (driver not loaded, or a machine without SGX): fall back to the standard
        # names so a later reboot finds the user already in them.
        # This script is /bin/sh, so no ${var// /} and no ${=var} -- unquoted $var word-splits here.
        if [ -z "$(echo "$sgx_groups" | tr -d ' ')" ]; then
            sgx_groups="sgx sgx_prv"
        fi

        for grp in $sgx_groups; do
            [ -n "$grp" ] || continue
            if ! getent group "$grp" > /dev/null 2>&1; then
                echo "Group $grp does not exist yet; it is created with the SGX driver -- re-run this script after a reboot"
                continue
            fi
            if id -nG "$SUDO_USER" 2>/dev/null | tr ' ' '\n' | grep -qx "$grp"; then
                echo "$SUDO_USER is already in group $grp"
            else
                echo "Adding $SUDO_USER to group $grp (needed to use the SGX device without root)"
                usermod -aG "$grp" "$SUDO_USER"
            fi
        done
    else
        echo "SUDO_USER is not set, so no user was added to the SGX groups; the node will need root"
    fi

    installed_sgx_default_qcnl_conf=false

    # check if running in Azure using "curl -H Metadata:true "http://169.254.169.254/metadata/instance?api-version=2021-02-01""
    if curl -m 4 -H Metadata:true "http://169.254.169.254/metadata/instance?api-version=2021-02-01" > /dev/null 2>&1 ; then
        # pccs_url and local_pck_url point at Azure (THIM via IMDS) because that is how an Azure VM
        # gets its OWN platform certificates.  collateral_service deliberately does NOT: it points at
        # Intel's PCS.
        #
        # A cloud cache only holds collateral for that cloud's own machines.  With collateral_service
        # left on global.acccache.azure.net, this VM can verify quotes from other Azure machines and
        # FAILS on anything from on-prem -- OE_QUOTE_PROVIDER_CALL_ERROR, while the cache is
        # perfectly reachable, so it reads like a network fault and is not one.  In a chain whose
        # nodes span Azure and on-prem, every node must be able to verify every other node's enclave.
        #
        # Verified on a live Azure SGX VM: with this change it verifies on-prem quotes, and its own
        # quote generation is unaffected because that path uses local_pck_url.
        echo "Running in Azure: installing sgx_default_qcnl.conf (Azure PCCS for our own certs, Intel PCS for verifying others)"
        cp ubuntu/azure_sgx_default_qcnl.conf /etc/sgx_default_qcnl.conf
        installed_sgx_default_qcnl_conf=true
    else
        echo "Not running in Azure, not installing a default sgx_default_qcnl.conf"
    fi

    # check if running in Alicloued
    if curl --max-time 3 -s "http://100.100.100.200/latest/meta-data/instance/instance-type" > /dev/nulll 2>&1 ; then
        echo "Running in Alibaba, installing a default sgx_default_qcnl.conf that points to Alibaba PCCS"
        # View the region of the instance.
        token=$(curl -s -X PUT -H "X-aliyun-ecs-metadata-token-ttl-seconds: 5" "http://100.100.100.200/latest/api/token")
        region_id=$(curl -s -H "X-aliyun-ecs-metadata-token: $token" http://100.100.100.200/latest/meta-data/region-id)

        # Specify the URL of Alibaba Cloud Provisioning Certificate Caching Service (PCCS) for the region in which the instance is deployed.
        PCCS_URL=https://sgx-dcap-server-vpc.${region_id}.aliyuncs.com/sgx/certification/v4/
        cat > '/etc/sgx_default_qcnl.conf' << EOF
# PCCS server address
PCCS_URL=${PCCS_URL}
# To accept insecure HTTPS cert, set this option to FALSE
USE_SECURE_CERT=TRUE
EOF
        installed_sgx_default_qcnl_conf=true

    else
        echo "Not running in Alibaba, not installing a default sgx_default_qcnl.conf"
    fi

    if [ "$installed_sgx_default_qcnl_conf" = false ]; then
        echo "No cloud-specific sgx_default_qcnl.conf installed yet, will install a default sgx_default_qcnl.conf"
        cp ubuntu/sgx_default_qcnl.conf /etc/sgx_default_qcnl.conf
    fi

    # ego
    # check if ego-go version is installed
    INSTALLED_EGO_GO_VERSION=""
    if command -v ego-go > /dev/null 2>&1; then
        INSTALLED_EGO_GO_VERSION=$(ego-go version 2>&1 | awk '{print $3}')
    fi

    if [ -z "$INSTALLED_EGO_GO_VERSION" ] || [ "$INSTALLED_EGO_GO_VERSION" != "$EGO_GO_VERSION" ]; then
        (cd installers; wget https://github.com/edgelesssys/ego/releases/download/v1.8.1/ego_1.8.1_amd64_ubuntu-22.04.deb; apt install -y ./ego_1.8.1_amd64_ubuntu-22.04.deb)
    else
        echo "ego-go $INSTALLED_EGO_GO_VERSION already installed"
    fi
    apt install -y build-essential libssl-dev
fi

# check if /usr/local/bin/protoc-gen-grpc-gateway exists
if [ ! -f /usr/local/bin/protoc-gen-grpc-gateway ]; then
    echo "Need to install protoc-gen-grpc-gateway version 1.16.0"
    go install github.com/grpc-ecosystem/grpc-gateway/protoc-gen-grpc-gateway@v1.16.0
    # Put it somewhere global
    install -m 0755 "$HOME/go/bin/protoc-gen-grpc-gateway" /usr/local/bin/protoc-gen-grpc-gateway
fi

# check if /usr/local/bin/protoc-gen-openapiv2 exists
if [ ! -f /usr/local/bin/protoc-gen-openapiv2 ]; then
    echo "Need to install protoc-gen-openapiv2 version 2.28.0"
    go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2@v2.28.0
    # Put it somewhere global
    install -m 0755 "$HOME/go/bin/protoc-gen-openapiv2" /usr/local/bin/protoc-gen-openapiv2
fi

# protoc-gen-gocosmos: PINNED TO THE VERSION IN go.mod, AND CHECKED BY VERSION, NOT EXISTENCE.
#
# This was `@latest` behind an `[ ! -f ]` test, and both halves were wrong:
#
#   @latest      baked in whatever was newest the day a machine was provisioned.  Measured
#                2026-08-18: the Mac had gogoproto v1.7.0, M1 had v1.4.12, and go.mod asks for
#                v1.7.2 -- three answers, none of them the project's.
#   [ ! -f ]     existence is not a version.  A machine provisioned two years ago is never
#                updated, because the file is there.
#
# The consequence is not cosmetic.  v1.4.12 emits an extra `var X_serviceDesc = _X_serviceDesc`
# alias per service file, so `ignite generate proto-go` rewrites nine .pb.go files, the tree goes
# dirty, and package_release.sh correctly refuses artifacts that "correspond to no commit" --
# which blocked phase 7 of 1st_node_bringup.sh on every run.  It is invisible until packaging.
#
# NOTE: THIS PLUGIN IS NOT WHAT IGNITE GENERATES WITH.  buf.gen.gogo.yaml names `gocosmos`, but
# hiding the binary entirely and running `ignite generate proto-go` still succeeds -- ignite supplies
# its own, cached under ~/.ignite.  Pinning it is still right for anyone invoking buf directly, and
# `@latest` behind an `[ ! -f ]` test was wrong regardless, but do not expect this to fix a codegen
# mismatch: see the cache note in the ignite block below, which is what actually decides the output.
#
# The version comes from go.mod so the two cannot drift apart again, and the check mirrors how
# ignite itself is handled twenty lines below: compare, then reinstall if it differs.
GOCOSMOS_VERSION=$(awk '$1 == "github.com/cosmos/gogoproto" { print $2; exit }' go.mod 2>/dev/null)
if [ -z "$GOCOSMOS_VERSION" ]; then
    echo "WARNING: could not read github.com/cosmos/gogoproto from go.mod; skipping the protoc-gen-gocosmos pin."
    echo "         Generated .pb.go files may not match the committed ones."
else
    INSTALLED_GOCOSMOS=""
    if [ -f /usr/local/bin/protoc-gen-gocosmos ]; then
        # `go version -m` reports the module that built a binary -- the only reliable way to ask a
        # plugin what it is.  Comparing file existence, or the binary's own hash across platforms,
        # answers a different question.
        INSTALLED_GOCOSMOS=$(go version -m /usr/local/bin/protoc-gen-gocosmos 2>/dev/null \
            | awk '$1 == "mod" && $2 == "github.com/cosmos/gogoproto" { print $3; exit }')
    fi
    if [ "$INSTALLED_GOCOSMOS" != "$GOCOSMOS_VERSION" ]; then
        echo "Installing protoc-gen-gocosmos $GOCOSMOS_VERSION (current: ${INSTALLED_GOCOSMOS:-none})"
        go install "github.com/cosmos/gogoproto/protoc-gen-gocosmos@$GOCOSMOS_VERSION"
        # Put it somewhere global
        install -m 0755 "$HOME/go/bin/protoc-gen-gocosmos" /usr/local/bin/protoc-gen-gocosmos
    else
        echo "protoc-gen-gocosmos $INSTALLED_GOCOSMOS already installed"
    fi
fi


# ignite
# wget https://github.com/ignite/cli/releases/download/v28.8.2/ignite_28.8.2_linux_arm64.tar.gz

# THE MODULE VERSION, NOT THE DISPLAYED ONE.
#
# `ignite version` prints a string baked into the source at build time.  Every machine here printed
# `v29.10.1-dev` while running DIFFERENT code: module v29.7.0 on the Mac, v29.8.0 on M1.  So the old
# comparison against "v${IGNITE_VERSION}" could neither recognise a correct install nor detect a
# wrong one -- it just always disagreed, and the difference it could not see is precisely the one
# that rewrites .pb.go and blocks packaging.
#
# `go version -m` reports the module a Go binary was built from, which is the field that varies.
# It works for a release tarball and a source build alike.
INSTALLED_IGNITE=""
echo "Checking if ignite is installed"
if command -v ignite > /dev/null 2>&1; then
    INSTALLED_IGNITE=$(go version -m "$(command -v ignite)" 2>/dev/null \
        | awk '$1 == "mod" && $2 == "github.com/ignite/cli/v29" { print $3; exit }')
    echo "Installed ignite module: ${INSTALLED_IGNITE:-unknown} (displays: $(sudo -u "$SUDO_USER" env PATH="/usr/local/bin:/usr/local/go/bin:$PATH" ignite version 2>&1 | awk '/Ignite CLI version:/ {print $NF}'))"
fi

if [ "$INSTALLED_IGNITE" != "v${IGNITE_VERSION}" ]; then
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

    # CLEAR THE CACHE, or the new binary keeps generating with the OLD one's tooling.
    #
    # This is the part that actually decides the output, and it took three wrong diagnoses to find.
    # ignite caches its generation tooling under ~/.ignite (93 MB on M1), and swapping the BINARY
    # does not touch it.  Measured 2026-08-18: M1 was upgraded from module v29.8.0 to v29.7.0 to
    # match the Mac, and STILL rewrote nine .pb.go files -- until the cache was cleared, after which
    # it regenerated byte-identical to the committed tree.
    #
    # Proof the binary on PATH is not what generates: hiding protoc-gen-gocosmos entirely and
    # running `ignite generate proto-go` still succeeded.  ignite supplies its own plugins.
    #
    # The cache belongs to the invoking user, not root, so it is removed from THEIR home.
    IGNITE_CACHE_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    if [ -n "$IGNITE_CACHE_HOME" ]; then
        echo "Clearing ignite's cache so the new version does not generate with the old one's tooling"
        rm -rf "$IGNITE_CACHE_HOME/.ignite/cache" "$IGNITE_CACHE_HOME/.ignite/ignite_cache.db"
    fi
else
    echo "Ignite $INSTALLED_IGNITE already installed"
fi

# check if jq installed
if ! command -v jq > /dev/null 2>&1; then
    apt-get install -y jq
else
    echo "jq already installed"
fi

# check if bc installed
# Used by setup_env.sh to compute gas prices, so its absence breaks every transaction rather than
# one suite.  Present on a desktop Ubuntu and absent on the minimal/cloud images.
if ! command -v bc > /dev/null 2>&1; then
    apt-get install -y bc
else
    echo "bc already installed"
fi

# check if python3 installed
# Several test suites do their arithmetic in python3 rather than bc, because the amounts are
# 18-decimal integers that overflow shell arithmetic.
if ! command -v python3 > /dev/null 2>&1; then
    apt-get install -y python3
else
    echo "python3 already installed"
fi

# check if cast (foundry) installed -- required by testscripts/test_evm.sh
#
# INSTALLED AS THE USER, NOT AS ROOT.  foundry is a per-user install under ~/.foundry, so running
# the installer as root puts it in /root/.foundry where nothing else can see it.  A regression run
# then reports "cast (foundry) not found" on a machine where foundry is, in a sense, installed.
# -i gives a login shell, which the installer needs in order to update the user's profile.
if [ -n "$SUDO_USER" ]; then
    if sudo -u "$SUDO_USER" -i command -v cast > /dev/null 2>&1; then
        echo "cast (foundry) already installed"
    else
        echo "Installing foundry (cast, forge) for $SUDO_USER"
        if sudo -u "$SUDO_USER" -i sh -c 'curl -sL https://foundry.paradigm.xyz | bash' \
           && sudo -u "$SUDO_USER" -i sh -c '"$HOME/.foundry/bin/foundryup"'; then
            echo "foundry installed"
        else
            echo "WARNING: foundry install failed; testscripts/test_evm.sh will not be able to run"
        fi
    fi
else
    echo "SUDO_USER is not set, so foundry was not installed; testscripts/test_evm.sh needs it"
fi

# check if ifconfig installed
if ! command -v ifconfig > /dev/null 2>&1; then
    apt-get install -y net-tools
else
    echo "ifconfig already installed"
fi

# check if rotatelogs installed
if ! command -v rotatelogs > /dev/null 2>&1; then

    apt-get install -y apache2-utils
else
    echo "rotatelogs already installed"
fi

# if Linux, check if docker installed
if [ "$(uname -s)" = "Linux" ]; then
    echo "Checking if docker is installed"
    if ! command -v docker > /dev/null 2>&1; then
        echo "Docker is not installed, installing"
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
    else
        echo "Docker is already installed"
    fi
fi

# dasel
# go install github.com/tomwright/dasel/v2/cmd/dasel@master
# cp ~/go/bin/dasel /usr/local/bin

# check if dasel version is correct (relaxed: accept any 2.8.x)
INSTALLED_DASEL="$(dasel --version 2>/dev/null)"

# Extract major.minor (e.g. 2.8) in a POSIX-compatible way
DASEL_MM=$(printf '%s' "$DASEL_VERSION" | cut -d. -f1-2)
DASEL_MM_ESC=$(printf '%s' "$DASEL_MM" | sed 's/[.]/\\./g')

if ! command -v dasel > /dev/null 2>&1 || \
  ! printf '%s\n' "$INSTALLED_DASEL" | grep -Eq "(^|[^0-9])${DASEL_MM_ESC}\\.[0-9]+([^0-9]|$)"; then
    echo "dasel is not installed, installing"
    # Ensure go is available
    if ! command -v go > /dev/null 2>&1; then
        echo "go not found in PATH"
        exit 1
    fi

    go install "github.com/tomwright/dasel/v2/cmd/dasel@v${DASEL_VERSION}"

    # Put it somewhere global
    install -m 0755 "$HOME/go/bin/dasel" /usr/local/bin/dasel
else
    echo "dasel is already installed"
fi

rm -rf installers

echo "Now you need to:"
echo "  exit"
echo "...then log back in..."
echo ""
echo "  The log out and back in is REQUIRED, not tidiness: group membership is fixed when a"
echo "  session starts, so the sgx / sgx_prv groups added above do not apply to this one.  Until"
echo "  you do, the SGX device stays inaccessible and the node has to be run with sudo."
echo "  Check with:  id -nG   (expect sgx and sgx_prv)"
echo ""
echo "  cd qadena_v3"
echo "  buildscripts/init.sh   OR   buildscripts/build.sh"
echo "...then when done..."
echo "  scripts/run.sh"
