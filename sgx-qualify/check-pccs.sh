#!/bin/sh
#
# Diagnose (and optionally fix) the DCAP quote provider configuration.
#
# THIS IS THE FIRST THING TO RUN, and usually the thing that is actually wrong.  Attestation code is
# rarely the problem; the collateral path almost always is.  Quotes cannot be produced without PCK
# certificates, and those come from a PCCS -- a caching proxy in front of Intel's PCS.  A machine
# therefore needs one of:
#
#   its own PCCS          typical on-prem: install sgx-dcap-pccs, or point at another host's
#   a cloud PCCS          Azure and Alibaba run one for their SGX instances
#   a reachable remote    any PCCS you already operate
#
# The stock /etc/sgx_default_qcnl.conf points at https://localhost:8081, so a machine with no local
# PCCS is misconfigured OUT OF THE BOX while looking perfectly normal.  GetRemoteReport then fails
# with an error that names neither the PCCS nor the URL.
#
#   ./check-pccs.sh                     diagnose
#   sudo ./check-pccs.sh --install-azure
#   sudo ./check-pccs.sh --install-url https://<host>:8081/sgx/certification/v4/
#
# --install-url is what you want when one machine on the network already runs a PCCS and another
# does not: point the second at the first rather than installing a second cache.

CONF=/etc/sgx_default_qcnl.conf
INTEL_PCS="https://api.trustedservices.intel.com/sgx/certification/v4/"

# THE SAME CONFIGURATION QADENA INSTALLS, not an equivalent one.  ubuntu/setup_qadena_build.sh picks
# between these two files by detecting the cloud, and a machine qualified against different
# collateral settings has not been qualified for running Qadena.  When this directory is copied
# somewhere on its own the files are absent, and the embedded fallbacks below match them.
UBUNTU_DIR="$(cd "$(dirname "$0")/../ubuntu" 2>/dev/null && pwd)"

install_auto=0
install_url=""
use_intel_collateral=0

while [ $# -gt 0 ]; do
    case "$1" in
        --install)       install_auto=1; shift ;;
        --install-azure) install_auto=1; shift ;;
        --install-url)   install_url="$2"; shift 2 ;;
        --use-intel-collateral) use_intel_collateral=1; shift ;;
        --help|-h)
            sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) echo "unknown option: $1"; exit 2 ;;
    esac
done

json_field() {
    # The stock conf has // comments, so this is a grep rather than a JSON parse.
    grep -oE "\"$1\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" "$CONF" 2>/dev/null \
        | head -1 | sed 's/.*:[[:space:]]*"//; s/"$//'
}

reachable() {
    # A PCCS answers /rootcacrl.  -k because on-prem PCCS deployments usually have a self-signed
    # certificate, which use_secure_cert:false in the conf also reflects.
    code=$(curl -sk -m 6 -o /dev/null -w '%{http_code}' "$1rootcacrl" 2>/dev/null)
    case "$code" in
        200) echo "reachable"; return 0 ;;
        000) echo "no response"; return 1 ;;
        *)   echo "HTTP $code"; return 1 ;;
    esac
}

detect_cloud() {
    if curl -m 3 -s -H Metadata:true \
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01" > /dev/null 2>&1; then
        echo azure; return
    fi
    token=$(curl -s -m 3 -X PUT -H "X-aliyun-ecs-metadata-token-ttl-seconds: 5" \
        "http://100.100.100.200/latest/api/token" 2>/dev/null)
    if [ -n "$token" ]; then echo alibaba; return; fi
    echo on-prem
}

write_conf() {
    url="$1" secure="$2" collateral="$3"
    [ "$(id -u)" -eq 0 ] || { echo "writing $CONF needs root -- re-run with sudo"; exit 1; }
    [ -f "$CONF" ] && cp "$CONF" "$CONF.bak.$$" && echo "backed up to $CONF.bak.$$"
    cat > "$CONF" <<EOF
{
  "pccs_url": "$url"
  ,"use_secure_cert": $secure
  ,"collateral_service": "$collateral"
  ,"retry_times": 6
  ,"retry_delay": 5
  ,"pck_cache_expire_hours": 168
  ,"verify_collateral_cache_expire_hours": 24
}
EOF
    echo "wrote $CONF -> $url"
    echo "no service restart is needed: the quote provider reads this file per call."
}

if [ $install_auto -eq 1 ]; then
    [ "$(id -u)" -eq 0 ] || { echo "writing $CONF needs root -- re-run with sudo"; exit 1; }
    cloud=$(detect_cloud)
    echo "detected environment: $cloud"
    case "$cloud" in
        azure)
            if [ -f "$UBUNTU_DIR/azure_sgx_default_qcnl.conf" ]; then
                [ -f "$CONF" ] && cp "$CONF" "$CONF.bak.$$" && echo "backed up to $CONF.bak.$$"
                cp "$UBUNTU_DIR/azure_sgx_default_qcnl.conf" "$CONF"
                echo "installed $UBUNTU_DIR/azure_sgx_default_qcnl.conf -> $CONF"
            else
                write_conf "https://global.acccache.azure.net/sgx/certification/v3/" true \
                           "https://global.acccache.azure.net/sgx/certification/v3/"
            fi
            ;;
        alibaba)
            token=$(curl -s -m 3 -X PUT -H "X-aliyun-ecs-metadata-token-ttl-seconds: 5" \
                "http://100.100.100.200/latest/api/token" 2>/dev/null)
            region=$(curl -s -m 3 -H "X-aliyun-ecs-metadata-token: $token" \
                http://100.100.100.200/latest/meta-data/region-id 2>/dev/null)
            [ -n "$region" ] || { echo "could not read the Alibaba region id"; exit 1; }
            write_conf "https://sgx-dcap-server-vpc.${region}.aliyuncs.com/sgx/certification/v4/" true "$INTEL_PCS"
            ;;
        *)
            if [ -f "$UBUNTU_DIR/sgx_default_qcnl.conf" ]; then
                [ -f "$CONF" ] && cp "$CONF" "$CONF.bak.$$" && echo "backed up to $CONF.bak.$$"
                cp "$UBUNTU_DIR/sgx_default_qcnl.conf" "$CONF"
                echo "installed $UBUNTU_DIR/sgx_default_qcnl.conf -> $CONF"
                echo
                echo "NOTE: that config points at a LOCAL PCCS (localhost:8081), which is what"
                echo "Qadena assumes on-prem.  If no PCCS runs here, point at one that does:"
                echo "    sudo $0 --install-url https://<host>:8081/sgx/certification/v4/"
            else
                write_conf "https://localhost:8081/sgx/certification/v4/" false "$INTEL_PCS"
            fi
            ;;
    esac
    exit 0
fi
# A CLOUD PCCS ONLY HOLDS ITS OWN FLEET'S COLLATERAL.  Azure's cache answers about Azure machines;
# asked about an on-prem CPU it has nothing and does not go to Intel, so verification fails with
# OE_QUOTE_PROVIDER_CALL_ERROR while the cache is perfectly reachable.  Generation is unaffected --
# that uses pccs_url and, on Azure, local_pck_url (THIM) -- so ONLY collateral_service moves.
if [ $use_intel_collateral -eq 1 ]; then
    [ "$(id -u)" -eq 0 ] || { echo "writing $CONF needs root -- re-run with sudo"; exit 1; }
    [ -f "$CONF" ] || { echo "$CONF does not exist"; exit 1; }
    cp "$CONF" "$CONF.bak.$$" && echo "backed up to $CONF.bak.$$"
    if grep -q '"collateral_service"' "$CONF"; then
        sed -i 's|"collateral_service":[[:space:]]*"[^"]*"|"collateral_service": "'"$INTEL_PCS"'"|' "$CONF"
    else
        sed -i 's|\("pccs_url":[[:space:]]*"[^"]*"\)|\1\n  ,"collateral_service": "'"$INTEL_PCS"'"|' "$CONF"
    fi
    echo "collateral_service -> $INTEL_PCS"
    echo "pccs_url and local_pck_url are unchanged, so this machine still generates its own quotes."
    exit 0
fi

if [ -n "$install_url" ]; then
    case "$install_url" in */) ;; *) install_url="$install_url/" ;; esac
    # use_secure_cert:false because a PCCS you run yourself almost always has a self-signed
    # certificate; true would fail in a way that looks like the PCCS is down.
    write_conf "$install_url" false "$INTEL_PCS"
    exit 0
fi

echo "=== DCAP quote provider configuration ==="
echo

if [ ! -f "$CONF" ]; then
    echo "  $CONF does not exist."
    echo "  Install the quote provider first:  apt install -y libsgx-dcap-default-qpl"
    exit 1
fi

pccs=$(json_field pccs_url)
collateral=$(json_field collateral_service)
[ -n "$collateral" ] || collateral="$pccs"

echo "  config file:        $CONF"
echo "  pccs_url:           ${pccs:-<unset>}"
echo "  collateral_service: ${collateral:-<unset>}"
echo "  environment:        $(detect_cloud)"
echo

status=0

printf "  pccs_url reachable ......... "
if ! reachable "$pccs"; then status=1; fi

printf "  collateral reachable ....... "
reachable "$collateral" > /dev/null 2>&1 && echo reachable || echo "no response (verification may still work from cache)"

# Reachability is not the whole story for VERIFICATION.  A cloud cache answers only about its own
# fleet, so a machine configured this way can generate quotes and verify its neighbours while being
# unable to verify anything from outside the cloud -- an asymmetry that shows up only when tried.
case "$collateral" in
    *acccache.azure.net*|*aliyuncs.com*)
        echo
        echo "  NOTE: collateral_service is a CLOUD cache.  It holds collateral for that cloud's own"
        echo "  machines only, so this host can verify quotes from inside the cloud but NOT from"
        echo "  on-prem or other providers -- that fails with OE_QUOTE_PROVIDER_CALL_ERROR even"
        echo "  though the cache is reachable.  If this machine must verify outside quotes:"
        echo "      sudo $0 --use-intel-collateral"
        echo "  Quote GENERATION is unaffected either way."
        ;;
esac

echo
if [ $status -eq 0 ]; then
    echo "PCCS OK -- quote generation should work on this machine."
    exit 0
fi

echo "PCCS NOT REACHABLE.  Quote GENERATION will fail here, with an error that mentions"
echo "neither the PCCS nor this URL.  Options, in the order usually preferred:"
echo
case "$(detect_cloud)" in
    azure)
        echo "  This is an Azure instance, which provides a PCCS.  Install the same config"
        echo "  Qadena uses:"
        echo "      sudo $0 --install"
        ;;
    alibaba)
        echo "  This is an Alibaba instance; use the regional PCCS:"
        echo "      sudo $0 --install-url https://sgx-dcap-server-vpc.<region>.aliyuncs.com/sgx/certification/v4/"
        ;;
    *)
        case "$pccs" in
            *localhost*|*127.0.0.1*)
                echo "  The config points at a LOCAL PCCS that is not running.  Either:"
                echo
                echo "  a) point at another machine that already runs one -- simplest if you have one:"
                echo "         sudo $0 --install-url https://<other-host>:8081/sgx/certification/v4/"
                echo
                echo "  b) run a PCCS here (needs an Intel PCS API key from"
                echo "     https://api.portal.trustedservices.intel.com/provisioning-certification ):"
                echo "         sudo apt install -y sgx-dcap-pccs"
                ;;
            *)
                echo "  The configured PCCS did not answer.  Check it is up and reachable from here,"
                echo "  or point somewhere else:"
                echo "         sudo $0 --install-url https://<host>:8081/sgx/certification/v4/"
                ;;
        esac
        ;;
esac
exit 1
