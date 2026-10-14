#!/bin/zsh
#
# check_sgx_platform.sh -- refuse to start a real-SGX node whose SEALED STATE belongs to another CPU.
#
#   scripts/check_sgx_platform.sh            check (run.sh calls this before anything starts)
#   scripts/check_sgx_platform.sh --show     print this machine's fingerprint and the recorded one
#   QADENA_ACCEPT_PLATFORM_CHANGE=1 scripts/check_sgx_platform.sh
#                                            accept the current platform and re-record it
#
# WHY.  The enclaves seal with the PRODUCT key (ecrypto.SealWithProductKey), which SGX derives from
# a root key fused into the physical CPU.  A sealed file opens only on the CPU that wrote it, and
# only at a CPUSVN no LOWER than the one it was sealed at.  A cloud VM can land on a different
# physical host without anything inside it changing -- an Azure deallocate, resize, redeploy or
# service-healing does exactly that -- and then every sealed file fails with
#     cipher: message authentication failed
# from deep inside the enclaves, after the node has started.  That is how c3q-mainnet's Azure
# validator came back on 2026-10-14: signer_enclave could not open the validator key, the node
# halted, systemd retried five times and gave up, and the log said nothing about a host move.
#
# WHAT IS RECORDED, in $QADENAHOME/config/sgx_platform.env:
#   QE_ID, PCE_ID  identify the physical SGX platform (PCKIDRetrievalTool, sgx-pck-id-retrieval-tool)
#   CPUSVN         the security level sealing keys are derived at
#   PCE_SVN        recorded for the record; it does not enter the sealing key
#   AZURE_HOST     Hyper-V's PhysicalHostNameFullyQualified, on Azure only -- a second, independent
#                  signal, and the only one on a box without the retrieval tool
#
# REFUSES (exit 3) only when sealed state exists and either the platform is different (QE_ID,
# PCE_ID or AZURE_HOST changed) or CPUSVN went down.  A CPUSVN that went UP is a microcode/BIOS
# update: sealed data still opens, so the record is updated and the run continues.  A node with no
# sealed state yet just records.  A machine with no fingerprint source warns and continues -- this
# check must never be the reason a node that could run does not.

SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/../scripts/setup_env.sh" > /dev/null 2>&1

me="check_sgx_platform.sh"
record="$QADENAHOME/config/sgx_platform.env"
show=0
[[ "${1:-}" == "--show" ]] && show=1

# Only a real enclave seals with the CPU; a debug build's "sealing" is a prefix and moves anywhere.
if (( ! show )) && ! use_real_enclave "$qadenabin/qadenad_enclave"; then
    exit 0
fi

# --- this machine's fingerprint -------------------------------------------------------------
QE_ID="" PCE_ID="" CPUSVN="" PCE_SVN="" AZURE_HOST=""

_tool=$(command -v PCKIDRetrievalTool || ls /opt/intel/sgx-pck-id-retrieval-tool/PCKIDRetrievalTool 2>/dev/null)
if [[ -n "$_tool" ]]; then
    # STDIN FROM /dev/null: with a terminal on stdin the tool stops at an interactive prompt and
    # writes nothing.  It uploads nothing unless given -url, and needs no root -- the sgx_prv group
    # (ubuntu/setup_qadena_build.sh) is enough.
    _d=$(mktemp -d)
    ( cd "$_d" && timeout 60 "$_tool" -f pck.csv < /dev/null > /dev/null 2>&1 )
    if [[ -s "$_d/pck.csv" ]]; then
        # EncryptedPPID,PCE_ID,CPUSVN,PCE_SVN,QE_ID[,platform manifest].  The encrypted PPID is
        # left out: it changes with every encryption and identifies nothing by itself.
        IFS=, read -r _encppid PCE_ID CPUSVN PCE_SVN QE_ID _rest < "$_d/pck.csv"
        unset _encppid _rest
        QE_ID="${QE_ID%%[[:space:]]*}"
    fi
    rm -rf "$_d"
fi
if [[ -r /var/lib/hyperv/.kvp_pool_3 ]]; then
    # Fixed-size NUL-padded records: squeeze the NULs to one newline each, then key -> next line.
    AZURE_HOST=$(tr -s '\0' '\n' < /var/lib/hyperv/.kvp_pool_3 2>/dev/null \
                 | grep -A1 -x PhysicalHostNameFullyQualified | tail -1)
fi

_write_record() {
    mkdir -p "${record:h}"
    {
        print -r -- "# Written by scripts/check_sgx_platform.sh -- the platform this node's sealed state belongs to."
        print -r -- "RECORDED=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        print -r -- "QE_ID=$QE_ID"
        print -r -- "PCE_ID=$PCE_ID"
        print -r -- "CPUSVN=$CPUSVN"
        print -r -- "PCE_SVN=$PCE_SVN"
        print -r -- "AZURE_HOST=$AZURE_HOST"
    } > "$record.tmp" && mv "$record.tmp" "$record"
}

# Recorded values, read as data -- never sourced.
_rec() { [[ -f "$record" ]] && sed -n "s/^$1=//p" "$record" | tail -1 }

if (( show )); then
    print -r -- "this machine:  QE_ID=${QE_ID:-?} PCE_ID=${PCE_ID:-?} CPUSVN=${CPUSVN:-?} PCE_SVN=${PCE_SVN:-?} AZURE_HOST=${AZURE_HOST:--}"
    if [[ -f "$record" ]]; then
        print -r -- "recorded:      QE_ID=$(_rec QE_ID) PCE_ID=$(_rec PCE_ID) CPUSVN=$(_rec CPUSVN) PCE_SVN=$(_rec PCE_SVN) AZURE_HOST=$(_rec AZURE_HOST)  ($(_rec RECORDED))"
    else
        print -r -- "recorded:      none ($record)"
    fi
    [[ -z "$_tool" ]] && print -r -- "note: no PCKIDRetrievalTool -- apt install sgx-pck-id-retrieval-tool"
    exit 0
fi

if [[ -z "$QE_ID" && -z "$AZURE_HOST" ]]; then
    echo "$me: WARNING: cannot fingerprint this SGX platform, so a host/CPU change cannot be caught" >&2
    echo "$me:          before the enclaves try to unseal.  Install it:  sudo apt install sgx-pck-id-retrieval-tool" >&2
    exit 0
fi

# Sealed state is what is at stake; with none, there is nothing a platform change can break.
_sealed=("$QADENAHOME"/enclave_config/*(N.))

if [[ ! -f "$record" ]]; then
    _write_record
    if (( ${#_sealed} )); then
        echo "$me: recorded this platform (QE_ID=${QE_ID:-?}${AZURE_HOST:+, Azure host $AZURE_HOST}) for the first time." >&2
        echo "$me: sealed state already exists, so this assumes it was sealed HERE -- nothing earlier was recorded to check." >&2
    fi
    exit 0
fi

if [[ "${QADENA_ACCEPT_PLATFORM_CHANGE:-0}" == "1" ]]; then
    _write_record
    echo "$me: QADENA_ACCEPT_PLATFORM_CHANGE=1 -- re-recorded this platform as the node's own." >&2
    exit 0
fi

r_qe=$(_rec QE_ID) r_pce=$(_rec PCE_ID) r_svn=$(_rec CPUSVN) r_host=$(_rec AZURE_HOST)
why=()
[[ -n "$QE_ID"      && -n "$r_qe"   && "$QE_ID"      != "$r_qe"   ]] && why+=("QE_ID $r_qe -> $QE_ID (a different physical SGX platform)")
[[ -n "$PCE_ID"     && -n "$r_pce"  && "$PCE_ID"     != "$r_pce"  ]] && why+=("PCE_ID $r_pce -> $PCE_ID")
[[ -n "$AZURE_HOST" && -n "$r_host" && "$AZURE_HOST" != "$r_host" ]] && why+=("Azure physical host $r_host -> $AZURE_HOST (the VM was moved)")

# CPUSVN is 16 component bytes; a key sealed at one level derives only where no component is lower.
svn_up=0
if [[ -n "$CPUSVN" && -n "$r_svn" && "$CPUSVN" != "$r_svn" && ${#CPUSVN} -eq ${#r_svn} ]]; then
    integer i a b
    for (( i = 1; i <= ${#CPUSVN}; i += 2 )); do
        a=$(( 16#${r_svn[i,i+1]} )); b=$(( 16#${CPUSVN[i,i+1]} ))
        if (( b < a )); then why+=("CPUSVN went DOWN $r_svn -> $CPUSVN (microcode/BIOS downgrade)"); svn_up=0; break; fi
        (( b > a )) && svn_up=1
    done
fi

if (( ${#why} == 0 )); then
    if (( svn_up )); then
        echo "$me: CPUSVN rose $r_svn -> $CPUSVN (microcode/BIOS update); sealed state still opens.  Record updated." >&2
        _write_record
    fi
    exit 0
fi

if (( ! ${#_sealed} )); then
    echo "$me: platform changed (${(j:; :)why}), but there is no sealed state yet -- re-recording." >&2
    _write_record
    exit 0
fi

cat >&2 <<EOF
$me: ===================================================================================
$me: REFUSING TO START: this node's sealed state belongs to a different SGX platform.
$me:
EOF
for w in "${why[@]}"; do echo "$me:   - $w" >&2; done
cat >&2 <<EOF
$me:
$me: Sealed files open only on the CPU that wrote them, so the enclaves would fail with
$me: "cipher: message authentication failed" and the node would halt.  Sealed state here:
EOF
for f in "${_sealed[@]}"; do echo "$me:     ${f#$QADENAHOME/}" >&2; done
cat >&2 <<EOF
$me:
$me: Nothing has been changed.  If enclave_config/private_params_escrow.json exists, recover with
$me:     $qadenascripts/recover_enclave_after_cpu_move.sh --seed tcp://<healthy peer>:26657
$me: which keeps this pioneer's enclave key (restored from the escrow, re-sealed here), needs no
$me: transaction, and re-records this platform.  It needs config/priv_validator_key.json (or your
$me: offline copy of it) for the validator key.  Without an escrow the enclave key is gone: retire
$me: this pioneer and re-join the machine as a new one.
$me: ===================================================================================
EOF
exit 3
