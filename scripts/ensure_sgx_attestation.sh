#!/bin/zsh

# Makes DCAP attestation available before a REAL enclave starts: either Azure's DCAP client is
# installed (nothing to do), or the Intel PCCS docker container is running and answering.
#
# Hoisted out of the deleted run_realenclave.sh (its lines 28-69) when qadenad took over spawning
# the enclave processes: managing a docker sidecar is host provisioning, not something the chain
# binary should do, so it stays script-side -- called by run.sh before `qadenad start`, and by
# run_enclave_standalone.sh for enclave-only starts (promotion, upgrade, debugging).
#
# Exit 0 when attestation is available, 1 when it is not.  Harmless (instant no-op) on a
# non-SGX/debug host, but callers normally gate it on use_real_enclave anyway.

SCRIPT_DIR="${0:A:h}"
source "$SCRIPT_DIR/../scripts/setup_env.sh"

if dpkg -V az-dcap-client > /dev/null 2>&1 ; then
    echo "ensure_sgx_attestation.sh: Azure DCAP client installed -- nothing to do"
    exit 0
fi

echo "ensure_sgx_attestation.sh: checking the Intel PCCS (Provisioning Certificate Caching Service) docker container"
if docker container ls -a | grep -q pccs ; then
    if docker ps | grep -q pccs ; then
        if curl --fail -k https://localhost:8081/sgx/certification/v4/rootcacrl > /dev/null 2>&1 ; then
            echo "ensure_sgx_attestation.sh: PCCS is working"
            exit 0
        fi
        echo "ensure_sgx_attestation.sh: PCCS is up but not answering -- restarting it"
        docker stop pccs
        docker start pccs
    else
        echo "ensure_sgx_attestation.sh: starting the existing PCCS container"
        docker start pccs
    fi
else
    echo "ensure_sgx_attestation.sh: PCCS not installed -- installing and running"
    docker run -p 8081:8081 --name pccs -d ghcr.io/edgelesssys/pccs
fi

for i in 1 2 3 4 5 ; do
    if curl --fail -k https://localhost:8081/sgx/certification/v4/rootcacrl > /dev/null 2>&1 ; then
        echo "ensure_sgx_attestation.sh: PCCS is working"
        exit 0
    fi
    echo "ensure_sgx_attestation.sh: PCCS is not yet up, waiting...$i"
    sleep 3
done

echo "ensure_sgx_attestation.sh: PCCS did not come up -- a real enclave cannot attest without it (or Azure DCAP)"
exit 1
