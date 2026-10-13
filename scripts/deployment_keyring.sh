#!/bin/zsh
#
# WHICH KEYRING A DEPLOYMENT'S CONTRACT CLI SIGNS FROM.  Sourced by enf_cli.sh and epdc_cli.sh,
# after setup_env.sh.
#
# A deployment's keys live in TWO keyrings on a devnet:
#
#   node        $QADENAHOME             pioneer1, treasury, foundation-appsvr, foundation-users
#   deployment  <sec home>/keyring      <name>identitysrvprv, <name>-create-wallet-sponsor,
#                                       <name>-admin ... -- step_1 always writes there
#                                       (veritas_scripts/step_1.sh, QADENA_KEYRING_DIR)
#
# The CLIs only ever looked in the node keyring, so on a chain onboarded through the veritas steps
# setup-<name> stopped at "identity provider ... is not in the keyring" with the key sitting one
# directory over.  Pointing them wholesale at the deployment keyring is not the fix either: the
# deployer user may already live in the node keyring on a box set up before the split, and a CLI
# that could no longer see it would create a SECOND deployer whose credential collides on its
# fixed a/bf values.  So the choice is made per run, from where the keys actually are:
#
#   1. QADENA_KEYRING_DIR already set by the caller   -> left alone
#   2. the deployer ($FROM) is in the deployment keyring -> deployment
#   3. the deployer is in the node keyring            -> node (a box that works today is unchanged)
#   4. neither -- not created yet: wherever the deployment's identity provider is, since
#      create_user.sh signs its credentials with that key
#
# DECIDED FROM THE KEYRING FILES, NOT `keys show`.  On the `file` backend `keys show` needs the
# passphrase, and this runs BEFORE qadena_keyring_unlock so that the prompt names the keyring it is
# for.  <name>.info is how cosmos stores a key in both the file and test backends.
#
# THE NODE-SIDE KEYS STAY REACHABLE through node_keyring_address and node_keyring_run, which drop
# QADENA_KEYRING_DIR in a subshell.  The passphrase is assumed to be the same for both keyrings
# unless QADENA_NODE_KEYRING_PASS says otherwise.

_dkr_has() { [[ -f "$1/keyring-$QADENA_KEYRING_BACKEND/$2.info" ]] }

# deployment_keyring_select <deployment> <deployer key> <identity provider key>
deployment_keyring_select() {
    local dep="$1" from="$2" provider="$3"
    [[ -n "${QADENA_KEYRING_DIR:-}" ]] && return 0
    source "${qadenabuild:-${SCRIPT_DIR:h}}/foundation_scripts/deployment_profile.sh"
    deployment_profile_load "$dep" > /dev/null || return 0
    local dkr="${VERITAS_SEC_HOME:-$DEPLOY_SEC_HOME}/keyring"
    local why=""
    if _dkr_has "$dkr" "$from"; then
        why="'$from' is there"
    elif _dkr_has "$QADENAHOME" "$from"; then
        return 0
    elif _dkr_has "$dkr" "$provider"; then
        why="'$from' does not exist yet and '$provider', which issues its credentials, is there"
    else
        return 0
    fi
    export QADENA_KEYRING_DIR="$dkr"
    echo "Using the $dep deployment keyring $dkr ($why)." >&2
}

# The same calls against the NODE keyring, for the keys only it holds (treasury, foundation-appsvr).
# A no-op wrapper when the node keyring is already the one in use.
node_keyring_run() {
    if [[ -z "${QADENA_KEYRING_DIR:-}" ]]; then "$@"; return; fi
    ( unset QADENA_KEYRING_DIR
      QADENA_KEYRING_PASS="${QADENA_NODE_KEYRING_PASS:-${QADENA_KEYRING_PASS:-}}"
      "$@" )
}

# A node-keyring key name -> its address; an address passes through.  Empty when not found.
node_keyring_address() {
    case "$1" in qadena1*) print -r -- "$1"; return ;; esac
    node_keyring_run qadenad_alias keys show "$1" --address 2>/dev/null | tr -d '\r'
}
