#!/bin/zsh
#
# VERITAS on the STAGING fleet (Azure primary, AWS joiner), end to end.
#
#   ./testscripts/veritas_full_setup_sec_staging.sh --from prepare
#
# THIS WAS A 520-LINE COPY of veritas_full_setup.sh with ten values changed.  Copies drift, and this
# one had: it was missing the --keyring-passfile argument the original passes to the fleet bring-up,
# and the compose.yml check that catches a wrong --env-file.  Neither absence was a decision.
#
# The ten values are now testscripts/fleet_site_profile.sh's `staging` profile -- the two
# hosts, the passphrase file, the launch directory, the ~/sec-*-staging suffix that keeps a rebuild
# here from wiping the local fleet's keys, the env file name, the advertised addresses, full-nodes-
# not-validators, and the unverified-peer-agreement flag the NLB requires.
#
# Kept as its own entry point because the sequence should stay readable from `ls`, and because this
# name is in the runbooks.  Every option of veritas_full_setup.sh applies.

HERE="${0:A:h}"
export QADENA_PROG="veritas_full_setup_sec_staging.sh"
exec "$HERE/veritas_full_setup.sh" --site staging "$@"
