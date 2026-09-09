#!/bin/zsh
#
# The whole ekycph bring-up on a devnet, end to end.
#
#   ./testscripts/ekycph_full_setup.sh --from setup          # skip the build
#   ./testscripts/ekycph_full_setup.sh --from base --until verify
#
# A thin wrapper over testscripts/deployment_full_setup.sh, which is deployment-generic.  Every
# option of that script applies; see --help, and docs/HOWTO-SPONSOR-DEPLOYMENT.md for the
# production (multisig, launch-chain) counterpart in foundation_scripts/ekycph_*.sh.

HERE="${0:A:h}"
# So that --help and the resume hint name THIS script, not the implementation it execs.
export QADENA_PROG="ekycph_full_setup.sh"
exec "$HERE/deployment_full_setup.sh" --deployment ekycph "$@"
