#!/bin/zsh
#
# The whole enf bring-up on a DEVNET -- one machine, no ceremonies.
#
#   ./testscripts/enf_devnet_setup.sh --from setup          # skip the build
#   ./testscripts/enf_devnet_setup.sh --from base --until verify
#
# THE DEVNET PATH, NOT THE LAUNCH ONE.  This funds by `tx bank send --from treasury`, a key no
# launch chain has.  For a real fleet use testscripts/enf_full_setup.sh, which drives the
# multisig ceremonies against a coordinator keyring.
#
# A thin wrapper over testscripts/deployment_full_setup.sh, which is deployment-generic.  Every
# option of that script applies; see --help, and docs/HOWTO-SPONSOR-DEPLOYMENT.md for the
# production (multisig, launch-chain) counterpart in foundation_scripts/enf_*.sh.

HERE="${0:A:h}"
# So that --help and the resume hint name THIS script, not the implementation it execs.
export QADENA_PROG="enf_devnet_setup.sh"
exec "$HERE/deployment_full_setup.sh" --deployment enf "$@"
