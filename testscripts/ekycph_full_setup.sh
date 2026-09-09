#!/bin/zsh
#
# The whole eKYC PH bring-up on a LAUNCH FLEET, end to end -- sponsored, and multisig throughout.
#
#   ./testscripts/ekycph_full_setup.sh --site local   --rebuild-chain --count 30
#   ./testscripts/ekycph_full_setup.sh --site staging --from prepare
#
# A thin wrapper over testscripts/veritas_full_setup.sh, which is deployment-generic: --deployment
# selects the sponsor keys, the admin key, the service providers, the allocation bucket that funds
# them and the members who sign for that bucket.  One implementation, not three.
#
# eKYC PH FUNDS FROM BUCKET 01, ADOPTION PROGRAMS -- a 3-of-5 multisig, where VERITAS's bucket 10
# is 5-of-7.  The profile carries that, so the ceremony asks the right five people; see
# foundation_scripts/deployment_profile.sh and docs/HOWTO-SPONSOR-DEPLOYMENT.md.
#
# NOT the devnet path.  testscripts/ekycph_devnet_setup.sh brings ekycph up on one machine, funding
# by `tx bank send --from treasury` -- a key no launch chain has, which is why they are separate.

HERE="${0:A:h}"
# So that --help and the resume hint name THIS script, not the implementation it execs.
export QADENA_PROG="ekycph_full_setup.sh"
exec "$HERE/veritas_full_setup.sh" --deployment ekycph "$@"
