#!/bin/zsh
#
# eKYC PH -- foundation side, after_step_3.
#
# A THIN WRAPPER, DELIBERATELY.  The implementation is sec_veritas_after_step_3.sh, which is
# deployment-generic: --deployment selects the sponsor key names, the admin key and the
# sponsors/pregrant/pool filenames out of foundation_scripts/deployment_profile.sh.  This file
# exists so that `ls foundation_scripts/` shows the ekycph sequence in order, for the same reason
# sec_veritas_after_step_2.sh is its own entry point rather than a flag: a stage hidden behind an
# option on a file named for another deployment is exactly the confusion the naming prevents.
#
# Every option of the underlying script applies.  See:
#     foundation_scripts/sec_veritas_after_step_3.sh --help
#     docs/HOWTO-SPONSOR-DEPLOYMENT.md
#
# The bring-up order is:
#   ekycph_before_step_1.sh --stage prepare   FOUNDATION  stake, and fund the two sponsor accounts
#   veritas_scripts/step_1.sh --deployment ekycph         eKYC PH: creates its keys, reports its admin address
#   ekycph_after_step_1.sh --sec-admin <addr> FOUNDATION  authz + the wallet pre-grants
#   veritas_scripts/step_2.sh --deployment ekycph         eKYC PH: creates its providers, reports two proposal ids
#   ekycph_after_step_2.sh <id> <id>          FOUNDATION  deposit + vote, expedited
#   veritas_scripts/step_3.sh --deployment ekycph         eKYC PH: creates its wallets and users
#   ekycph_after_step_3.sh                    FOUNDATION  the app-server's sponsor pool
#   ekycph_verify.sh --coord-home <dir>       FOUNDATION  15 gating checks

HERE="${0:A:h}"
# So that --help names THIS script rather than the implementation it execs.
export QADENA_PROG="ekycph_after_step_3.sh"
exec "$HERE/sec_veritas_after_step_3.sh" --deployment ekycph "$@"
