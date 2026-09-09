#!/bin/zsh
#
# RUN BY THE QADENA FOUNDATION, after SEC's step_2 and before their step_3.
#
#   sec_veritas_after_step_2.sh <proposal-id> <proposal-id> [options]
#
# step_2 prints two proposal ids -- identity provider and DSVS.  This deposits and votes YES on
# each, from the `foundation` bucket: the deposit needs liquid tokens and the vote needs bonded
# ones, and bucket 03 is the only bucket with both.
#
# A thin wrapper over sec_veritas_before_step_1.sh --stage approve -- one implementation, because
# it shares that script's whole multisig ceremony, but its own entry point so the sequence stays
# readable from `ls`: a stage hidden behind a flag on a file named "before_step_1" is exactly the
# confusion the naming exists to prevent.
#
# NOTE: the wallet PRE-GRANTS are NOT here.  They briefly were, and it was a bug: step_2 itself
# creates the provider wallets, so grants issued after step_2 were too late for them.  All 124
# addresses are derivable at step_1, so step_1 emits the block and sec_veritas_after_step_1.sh
# signs the grants -- before anything is created.

HERE="${0:A:h}"
# The name to PRINT in usage.  A per-deployment wrapper execs this file, so a hard-coded
# "sec_veritas_*.sh" told an ekycph operator to run a script whose --help they were not
# reading.  The wrapper exports QADENA_PROG; direct callers get the real name.
PROG="${QADENA_PROG:-sec_veritas_after_step_2.sh}"

# Scan every argument: the per-deployment wrappers prepend "--deployment <name>", so --help does
# not arrive as $1.
_want_help=0
for _a in "$@"; do [[ "$_a" == "--help" || "$_a" == "-h" ]] && _want_help=1; done

case "$_want_help" in
    1)
        print "Usage: $PROG <proposal-id>... [options]"
        print ""
        print "  Deposits and votes YES on each proposal id that SEC's step_2 printed."
        print "  Every option of sec_veritas_before_step_1.sh applies -- --members,"
        print "  --coord-home, --keyring-backend, --keyring-passfile, --print-ceremony, --via-ssh."
        print ""
        print "  $PROG 12 13 --coord-home ~/launch/coord \\\\"
        print "      --members foundation-m1,foundation-m2,foundation-m3"
        print ""
        print "  Then watch both to PASSED before SEC runs step_3:"
        print "      provider_scripts/query_service_provider_proposal.sh <id> --wait${QADENA_NODE:+ --node $QADENA_NODE}"
        exit 0 ;;
esac

exec "$HERE/sec_veritas_before_step_1.sh" --stage approve "$@"
