#!/bin/zsh
#
# RUN BY THE QADENA FOUNDATION, after SEC's step_2 and before their step_3.
#
#   sec_veritas_after_step_2.sh <proposal-id> <proposal-id> [options]
#
# step_2 prints two proposal ids -- one for the identity service provider, one for DSVS. This
# deposits and votes YES on each, from the `foundation` bucket: the deposit needs liquid tokens
# and the vote needs bonded ones, and bucket 03 is the only one with both.
#
# WHY THIS FILE EXISTS RATHER THAN JUST DOCUMENTING A FLAG.
#
# The work is a stage of sec_veritas_before_step_1.sh (`--stage approve`), because it shares that
# script's whole multisig ceremony -- build, sign per member, combine, broadcast, verify.  But the
# point of naming these files after the step they follow is that `ls foundation_scripts/` tells an
# operator the order without opening anything, and a stage hidden behind a flag on a file called
# "before_step_1" is exactly the thing that ordering was meant to stop.
#
# So: one implementation, two entry points, and the sequence is readable.
#
#   sec_veritas_before_step_1.sh   stake, create and fund the sponsor accounts
#   step_1   SEC                   creates its keys, reports its admin address
#   sec_veritas_after_step_1.sh    delegate MsgGrantAllowance authority to that address
#   step_2   SEC                   creates its providers, reports two proposal ids
#   THIS                           deposit + vote on both, expedited
#   step_3   SEC                   creates its wallets and users, reports the sponsor pool
#   sec_veritas_after_step_3.sh    authorise the app-server's sponsor pool

HERE="${0:A:h}"

case "${1:-}" in
    --help|-h)
        print "Usage: sec_veritas_after_step_2.sh <proposal-id>... [options]"
        print ""
        print "  Deposits and votes YES on each proposal id that SEC's step_2 printed."
        print "  Every option of sec_veritas_before_step_1.sh applies -- --members,"
        print "  --coord-home, --keyring-backend, --stake-bucket, --print-ceremony, --via-ssh."
        print ""
        print "  sec_veritas_after_step_2.sh 12 13 --coord-home ~/launch/coord \\\\"
        print "      --members foundation-m1,foundation-m2,foundation-m3"
        print ""
        print "  Then watch both to PASSED before SEC runs step_3:"
        print "      provider_scripts/query_service_provider_proposal.sh <id> --wait"
        exit 0 ;;
esac

# NOT `exec ... "$@"` WITH THE STAGE APPENDED.  The proposal ids are positional, and the option
# parser collects positionals wherever they appear -- so forwarding verbatim and prepending the
# stage keeps `12 13 --members x` working exactly as it does on the underlying script.
exec "$HERE/sec_veritas_before_step_1.sh" --stage approve "$@"
