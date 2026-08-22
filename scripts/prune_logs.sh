#!/bin/bash
#
# Post-rotation hook for rotatelogs.  Wired in with -p:
#
#   rotatelogs -l -D -p .../prune_logs.sh -L .../qadena.log .../qadena-%Y-%m-%d.log 86400
#
# WHY THIS EXISTS.  rotatelogs ROTATES; it does not DELETE.  Nothing in that invocation ever removed
# a rotated file, so qadena-YYYY-MM-DD.log accumulated forever at roughly 12 GB/day of debug output.
# On 2026-08-22 that filled all four ARM nodes: M4 reached 99% and its enclave stopped answering
# health checks -- writes stall when the filesystem is full -- then signer_enclave exited and the
# node halted, correctly, rather than committing blocks without it.  M1 reached 100% with 87 MB
# free and stalled behind the other three at height 79555 while they carried on to 79582.  A 60 GB
# disk holds about five days of this, which is why it had gone unnoticed since the fleet was built.
#
# -n is NOT the fix.  It gives a circular list of UNTIMESTAMPED names (logfile, logfile.1, ...) and
# cannot be combined with the %Y-%m-%d pattern; adopting it would trade dated logs for retention.
# -p keeps both.
#
# rotatelogs calls this with the NEW file as $1 and, when rotating, the OLD file as $2.  It does not
# wait for us and ignores our exit code, so this must never block rotation and must never assume it
# is the only copy running.
#
# TWO LIMITS, AND THE SIZE ONE IS THE POINT.  Age alone does not protect a fixed disk: at 12 GB/day
# even three days is 36 GB, more than this 60 GB disk can spare next to the chain data, toolchain and
# backups.  So the budget is enforced as well, oldest deleted first, and whichever limit bites first
# wins.  Age keeps the recent history you actually read; the budget is what stops a full disk.
set -u

KEEP_DAYS="${QADENA_LOG_KEEP_DAYS:-3}"
MAX_TOTAL_MB="${QADENA_LOG_MAX_TOTAL_MB:-18000}"

newfile="${1:-}"
[ -n "$newfile" ] || exit 0
dir=$(dirname -- "$newfile")
[ -d "$dir" ] || exit 0

# One at a time.  Rotations are daily so overlap is unlikely, but a slow prune racing the next one
# would have two passes deleting from the same list and mis-counting the budget.  Non-blocking:
# rotation must not wait on us, and a skipped prune is harmless -- the next one sees the same files.
exec 9>"$dir/.prune.lock" 2>/dev/null || exit 0
flock -n 9 2>/dev/null || exit 0

note() { printf '%s prune_logs: %s\n' "$(date -u +%FT%TZ)" "$*" >> "$dir/prune.log" 2>/dev/null; }

# NEVER the file being written to, and never the -L link.  $1 is the newly opened file; the link is
# a separate name pointing at it.  Deleting either loses the live log rather than an old one.
protected=$(basename -- "$newfile")

candidates() {
    find "$dir" -maxdepth 1 -type f -name 'qadena-*.log' ! -name "$protected" -printf '%T@ %s %p\n' 2>/dev/null \
        | sort -n
}

# 1. AGE.
while read -r _ _ path; do
    [ -n "$path" ] || continue
    if [ -n "$(find "$path" -maxdepth 0 -mtime "+$KEEP_DAYS" 2>/dev/null)" ]; then
        sz=$(stat -c %s "$path" 2>/dev/null || echo 0)
        rm -f -- "$path" && note "deleted $(basename -- "$path") (older than ${KEEP_DAYS}d, $((sz/1024/1024))MB)"
    fi
done < <(candidates)

# 2. BUDGET, oldest first, until the total fits.  Recomputed from what survived step 1.
total=$(candidates | awk '{s+=$2} END {printf "%d", s/1024/1024}')
[ -n "$total" ] || total=0
if [ "$total" -gt "$MAX_TOTAL_MB" ]; then
    note "rotated logs total ${total}MB, over budget ${MAX_TOTAL_MB}MB -- trimming oldest"
    while read -r _ sz path; do
        [ "$total" -gt "$MAX_TOTAL_MB" ] || break
        [ -n "$path" ] || continue
        rm -f -- "$path" && total=$(( total - sz/1024/1024 )) \
            && note "deleted $(basename -- "$path") (budget, now ${total}MB)"
    done < <(candidates)
fi

# Visible in the log itself, so a full disk is seen BEFORE it halts a node rather than after.
avail=$(df -Pm "$dir" | tail -1 | awk '{print $4}')
[ "${avail:-99999}" -lt 5000 ] && note "WARNING: only ${avail}MB free on the log filesystem"
exit 0
