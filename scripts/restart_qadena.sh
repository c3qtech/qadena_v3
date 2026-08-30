#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

# UNDER SYSTEMD, ASK SYSTEMD -- one restart, one instance, and the unit keeps its own supervision.
if qadena_systemd_managed; then
    echo "restart_qadena.sh: systemd unit present -- restarting qadena.service"
    exec sudo systemctl restart qadena
fi

# get parameter --skip-stop, --syslog-logger
skip_stop=0
syslog_logger=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-stop)
      skip_stop=1
      shift
      ;;
    --syslog-logger)
      syslog_logger=1
      shift
      ;;
    --help)
      echo "Usage: restart_qadena.sh [--skip-stop] [--syslog-logger]"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done


# Root only when an ego enclave will actually run: SGX hardware AND a signed binary.
needs_root_if_real_enclave "restart_qadena.sh" "$qadenabin/qadenad_enclave"

if [[ $skip_stop -eq 0 ]]; then
    if is_qadena_running; then
      echo "restart_qadena.sh: Stopping Qadena $(qadena_supervision_tag)"
      $qadenascripts/stop_qadena.sh --all
    fi
fi


# `set -o pipefail` for the same reason the systemd unit needs it: a pipeline exits with the status
# of its LAST command, and both `logger` and `rotatelogs` exit 0 whenever their stdin closes -- so
# without it the backgrounded job's status says "clean exit" no matter how the node died.  Nothing
# reads it here today (the job is backgrounded and this script returns), but a status that is
# always 0 is a trap for whoever eventually does.
# -p prune_logs.sh: rotatelogs ROTATES BUT NEVER DELETES.  Without this the dated files accumulate
# at ~12 GB/day of debug output and fill a 60 GB disk in about five days -- which is exactly how the
# whole ARM fleet ran out of space on 2026-08-22, halting M4 and stalling M1.  See prune_logs.sh.
if [[ $syslog_logger -eq 1 ]]; then
    echo "restart_qadena.sh: Running in background with syslog (check /var/log/syslog)"
    nohup bash -c "set -o pipefail; $qadenascripts/run.sh 2>&1 | logger -t qadena" &
else
    echo "restart_qadena.sh: Running in background with local logger (check $QADENAHOME/logs)"
    nohup bash -c "set -o pipefail; $qadenascripts/run.sh 2>&1 | rotatelogs -l -D -p $qadenascripts/prune_logs.sh -L $QADENAHOME/logs/qadena.log $QADENAHOME/logs/qadena-%Y-%m-%d.log 86400" &
fi
