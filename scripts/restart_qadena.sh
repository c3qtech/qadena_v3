#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

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


# if REAL_ENCLAVE, check if running as root
if [[ $REAL_ENCLAVE -eq 1 ]]; then
    if [[ $(id -u) -ne 0 ]]; then
        echo "restart_qadena.sh:  Error: qadenad_enclave must be run as root"
        exit 1
    fi
fi

if [[ $skip_stop -eq 0 ]]; then
    if is_qadena_running; then
      echo "restart_qadena.sh: Stopping Qadena"
      $qadenascripts/stop_qadena.sh --all
    fi
fi


if [[ $syslog_logger -eq 1 ]]; then
    echo "restart_qadena.sh: Running in background with syslog (check /var/log/syslog)"
    nohup bash -c "$qadenascripts/run.sh 2>&1 | logger -t qadena" &
else
    echo "restart_qadena.sh: Running in background with local logger (check $QADENAHOME/logs)"
    nohup bash -c "$qadenascripts/run.sh 2>&1 | rotatelogs -l -D -L $QADENAHOME/logs/qadena.log $QADENAHOME/logs/qadena-%Y-%m-%d.log 86400" &
fi
