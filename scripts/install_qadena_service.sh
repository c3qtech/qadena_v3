#!/bin/bash

set -euo pipefail

if [ "${EUID}" -ne 0 ]; then
  echo "install_qadena_service.sh: Error: must be run with sudo." >&2
  exit 1
fi

if [ -z "${SUDO_USER:-}" ] || [ "${SUDO_USER}" = "root" ]; then
  echo "install_qadena_service.sh: Error: must be run via sudo from a non-root user (SUDO_USER is not set)." >&2
  exit 1
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SKEL_FILE="${SCRIPT_DIR}/qadena.service-skel"

if [ ! -f "${SKEL_FILE}" ]; then
  echo "install_qadena_service.sh: Error: missing ${SKEL_FILE}" >&2
  exit 1
fi

USERNAME="${SUDO_USER}"

if ! id "${USERNAME}" >/dev/null 2>&1; then
  echo "install_qadena_service.sh: Error: user '${USERNAME}' not found" >&2
  exit 1
fi

SYSTEMD_DIR="/etc/systemd/system"
SERVICE_NAME="qadena.service"
DEST_FILE="${SYSTEMD_DIR}/${SERVICE_NAME}"

TMP_FILE="$(mktemp)"
trap 'rm -f "${TMP_FILE}"' EXIT

sed "s#<username>#${USERNAME}#g" "${SKEL_FILE}" > "${TMP_FILE}"
install -m 0644 "${TMP_FILE}" "${DEST_FILE}"

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
  echo "install_qadena_service.sh: Installed ${DEST_FILE} and reloaded systemd." >&2
  echo "install_qadena_service.sh: To enable and start: sudo systemctl enable --now ${SERVICE_NAME}" >&2
else
  echo "install_qadena_service.sh: Installed ${DEST_FILE}. (systemctl not found; skipping daemon-reload)" >&2
fi
