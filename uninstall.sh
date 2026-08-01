#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Bitte mit sudo ausfuehren: sudo ./uninstall.sh" >&2
  exit 1
fi

rm -f /usr/local/bin/viper
echo "Viper wurde entfernt."
