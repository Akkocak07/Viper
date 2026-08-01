#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Bitte mit sudo ausfuehren: sudo ./install.sh" >&2
  exit 1
fi

install -Dm755 "$(dirname "$0")/viper.py" /usr/local/bin/viper

echo "Viper wurde nach /usr/local/bin/viper installiert."
echo "Trockenlauf: viper"
echo "Echte Ausfuehrung: sudo viper --execute"
