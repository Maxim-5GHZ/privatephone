#!/usr/bin/env bash
# install_ca.sh — import the PrivatePhone mesh CA into the OS trust store.
# After this, every node's https://<node-ip>:<port> validates with no warning,
# and WebRTC (getUserMedia) works in the subscriber browser.
#
#   scripts/install_ca.sh data/ca.crt
#
# On Windows (per-device):
#   powershell -Command "Import-Certificate -FilePath ca.crt -CertStoreLocation Cert:\LocalMachine\Root"
# On Android: Settings → Security → Install a certificate → CA certificate → select ca.crt
set -euo pipefail

CA_CERT="${1:?usage: install_ca.sh <ca.crt>}"
if [[ ! -f "$CA_CERT" ]]; then
  echo "error: no such file: $CA_CERT" >&2
  exit 2
fi

case "$(uname -s)" in
  Linux)
    if (( EUID != 0 )); then
      echo "info: need root to write to the system trust store; try with sudo" >&2
    fi
    PKI=/usr/local/share/ca-certificates
    mkdir -p "$PKI"
    cp "$CA_CERT" "$PKI/privatephone-ca.crt"
    if command -v update-ca-certificates >/dev/null 2>&1; then
      update-ca-certificates
    else
      # Debian/Ubuntu have update-ca-certificates; else try the ssl trust store.
      cp "$CA_CERT" /etc/ssl/certs/privatephone-ca.pem
      echo "installed to /etc/ssl/certs (no update-ca-certificates found)"
    fi
    ;;
  Darwin)
    security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$CA_CERT"
    echo "installed into the macOS system keychain (admin password required)"
    ;;
  *)
    echo "unsupported OS: $(uname -s)"
    echo "windows: powershell Import-Certificate -FilePath $CA_CERT -CertStoreLocation Cert:\\LocalMachine\\Root"
    exit 1
    ;;
esac

echo "mesh CA '$CA_CERT' is now trusted. Restart the browser, then open https://<node-ip>:<port>."