#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  sign_policy_external.sh \
    --policy <policy.conf> \
    --public-key <signer.pub> \
    --output <policy.signed> \
    --sign-command '<external command>'

Options:
  --policy-version <n>   Bundle policy_version (default: version_counter + 1)
  --expires <unix_ts>    Bundle expiration timestamp (default: 0 = never)

The external sign command receives the signing payload on stdin and must emit a
64-byte Ed25519 signature as 128 lowercase/uppercase hex characters on stdout.
EOF
}

POLICY=""
PUBLIC_KEY=""
OUTPUT=""
SIGN_COMMAND=""
POLICY_VERSION=""
EXPIRES="0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --policy) POLICY="${2:-}"; shift 2 ;;
    --public-key) PUBLIC_KEY="${2:-}"; shift 2 ;;
    --output) OUTPUT="${2:-}"; shift 2 ;;
    --sign-command) SIGN_COMMAND="${2:-}"; shift 2 ;;
    --policy-version) POLICY_VERSION="${2:-}"; shift 2 ;;
    --expires) EXPIRES="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "unknown arg: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "${POLICY}" || -z "${PUBLIC_KEY}" || -z "${OUTPUT}" || -z "${SIGN_COMMAND}" ]]; then
  usage >&2
  exit 2
fi

if [[ ! -f "${POLICY}" ]]; then
  echo "policy not found: ${POLICY}" >&2
  exit 1
fi
if [[ ! -f "${PUBLIC_KEY}" ]]; then
  echo "public key not found: ${PUBLIC_KEY}" >&2
  exit 1
fi

read_version_counter() {
  local path="${AEGIS_VERSION_COUNTER_PATH:-/var/lib/aegisbpf/version_counter}"
  if [[ -r "${path}" ]]; then
    awk 'NR==1{print $1+0}' "${path}"
  else
    echo "0"
  fi
}

if [[ -z "${POLICY_VERSION}" ]]; then
  POLICY_VERSION="$(( $(read_version_counter) + 1 ))"
fi

if ! [[ "${POLICY_VERSION}" =~ ^[0-9]+$ ]]; then
  echo "invalid --policy-version: ${POLICY_VERSION}" >&2
  exit 1
fi
if ! [[ "${EXPIRES}" =~ ^[0-9]+$ ]]; then
  echo "invalid --expires: ${EXPIRES}" >&2
  exit 1
fi

POLICY_SHA256="$(sha256sum "${POLICY}" | awk '{print $1}')"
TIMESTAMP="$(date +%s)"
SIGN_PAYLOAD="${POLICY_SHA256}${POLICY_VERSION}${TIMESTAMP}${EXPIRES}"

SIGNATURE_HEX="$(
  printf '%s' "${SIGN_PAYLOAD}" | bash -lc "${SIGN_COMMAND}" | tr -d ' \n\r\t'
)"
if ! [[ "${SIGNATURE_HEX}" =~ ^[0-9a-fA-F]{128}$ ]]; then
  echo "sign command did not return 128 hex chars for signature" >&2
  exit 1
fi

SIGNER_KEY_HEX="$(head -n1 "${PUBLIC_KEY}" | tr -d ' \n\r\t')"
if ! [[ "${SIGNER_KEY_HEX}" =~ ^[0-9a-fA-F]{64}$ ]]; then
  echo "public key must be 64 hex chars (Ed25519 public key)" >&2
  exit 1
fi

{
  echo "AEGIS-POLICY-BUNDLE-V1"
  echo "format_version: 1"
  echo "policy_version: ${POLICY_VERSION}"
  echo "timestamp: ${TIMESTAMP}"
  echo "expires: ${EXPIRES}"
  echo "signer_key: ${SIGNER_KEY_HEX}"
  echo "signature: ${SIGNATURE_HEX}"
  echo "policy_sha256: ${POLICY_SHA256}"
  echo "---"
  cat "${POLICY}"
} > "${OUTPUT}"

echo "signed bundle written to ${OUTPUT}"
