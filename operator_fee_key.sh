#!/usr/bin/env bash
# Generate the MMaaS operator fee hotkey OFFLINE, under the operator principal's own
# custody. Run this on your own machine — never on SaturnSwap infrastructure.
#
# Why it exists: every client's prepaid fee channel is the native script
# `any[operator_fee_vkh, client_owner_vkh]`, so the operator vkh is baked into every
# channel address. A key generated on a server we run has been in that server's memory
# and disk before anyone chose to trust it. This script inverts that: the private half
# is born on your machine and the ONLY thing that travels back is the public key hash.
#
#   bash maker_stake/operator_fee_key.sh --out-dir ~/saturnswap-operator-keys --network mainnet
#   bash maker_stake/operator_fee_key.sh --out-dir ~/saturnswap-operator-keys --network mainnet --verify
#
# Send back the OPERATOR_FEE_VKH line. Send NOTHING else. The .skey never leaves the
# machine that generated it except by your own deliberate transfer to the signing host.
set -euo pipefail

OUT_DIR=""; NETWORK=""; VERIFY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --out-dir) OUT_DIR="${2:-}"; shift 2;;
    --network) NETWORK="${2:-}"; shift 2;;
    --verify)  VERIFY=1; shift;;
    -h|--help) sed -n '2,16p' "$0"; exit 0;;
    *) echo "unknown argument: $1" >&2; exit 2;;
  esac
done

[ -n "$OUT_DIR" ] || { echo "ERROR: --out-dir is required" >&2; exit 2; }
case "$NETWORK" in
  mainnet) NET_ARG=(--mainnet);;
  testnet) NET_ARG=(--testnet-magic 1);;
  "") echo "ERROR: --network is required (mainnet|testnet); there is no default, because a testnet key used on mainnet fails only at the moment it matters" >&2; exit 2;;
  *) echo "ERROR: --network must be 'mainnet' or 'testnet', got '$NETWORK'" >&2; exit 2;;
esac

command -v cardano-cli >/dev/null 2>&1 || {
  echo "ERROR: cardano-cli not found on PATH." >&2
  echo "  Download the release binary from https://github.com/IntersectMBO/cardano-cli/releases" >&2
  echo "  and put it on your PATH. This script deliberately has no other dependency." >&2
  exit 3
}

SKEY="$OUT_DIR/operator-fee.skey"
VKEY="$OUT_DIR/operator-fee.vkey"

if [ "$VERIFY" -eq 1 ]; then
  [ -f "$VKEY" ] || { echo "ERROR: no verification key at $VKEY to verify" >&2; exit 4; }
else
  if [ -e "$SKEY" ] || [ -e "$VKEY" ]; then
    echo "ERROR: a key already exists at $OUT_DIR — refusing to overwrite it." >&2
    echo "  Re-run with --verify to re-derive its public hash, or choose another --out-dir." >&2
    exit 4
  fi
  mkdir -p "$OUT_DIR"
  chmod 700 "$OUT_DIR"
  # umask so the key is never briefly world-readable between creation and chmod
  ( umask 077; cardano-cli address key-gen --verification-key-file "$VKEY" --signing-key-file "$SKEY" )
  chmod 600 "$SKEY"
  chmod 644 "$VKEY"
fi

VKH=$(cardano-cli address key-hash --payment-verification-key-file "$VKEY")
ADDR=$(cardano-cli address build --payment-verification-key-file "$VKEY" "${NET_ARG[@]}")

cat <<EOF

  Operator fee hotkey — $NETWORK
  ------------------------------------------------------------------
  Signing key   $SKEY   (mode 600, NEVER transmit, NEVER paste)
  Verify key    $VKEY   (public)

  Send back ONLY this line:

OPERATOR_FEE_VKH=$VKH

  For your own records (public, derivable from the vkey by anyone):

OPERATOR_FEE_ADDRESS=$ADDR

  Next:
    1. Back the .skey up offline. If you lose it, every funded client fee
       channel keeps working for the client, but the operator half is
       stranded and every channel must be re-derived and re-funded.
    2. Copy the .skey yourself to the signing host at the path the keeper's
       OperatorFeeSigningKeyPath names (mode 600, containing dir 700). Do it
       from your machine; do not send it through anyone else.
    3. The vkh above goes into MmaasFeeKeeper.OperatorFeeVkh. The keeper
       refuses to start if the on-disk key does not hash to it.
EOF
