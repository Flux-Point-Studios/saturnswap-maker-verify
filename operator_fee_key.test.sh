#!/usr/bin/env bash
# Tests for operator_fee_key.sh — the OFFLINE generator deci runs on his own
# machine so the operator fee hotkey is never born on our infrastructure. Every
# case here guards a way the script could quietly hand back something unusable,
# overwrite an existing key, or leak the secret half.
#   bash maker_stake/operator_fee_key.test.sh
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
GEN="$HERE/operator_fee_key.sh"
pass=0; fail=0
check(){ if [ "$2" = "$3" ]; then pass=$((pass+1)); else fail=$((fail+1)); echo "FAIL $1: expected [$3] got [$2]"; fi; }
ok(){ if [ "$2" -eq 0 ]; then pass=$((pass+1)); else fail=$((fail+1)); echo "FAIL $1: rc=$2"; fi; }
notok(){ if [ "$2" -ne 0 ]; then pass=$((pass+1)); else fail=$((fail+1)); echo "FAIL $1: expected non-zero"; fi; }
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT

if ! command -v cardano-cli >/dev/null 2>&1; then
  echo "SKIP: no cardano-cli on PATH; operator_fee_key cases not run"
  echo "operator_fee_key.test.sh: 0 passed, 0 failed"; exit 0
fi

# generate into a clean dir
OUT="$WORK/keys"
RES=$(bash "$GEN" --out-dir "$OUT" --network mainnet 2>&1); rc=$?
ok "generates cleanly" $rc
[ -f "$OUT/operator-fee.skey" ]; ok "writes the signing key" $?
[ -f "$OUT/operator-fee.vkey" ]; ok "writes the verification key" $?

# the ONLY thing that should be transmitted is the vkh; it must be printed and be a 28-byte hash
VKH=$(grep -oE '^OPERATOR_FEE_VKH=[0-9a-f]{56}$' <<< "$RES" | cut -d= -f2)
check "prints a 56-hex vkh in a machine-readable line" "${#VKH}" "56"

# and it must actually be the hash of the generated vkey, not something decorative
DERIVED=$(cardano-cli address key-hash --payment-verification-key-file "$OUT/operator-fee.vkey")
check "the printed vkh IS the generated key's hash" "$VKH" "$DERIVED"

# the secret must never appear in what the operator is told to send back
CBOR=$(python3 -c "import json;print(json.load(open('$OUT/operator-fee.skey'))['cborHex'])")
if grep -q "$CBOR" <<< "$RES"; then fail=$((fail+1)); echo "FAIL: the signing key leaked into stdout"; else pass=$((pass+1)); fi

# file modes: secret 600, dir 700
check "skey is owner-read-only" "$(stat -c %a "$OUT/operator-fee.skey")" "600"
check "key dir is owner-only" "$(stat -c %a "$OUT")" "700"

# refuses to clobber an existing key — a second run must not destroy the first
BEFORE=$(sha256sum "$OUT/operator-fee.skey" | cut -d' ' -f1)
bash "$GEN" --out-dir "$OUT" --network mainnet >/dev/null 2>&1; notok "refuses to overwrite an existing key" $?
check "the original key is untouched" "$(sha256sum "$OUT/operator-fee.skey" | cut -d' ' -f1)" "$BEFORE"

# network is required and validated — a testnet key silently used on mainnet is a real footgun
bash "$GEN" --out-dir "$WORK/n1" >/dev/null 2>&1; notok "requires --network" $?
bash "$GEN" --out-dir "$WORK/n2" --network mainet >/dev/null 2>&1; notok "refuses a misspelled network" $?

# the address it prints must match the network it was told
RES_T=$(bash "$GEN" --out-dir "$WORK/tn" --network testnet 2>&1)
ADDR_T=$(grep -oE '^OPERATOR_FEE_ADDRESS=[a-z0-9_]+$' <<< "$RES_T" | cut -d= -f2)
case "$ADDR_T" in addr_test1*) pass=$((pass+1));; *) fail=$((fail+1)); echo "FAIL: testnet run printed [$ADDR_T]";; esac
ADDR_M=$(grep -oE '^OPERATOR_FEE_ADDRESS=[a-z0-9_]+$' <<< "$RES" | cut -d= -f2)
case "$ADDR_M" in addr1*) pass=$((pass+1));; *) fail=$((fail+1)); echo "FAIL: mainnet run printed [$ADDR_M]";; esac

# --verify re-derives from an existing key without generating anything new
V=$(bash "$GEN" --out-dir "$OUT" --network mainnet --verify 2>&1); ok "--verify succeeds on an existing key" $?
check "--verify reports the same vkh" "$(grep -oE 'OPERATOR_FEE_VKH=[0-9a-f]{56}' <<< "$V" | cut -d= -f2)" "$VKH"

echo "operator_fee_key.test.sh: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
