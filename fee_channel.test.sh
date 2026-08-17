#!/bin/bash
# Unit tests for the fee channel's chain-free guarantees: malformed key hashes are REFUSED before a
# script is written, the emitted script is the CANONICAL operator-first bytes the backend meters
# against, the channel address is always re-derived (never accepted as input), witnessing uses
# `conway transaction witness` (never `sign`), every body is VIEWED by the sign cli before it is
# witnessed and refused if it pays past the expected addresses (an unavailable view is itself a
# refusal unless FEE_CHANNEL_REQUIRE_VIEW=0), and reclaim drains every channel
# UTxO back to --dest largest-first in batches of at most 40 per tx (a dusted channel cannot strand
# the float behind maxTxSize). fund/reclaim run against a stub cardano-cli that records every
# invocation; the golden vectors run against a real cardano-cli when one is on PATH — set
# FEE_CHANNEL_REQUIRE_CLI=1 to turn a missing cardano-cli into a failure instead of a skip. The
# live fund/draw/reclaim cycle is proven separately on-chain.
# Run: bash maker_stake/fee_channel.test.sh
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=/dev/null
source "$HERE/fee_channel.sh"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
pass=0; fail=0
check(){ if [ "$2" = "$3" ]; then pass=$((pass+1)); else fail=$((fail+1)); echo "FAIL $1: expected [$3] got [$2]"; fi; }
contains(){ if grep -qF -- "$2" <<<"$1"; then pass=$((pass+1)); else fail=$((fail+1)); echo "FAIL $3: [$1] lacks [$2]"; fi; }

OP=11111111111111111111111111111111111111111111111111111111
ME=22222222222222222222222222222222222222222222222222222222
CANON='{"type":"any","scripts":[{"type":"sig","keyHash":"'$OP'"},{"type":"sig","keyHash":"'$ME'"}]}'
STUB_HASH=feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface
STUB_ADDR=addr_test1stubchannel
BIG_IN=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa#0
SMALL_IN=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb#1
CHAN_IN1=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee#0
CHAN_IN2=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff#1

# A recording cardano-cli: logs every invocation to <dir>/log and answers from <dir>/fixtures.
make_stub(){
  mkdir -p "$1/fixtures"
  cat > "$1/cardano-cli" <<'SH'
#!/bin/bash
D=$(cd "$(dirname "$0")" && pwd)
echo "$*" >> "$D/log"
out=""; prev=""
for a in "$@"; do [ "$prev" = --out-file ] && out="$a"; prev="$a"; done
case "$*" in
  "address key-hash "*) cat "$D/fixtures/keyhash";;
  "conway transaction policyid "*) cat "$D/fixtures/scripthash";;
  "address build "*) cat "$D/fixtures/addr";;
  "query utxo "*)
    if grep -qF -- "--address $(cat "$D/fixtures/addr")" <<<"$*"
    then cp "$D/fixtures/channel-utxos.json" "$out"
    else cp "$D/fixtures/fund-utxos.json" "$out"; fi;;
  "debug transaction view "*)
    case "$*" in
      *fund.body*) cat "$D/fixtures/view-fund.json";;
      *) cat "$D/fixtures/view-reclaim.json";;
    esac;;
  "conway transaction build "*) : > "$out";;
  "conway transaction txid "*) echo cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc;;
  "conway transaction witness "*) : > "$out";;
  "conway transaction assemble "*) : > "$out";;
  "conway transaction submit "*) echo "Transaction successfully submitted.";;
  *) echo "stub cardano-cli: unhandled: $*" >&2; exit 9;;
esac
SH
  chmod +x "$1/cardano-cli"
  echo "$ME" > "$1/fixtures/keyhash"
  echo "$STUB_HASH" > "$1/fixtures/scripthash"
  echo "$STUB_ADDR" > "$1/fixtures/addr"
  cat > "$1/fixtures/fund-utxos.json" <<JSON
{"$BIG_IN": {"value": {"lovelace": 100000000}, "referenceScript": null},
 "$SMALL_IN": {"value": {"lovelace": 1000000}, "referenceScript": null}}
JSON
  cat > "$1/fixtures/channel-utxos.json" <<JSON
{"$CHAN_IN1": {"value": {"lovelace": 30000000}, "referenceScript": null},
 "$CHAN_IN2": {"value": {"lovelace": 12000000}, "referenceScript": null}}
JSON
  cat > "$1/fixtures/view-fund.json" <<JSON
{"outputs": [{"address": "$STUB_ADDR", "amount": {"lovelace": 7000000}},
 {"address": "addr_test1stubfund", "amount": {"lovelace": 92800000}}]}
JSON
  cat > "$1/fixtures/view-reclaim.json" <<JSON
{"outputs": [{"address": "addr_test1dest", "amount": {"lovelace": 41800000}}]}
JSON
}
S1="$WORK/stub1"; make_stub "$S1"
touch "$WORK/client.skey"

# --- usage errors: wrong invocations die with exit 2 before any key is looked at ---
out=$(bash "$HERE/fee_channel.sh" 2>&1); rc=$?
check "no arguments is a usage error" "$rc" 2
contains "$out" "missing required --operator-fee-vkh" "the usage error names the missing flag"
out=$(bash "$HERE/fee_channel.sh" --channel-addr addr1qqq 2>&1); rc=$?
check "a channel address is never an accepted input" "$rc" 2
contains "$out" "unknown argument: --channel-addr" "the unknown flag is named"
out=$(bash "$HERE/fee_channel.sh" --mode drain --operator-fee-vkh "$OP" --my-vkh "$ME" 2>&1); rc=$?
check "an unknown mode is a usage error" "$rc" 2
out=$(bash "$HERE/fee_channel.sh" --operator-fee-vkh "$OP" 2>&1); rc=$?
check "a missing client key is a usage error" "$rc" 2
contains "$out" "missing required --my-vkh or --my-vkey-file" "the usage error names both client-key flags"
out=$(bash "$HERE/fee_channel.sh" --operator-fee-vkh "$OP" --my-vkh "$ME" --my-vkey-file x.vkey 2>&1); rc=$?
check "passing both client-key flags is a usage error" "$rc" 2
out=$(bash "$HERE/fee_channel.sh" --mode fund --operator-fee-vkh "$OP" --my-vkh "$ME" \
      --fund-addr addr_test1stubfund --signing-key "$WORK/client.skey" 2>&1); rc=$?
check "fund without --amount is a usage error" "$rc" 2
out=$(bash "$HERE/fee_channel.sh" --mode fund --operator-fee-vkh "$OP" --my-vkh "$ME" --amount 5ADA \
      --fund-addr addr_test1stubfund --signing-key "$WORK/client.skey" 2>&1); rc=$?
check "a non-integer amount is a usage error" "$rc" 2
out=$(bash "$HERE/fee_channel.sh" --mode reclaim --operator-fee-vkh "$OP" --my-vkh "$ME" \
      --signing-key "$WORK/client.skey" 2>&1); rc=$?
check "reclaim without --dest is a usage error" "$rc" 2

# --- refusals: a key hash that is not exactly 56 lowercase hex chars must never reach a script ---
out=$(validate_vkh "operator fee vkh" "${OP:0:55}" 2>&1); rc=$?
check "a 55-char vkh is refused" "$rc" 3
contains "$out" "REFUSING:" "the short-vkh refusal is explicit"
out=$(validate_vkh "operator fee vkh" "${OP}1" 2>&1); rc=$?
check "a 57-char vkh is refused" "$rc" 3
out=$(validate_vkh "client vkh" "${OP:0:55}A" 2>&1); rc=$?
check "an uppercase vkh is refused" "$rc" 3
contains "$out" "REFUSING:" "the uppercase refusal is explicit"
out=$(validate_vkh "client vkh" "${OP:0:55}g" 2>&1); rc=$?
check "a non-hex vkh is refused" "$rc" 3
DR="$WORK/refuse"; mkdir -p "$DR"
out=$(bash "$HERE/fee_channel.sh" --operator-fee-vkh "${OP:0:55}A" --my-vkh "$ME" \
      --out-dir "$DR" --cardano-cli "$S1/cardano-cli" 2>&1); rc=$?
check "the tool exits 3 on a malformed operator vkh" "$rc" 3
contains "$out" "REFUSING:" "the tool-level refusal is explicit"
check "nothing is written before the refusal" "$([ -f "$DR/channel.json" ] && echo present || echo absent)" "absent"
out=$(bash "$HERE/fee_channel.sh" --operator-fee-vkh "$OP" --my-vkh "${ME:0:54}" \
      --out-dir "$DR" --cardano-cli "$S1/cardano-cli" 2>&1); rc=$?
check "the tool exits 3 on a malformed client vkh" "$rc" 3

# --- canonical bytes: operator key FIRST, client key SECOND — the cross-repo channel contract ---
write_channel_script "$OP" "$ME" "$WORK/canon.json"
check "write_channel_script emits the canonical operator-first bytes" "$(cat "$WORK/canon.json")" "$CANON"
D1="$WORK/derive1"; mkdir -p "$D1"
out=$(bash "$HERE/fee_channel.sh" --my-vkh "$ME" --operator-fee-vkh "$OP" \
      --out-dir "$D1" --cardano-cli "$S1/cardano-cli" 2>&1); rc=$?
check "derive succeeds against the stub" "$rc" 0
contains "$out" "$STUB_HASH" "derive prints the script hash"
contains "$out" "$STUB_ADDR" "derive prints the channel address"
check "derive orders keys by role, not argv order" "$(cat "$D1/channel.json")" "$CANON"
D2="$WORK/derive2"; mkdir -p "$D2"
echo stub-vkey > "$WORK/client.vkey"
out=$(bash "$HERE/fee_channel.sh" --operator-fee-vkh "$OP" --my-vkey-file "$WORK/client.vkey" \
      --out-dir "$D2" --cardano-cli "$S1/cardano-cli" 2>&1); rc=$?
check "derive accepts a vkey file for the client key" "$rc" 0
check "the vkey-derived hash lands in the canonical client slot" "$(cat "$D2/channel.json")" "$CANON"

if command -v python3 >/dev/null 2>&1; then
  # --- fund: a plain payment from the client wallet to the RE-DERIVED channel address ---
  : > "$S1/log"
  D3="$WORK/fund1"; mkdir -p "$D3"
  out=$(bash "$HERE/fee_channel.sh" --mode fund --operator-fee-vkh "$OP" --my-vkh "$ME" \
        --amount 7000000 --fund-addr addr_test1stubfund --signing-key "$WORK/client.skey" \
        --out-dir "$D3" --cardano-cli "$S1/cardano-cli" 2>&1); rc=$?
  check "fund succeeds against the stub" "$rc" 0
  log=$(cat "$S1/log")
  contains "$log" "--tx-out $STUB_ADDR+7000000" "fund pays the re-derived channel address"
  contains "$log" "--tx-in $BIG_IN" "fund selects the largest wallet UTxO"
  check "fund leaves the unneeded small UTxO alone" "$(grep -cF -- "--tx-in $SMALL_IN" "$S1/log")" "0"
  contains "$log" "conway transaction witness" "signing goes through transaction witness"
  check "transaction sign is never invoked" "$(grep -cF "transaction sign" "$S1/log")" "0"
  contains "$log" "conway transaction submit" "the signed fund tx is submitted"
  contains "$log" "debug transaction view" "the fund body is viewed before witnessing"
  contains "$out" "verified:" "the fund output summary is printed for eyeballing"
  v=$(grep -nF -m1 "debug transaction view" "$S1/log" | cut -d: -f1)
  w=$(grep -nF -m1 "conway transaction witness" "$S1/log" | cut -d: -f1)
  check "the view precedes the witness" "$(( ${v:-9999} < ${w:-0} ))" "1"
  out=$(bash "$HERE/fee_channel.sh" --mode fund --operator-fee-vkh "$OP" --my-vkh "$ME" \
        --amount 200000000 --fund-addr addr_test1stubfund --signing-key "$WORK/client.skey" \
        --out-dir "$D3" --cardano-cli "$S1/cardano-cli" 2>&1); rc=$?
  check "fund exits 4 when the wallet cannot cover amount plus fee" "$rc" 4
  # --- the air-gapped signer: --sign-cli witnesses, the trusted node never sees the key step ---
  S2="$WORK/stub2"; make_stub "$S2"
  : > "$S1/log"
  out=$(bash "$HERE/fee_channel.sh" --mode fund --operator-fee-vkh "$OP" --my-vkh "$ME" \
        --amount 7000000 --fund-addr addr_test1stubfund --signing-key "$WORK/client.skey" \
        --out-dir "$D3" --cardano-cli "$S1/cardano-cli" --sign-cli "$S2/cardano-cli" 2>&1); rc=$?
  check "fund succeeds with a separate sign-cli" "$rc" 0
  contains "$(cat "$S2/log")" "conway transaction witness" "the air-gapped signer produces the witness"
  check "the trusted node never runs the witness step" "$(grep -cF "transaction witness" "$S1/log")" "0"
  contains "$(cat "$S1/log")" "conway transaction submit" "the trusted node still submits"
  contains "$(cat "$S2/log")" "debug transaction view" "the air-gapped signer itself views the body"
  check "the trusted node never views for the signer" "$(grep -c "transaction view" "$S1/log")" "0"
  # --- reclaim: every channel UTxO goes back to --dest on the client witness alone ---
  : > "$S1/log"
  D4="$WORK/reclaim1"; mkdir -p "$D4"
  out=$(bash "$HERE/fee_channel.sh" --mode reclaim --operator-fee-vkh "$OP" --my-vkh "$ME" \
        --dest addr_test1dest --signing-key "$WORK/client.skey" \
        --out-dir "$D4" --cardano-cli "$S1/cardano-cli" 2>&1); rc=$?
  check "reclaim succeeds against the stub" "$rc" 0
  log=$(cat "$S1/log")
  contains "$log" "--tx-in $CHAN_IN1 --tx-in-script-file $D4/channel.json" "reclaim spends channel UTxO 1 with the channel script"
  contains "$log" "--tx-in $CHAN_IN2 --tx-in-script-file $D4/channel.json" "reclaim spends channel UTxO 2 with the channel script"
  contains "$log" "--change-address addr_test1dest" "the whole channel balance changes to --dest"
  contains "$log" "--required-signer-hash $ME" "the client key is the declared signer"
  contains "$log" "conway transaction witness" "reclaim signs through transaction witness"
  contains "$log" "conway transaction submit" "the signed reclaim tx is submitted"
  S3="$WORK/stub3"; make_stub "$S3"
  echo '{}' > "$S3/fixtures/channel-utxos.json"
  out=$(bash "$HERE/fee_channel.sh" --mode reclaim --operator-fee-vkh "$OP" --my-vkh "$ME" \
        --dest addr_test1dest --signing-key "$WORK/client.skey" \
        --out-dir "$D4" --cardano-cli "$S3/cardano-cli" 2>&1); rc=$?
  check "reclaiming an empty channel exits 4" "$rc" 4
  contains "$out" "nothing to reclaim" "the empty channel is named"

  # --- reclaim --max-batches ---
  # Dusting the channel is cheap and public: anyone can push hundreds of tiny UTxOs at it. Reclaim
  # drains 40 inputs per tx, so an unbounded loop makes the CLIENT pay a fee per batch to recover
  # their own float, with no way to bound the spend. The cap stops on a batch boundary — every
  # earlier batch has already landed — and says what is left, so re-running resumes.
  S5B="$WORK/stub5b"; make_stub "$S5B"
  python3 - "$S5B/fixtures/channel-utxos.json" <<'PY'
import json, sys
# 85 UTxOs: two full batches of 40, then a 5-UTxO remainder.
json.dump({f"{i:064x}#0": {"value": {"lovelace": 2000000 + i}} for i in range(85)},
          open(sys.argv[1], "w"))
PY
  D5B="$WORK/reclaim-capped"; mkdir -p "$D5B"
  out=$(bash "$HERE/fee_channel.sh" --mode reclaim --operator-fee-vkh "$OP" --my-vkh "$ME" \
        --dest addr_test1dest --signing-key "$WORK/client.skey" --max-batches 2 \
        --out-dir "$D5B" --cardano-cli "$S5B/cardano-cli" 2>&1); rc=$?
  check "a capped reclaim exits 5, not 0" "$rc" 5
  contains "$out" "5 channel UTxO(s) remain" "the remainder is named so the client can re-run"
  check "the cap stopped it at 2 batches" "$(grep -c 'conway transaction build ' "$S5B/log")" "2"

  S5C="$WORK/stub5c"; make_stub "$S5C"
  out=$(bash "$HERE/fee_channel.sh" --mode reclaim --operator-fee-vkh "$OP" --my-vkh "$ME" \
        --dest addr_test1dest --signing-key "$WORK/client.skey" --max-batches nonsense \
        --out-dir "$D5B" --cardano-cli "$S5C/cardano-cli" 2>&1); rc=$?
  check "a non-numeric --max-batches is a usage error" "$rc" 2

  # Uncapped stays uncapped: the default must not silently start truncating a drain.
  S5D="$WORK/stub5d"; make_stub "$S5D"
  cp "$S5B/fixtures/channel-utxos.json" "$S5D/fixtures/channel-utxos.json"
  D5D="$WORK/reclaim-uncapped"; mkdir -p "$D5D"
  out=$(bash "$HERE/fee_channel.sh" --mode reclaim --operator-fee-vkh "$OP" --my-vkh "$ME" \
        --dest addr_test1dest --signing-key "$WORK/client.skey" \
        --out-dir "$D5D" --cardano-cli "$S5D/cardano-cli" 2>&1); rc=$?
  check "an uncapped reclaim still drains fully" "$rc" 0
  check "and takes all three batches" "$(grep -c 'conway transaction build ' "$S5D/log")" "3"

  # --- the view gate: a body paying anywhere unexpected is refused UNSIGNED, exit 3 ---
  S4="$WORK/stub4"; make_stub "$S4"
  cat > "$S4/fixtures/view-fund.json" <<JSON
{"outputs": [{"address": "$STUB_ADDR", "amount": {"lovelace": 7000000}},
 {"address": "addr_test1attacker", "amount": {"lovelace": 92800000}}]}
JSON
  out=$(bash "$HERE/fee_channel.sh" --mode fund --operator-fee-vkh "$OP" --my-vkh "$ME" \
        --amount 7000000 --fund-addr addr_test1stubfund --signing-key "$WORK/client.skey" \
        --out-dir "$D3" --cardano-cli "$S4/cardano-cli" 2>&1); rc=$?
  check "fund refuses a body that pays an unexpected address" "$rc" 3
  contains "$out" "REFUSING:" "the fund view refusal is explicit"
  contains "$out" "addr_test1attacker" "the refusal names the rogue address"
  check "the rogue fund body is never witnessed" "$(grep -cF "transaction witness" "$S4/log")" "0"
  check "the rogue fund body is never submitted" "$(grep -cF "transaction submit" "$S4/log")" "0"
  S5="$WORK/stub5"; make_stub "$S5"
  cat > "$S5/fixtures/view-reclaim.json" <<JSON
{"outputs": [{"address": "addr_test1attacker", "amount": {"lovelace": 41800000}}]}
JSON
  out=$(bash "$HERE/fee_channel.sh" --mode reclaim --operator-fee-vkh "$OP" --my-vkh "$ME" \
        --dest addr_test1dest --signing-key "$WORK/client.skey" \
        --out-dir "$D4" --cardano-cli "$S5/cardano-cli" 2>&1); rc=$?
  check "reclaim refuses a body that pays past --dest" "$rc" 3
  contains "$out" "REFUSING:" "the reclaim view refusal is explicit"
  check "the rogue reclaim body is never witnessed" "$(grep -cF "transaction witness" "$S5/log")" "0"
  S6="$WORK/stub6"; make_stub "$S6"
  echo '{"outputs": []}' > "$S6/fixtures/view-fund.json"
  out=$(bash "$HERE/fee_channel.sh" --mode fund --operator-fee-vkh "$OP" --my-vkh "$ME" \
        --amount 7000000 --fund-addr addr_test1stubfund --signing-key "$WORK/client.skey" \
        --out-dir "$D3" --cardano-cli "$S6/cardano-cli" 2>&1); rc=$?
  check "a body with no outputs at all is refused" "$rc" 3
  # --- an unavailable view (no view command, unrecognized schema) is a REFUSAL by default;
  # FEE_CHANNEL_REQUIRE_VIEW=0 downgrades it to a loud warning NAMING the skipped check ---
  S7="$WORK/stub7"; make_stub "$S7"; rm "$S7"/fixtures/view-*.json
  out=$(bash "$HERE/fee_channel.sh" --mode fund --operator-fee-vkh "$OP" --my-vkh "$ME" \
        --amount 7000000 --fund-addr addr_test1stubfund --signing-key "$WORK/client.skey" \
        --out-dir "$D3" --cardano-cli "$S7/cardano-cli" 2>&1); rc=$?
  check "fund refuses by default when the cli cannot view" "$rc" 3
  contains "$out" "REFUSING: pre-witness output check unavailable" "the no-view refusal is explicit"
  contains "$out" "FEE_CHANNEL_REQUIRE_VIEW=0" "the refusal names the override knob"
  check "the unviewable body is never witnessed" "$(grep -cF "transaction witness" "$S7/log")" "0"
  check "the unviewable body is never submitted" "$(grep -cF "transaction submit" "$S7/log")" "0"
  : > "$S7/log"
  out=$(FEE_CHANNEL_REQUIRE_VIEW=0 bash "$HERE/fee_channel.sh" --mode fund --operator-fee-vkh "$OP" --my-vkh "$ME" \
        --amount 7000000 --fund-addr addr_test1stubfund --signing-key "$WORK/client.skey" \
        --out-dir "$D3" --cardano-cli "$S7/cardano-cli" 2>&1); rc=$?
  check "FEE_CHANNEL_REQUIRE_VIEW=0 proceeds when the cli cannot view" "$rc" 0
  contains "$out" "SKIPPING the pre-witness output-address check" "the warning names the skipped check"
  contains "$(cat "$S7/log")" "conway transaction submit" "the unviewable body still submits unverified"
  S8="$WORK/stub8"; make_stub "$S8"
  echo "auxiliary scripts: null" > "$S8/fixtures/view-fund.json"
  out=$(bash "$HERE/fee_channel.sh" --mode fund --operator-fee-vkh "$OP" --my-vkh "$ME" \
        --amount 7000000 --fund-addr addr_test1stubfund --signing-key "$WORK/client.skey" \
        --out-dir "$D3" --cardano-cli "$S8/cardano-cli" 2>&1); rc=$?
  check "an undecodable view is refused by default" "$rc" 3
  contains "$out" "REFUSING: pre-witness output check unavailable" "the undecodable-view refusal is explicit"
  check "the undecoded body is never witnessed" "$(grep -cF "transaction witness" "$S8/log")" "0"
  : > "$S8/log"
  out=$(FEE_CHANNEL_REQUIRE_VIEW=0 bash "$HERE/fee_channel.sh" --mode fund --operator-fee-vkh "$OP" --my-vkh "$ME" \
        --amount 7000000 --fund-addr addr_test1stubfund --signing-key "$WORK/client.skey" \
        --out-dir "$D3" --cardano-cli "$S8/cardano-cli" 2>&1); rc=$?
  check "FEE_CHANNEL_REQUIRE_VIEW=0 downgrades the undecodable view to the warning" "$rc" 0
  contains "$out" "SKIPPING the pre-witness output-address check" "the parse-failure warning names the check"

  # --- batching: a dusted channel drains at most 40 UTxOs per tx, largest first, until empty ---
  S9="$WORK/stub9"; make_stub "$S9"
  python3 - "$S9/fixtures/channel-utxos.json" <<'PY'
import json, sys
u = {format(i, "064x") + f"#{i}": {"value": {"lovelace": 1_000_000 + i * 1_000}, "referenceScript": None}
     for i in range(43)}
json.dump(u, open(sys.argv[1], "w"))
PY
  D5="$WORK/reclaim2"; mkdir -p "$D5"
  out=$(bash "$HERE/fee_channel.sh" --mode reclaim --operator-fee-vkh "$OP" --my-vkh "$ME" \
        --dest addr_test1dest --signing-key "$WORK/client.skey" \
        --out-dir "$D5" --cardano-cli "$S9/cardano-cli" 2>&1); rc=$?
  check "a 43-UTxO reclaim succeeds" "$rc" 0
  check "43 UTxOs drain in two batches" "$(grep -cF "conway transaction submit" "$S9/log")" "2"
  check "every batch re-queries the channel" "$(grep -cF "query utxo" "$S9/log")" "3"
  b1=$(grep -F "conway transaction build " "$S9/log" | head -1)
  b2=$(grep -F "conway transaction build " "$S9/log" | tail -1)
  check "batch 1 takes exactly 40 inputs" "$(grep -oF -- "--tx-in " <<<"$b1" | wc -l)" "40"
  check "batch 2 takes the remaining 3" "$(grep -oF -- "--tx-in " <<<"$b2" | wc -l)" "3"
  top=$(printf '%064x' 42); low=$(printf '%064x' 0)
  contains "$b1" "--tx-in $top#42 " "the largest UTxO drains first"
  check "the smallest UTxO waits for batch 2" "$(grep -cF -- "--tx-in $low#0 " <<<"$b1")" "0"
  contains "$b2" "--tx-in $low#0 " "the smallest UTxO drains last"
  contains "$out" "batch 2: reclaiming 3 of 3" "the batch progress is narrated"
else
  echo "SKIP: no python3 on PATH; fund/reclaim cases not run"
fi

# --- the golden vector, against a REAL cardano-cli: the canonical bytes hash to the exact
# credential and enterprise addresses the backend meters against ---
if command -v cardano-cli >/dev/null 2>&1; then
  GM="$WORK/golden-mainnet"; mkdir -p "$GM"
  out=$(bash "$HERE/fee_channel.sh" --operator-fee-vkh "$OP" --my-vkh "$ME" \
        --network mainnet --out-dir "$GM" 2>&1); rc=$?
  check "golden mainnet derive succeeds against the real cardano-cli" "$rc" 0
  contains "$out" "254e553a131b6c13c02d1b4c849da6eb8803ce5984a1426827f21399" "the golden script hash"
  contains "$out" "addr1wyj5u4f6zvdkcy7q95d5epya5m4csq7wtxz2zsngylep8xgmqlyqn" "the golden mainnet address"
  check "the golden hash comes from the canonical bytes" "$(cat "$GM/channel.json")" "$CANON"
  GP="$WORK/golden-preprod"; mkdir -p "$GP"
  out=$(bash "$HERE/fee_channel.sh" --operator-fee-vkh "$OP" --my-vkh "$ME" \
        --network preprod --out-dir "$GP" 2>&1); rc=$?
  check "golden preprod derive succeeds against the real cardano-cli" "$rc" 0
  contains "$out" "addr_test1wqj5u4f6zvdkcy7q95d5epya5m4csq7wtxz2zsngylep8xgqgtc0k" "the golden preprod address"
  cardano-cli address key-gen --verification-key-file "$WORK/real.vkey" \
    --signing-key-file "$WORK/real.skey" >/dev/null 2>&1
  REAL_VKH=$(cardano-cli address key-hash --payment-verification-key-file "$WORK/real.vkey")
  GV="$WORK/golden-vkey"; mkdir -p "$GV"
  out=$(bash "$HERE/fee_channel.sh" --operator-fee-vkh "$OP" --my-vkey-file "$WORK/real.vkey" \
        --network preprod --out-dir "$GV" 2>&1); rc=$?
  check "a real vkey file derives the client key" "$rc" 0
  contains "$(cat "$GV/channel.json")" "\"keyHash\":\"$REAL_VKH\"}]}" "the real vkey hash lands in the client (second) slot"
  # --- the view gate against the REAL cli: raw body outputs are decoded and policed ---
  if command -v python3 >/dev/null 2>&1; then
    GB="$WORK/golden-view"; mkdir -p "$GB"
    cardano-cli conway transaction build-raw --tx-in "$BIG_IN" \
      --tx-out "addr1wyj5u4f6zvdkcy7q95d5epya5m4csq7wtxz2zsngylep8xgmqlyqn+5000000" \
      --fee 200000 --out-file "$GB/probe.body"
    out=$(verify_body_outputs cardano-cli "$GB/probe.body" \
          addr1wyj5u4f6zvdkcy7q95d5epya5m4csq7wtxz2zsngylep8xgmqlyqn 2>&1); rc=$?
    check "the real cli view passes a body paying only the expected address" "$rc" 0
    contains "$out" "5000000 lovelace" "the real view summary shows the output"
    out=$(verify_body_outputs cardano-cli "$GB/probe.body" addr_test1elsewhere 2>&1); rc=$?
    check "the real cli view refuses a body paying an unexpected address" "$rc" 3
    contains "$out" "REFUSING:" "the real-view refusal is explicit"
  else
    echo "SKIP: no python3 on PATH; real-cli view cases not run"
  fi
elif [ "${FEE_CHANNEL_REQUIRE_CLI:-0}" = 1 ]; then
  fail=$((fail+1)); echo "FAIL: FEE_CHANNEL_REQUIRE_CLI=1 but no cardano-cli is on PATH; golden-vector cases cannot run"
else
  echo "SKIP: no cardano-cli on PATH; golden-vector cases not run"
fi


# --- bare_txid: cardano-cli >= 10.16 prints JSON, older prints bare hex ---
HASH=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
check "bare_txid accepts bare hex" "$(bare_txid "$HASH")" "$HASH"
check "bare_txid accepts trailing newline" "$(bare_txid "$HASH
")" "$HASH"
check "bare_txid unwraps the 10.16 json object" "$(bare_txid '{
    "txhash": "'"$HASH"'"
}')" "$HASH"
check "bare_txid unwraps a bare json string" "$(bare_txid "\"$HASH\"")" "$HASH"
out=$(bare_txid "not a hash" 2>&1); rc=$?
check "bare_txid refuses junk (rc)" "$rc" "4"
contains "$out" "REFUSING:" "bare_txid refusal names itself"
out=$(bare_txid "${HASH}ff" 2>&1); rc=$?
check "bare_txid refuses a wrong-length hash (rc)" "$rc" "4"

# ---- Option C: any[ all[opA, opB], client ] ----
# The operator branch becomes 2-of-2 across INDEPENDENT infrastructure, so a single stolen
# operator key signs nothing. The client branch stays one key: reclaim must never get harder.
# Golden vector is cardano-cli's own output, pinned identically in the backend's C# tests.
G_OPA=6d99d7c84a098cec49453910df1a9c20b142bd2632e2eaff4cd58e7d
G_OPB=b38ba0f20b899261c5d5265b22e63abf6f2c28eecf7eeaf23c210d03
G_CLI=559c89b84c94f8569039b74f54a3f7f6852a79aacf67e6cdf2b89823
G_HASH=20ed63ab23efb5a8bce245143ffdf09369aca06036ec97916bd2ab1f
G_ADDR_M=addr1wysw6caty0hmt29uufz3g0la7zfknt9qvqmwe9u3d0f2k8c6262s4
G_ADDR_P=addr_test1wqsw6caty0hmt29uufz3g0la7zfknt9qvqmwe9u3d0f2k8cpzwkls

W2=$(mktemp -d)
# refusals are asserted by exit code; the suite has no notok, so define it locally
notok(){ if [ "$2" -ne 0 ]; then pass=$((pass+1)); else fail=$((fail+1)); echo "FAIL $1: expected a refusal, got rc=0"; fi; }
S2="$WORK/stub2"; make_stub "$S2"
write_channel_script_2of2 "$G_OPA" "$G_OPB" "$G_CLI" "$W2/c.json"
check_2of2_json=$(cat "$W2/c.json")
EXPECT='{"type":"any","scripts":[{"type":"all","scripts":[{"type":"sig","keyHash":"'$G_OPA'"},{"type":"sig","keyHash":"'$G_OPB'"}]},{"type":"sig","keyHash":"'$G_CLI'"}]}'
check "2of2 canonical json nests the operator branch under all" "$check_2of2_json" "$EXPECT"

# distinctness: the same key twice is a 2-of-2 one stolen key satisfies
derive_channel_2of2 "$S2/cardano-cli" "$G_OPA" "$G_OPA" "$G_CLI" "--mainnet" "$W2" >/dev/null 2>&1
notok "refuses the same operator key twice" $?
derive_channel_2of2 "$S2/cardano-cli" "$G_OPA" "$G_CLI" "$G_CLI" "--mainnet" "$W2" >/dev/null 2>&1
notok "refuses an operator key equal to the client key" $?
derive_channel_2of2 "$S2/cardano-cli" "zz$(printf 'a%.0s' {1..54})" "$G_OPB" "$G_CLI" "--mainnet" "$W2" >/dev/null 2>&1
notok "refuses a malformed operator key" $?

if command -v cardano-cli >/dev/null 2>&1; then
  derive_channel_2of2 cardano-cli "$G_OPA" "$G_OPB" "$G_CLI" "--mainnet" "$W2" >/dev/null
  check "2of2 hash matches the cross-repo golden vector" "$CHANNEL_HASH" "$G_HASH"
  check "2of2 mainnet address matches the golden vector" "$CHANNEL_ADDR" "$G_ADDR_M"
  derive_channel_2of2 cardano-cli "$G_OPA" "$G_OPB" "$G_CLI" "--testnet-magic 1" "$W2" >/dev/null
  check "2of2 preprod address matches the golden vector" "$CHANNEL_ADDR" "$G_ADDR_P"
  # key order is part of the address: a swap is a VALID script at a DIFFERENT address
  derive_channel_2of2 cardano-cli "$G_OPB" "$G_OPA" "$G_CLI" "--mainnet" "$W2" >/dev/null
  if [ "$CHANNEL_HASH" = "$G_HASH" ]; then fail=$((fail+1)); echo "FAIL: swapping opA/opB did not change the address"; else pass=$((pass+1)); fi
else
  echo "SKIP: no cardano-cli on PATH; 2of2 golden-vector cases not run"
fi
rm -rf "$W2"


# ---- the CLI must DISPATCH to the 2-of-2, not merely be able to derive it ----
# proof-audit finding: derive_channel_2of2 existed and was tested, but the executable
# path called derive_channel for every mode and --operator-fee-vkh-b was not even an
# argument. A client following this tool would fund an address the keeper cannot draw
# from. Tested through the REAL entry point, because the gap was exactly that the
# function nobody called was green.
SELF="$HERE/fee_channel.sh"
if command -v cardano-cli >/dev/null 2>&1; then
  OUT2=$(bash "$SELF" --mode derive --network preprod \
    --operator-fee-vkh "$G_OPA" --operator-fee-vkh-b "$G_OPB" --my-vkh "$G_CLI" \
    --out-dir "$WORK/cli2of2" 2>&1); rc=$?
  check "the CLI accepts --operator-fee-vkh-b" "$rc" "0"
  contains "$OUT2" "$G_ADDR_P" "the CLI derives the 2-of-2 address end to end"
  J=$(cat "$WORK/cli2of2/channel.json" 2>/dev/null)
  contains "$J" '"type":"all"' "the CLI writes the nested all-branch script"

  # and the 1-of-2 path must be untouched when no second key is given
  OUT1=$(bash "$SELF" --mode derive --network preprod \
    --operator-fee-vkh "$G_OPA" --my-vkh "$G_CLI" --out-dir "$WORK/cli1of2" 2>&1)
  J1=$(cat "$WORK/cli1of2/channel.json" 2>/dev/null)
  if grep -q '"type":"all"' <<< "$J1"; then
    fail=$((fail+1)); echo "FAIL: a 1-of-2 invocation emitted an all-branch"
  else pass=$((pass+1)); fi
  if [ "$(sed -n 's/.*channel address: *//p' <<< "$OUT1")" = "$G_ADDR_P" ]; then
    fail=$((fail+1)); echo "FAIL: 1-of-2 and 2-of-2 derived the SAME address"
  else pass=$((pass+1)); fi
else
  echo "SKIP: no cardano-cli on PATH; CLI 2of2 dispatch cases not run"
fi

echo "fee_channel.test.sh: $pass passed, $fail failed"
[ "$fail" -eq 0 ]