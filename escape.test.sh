#!/bin/bash
# Unit tests for the escape hatch's one security-critical, chain-free decision: it attaches ONLY
# scripts it rebuilt from public sources AND proved hash-equal to the credential the ceremony named.
# A substituted script — a spend validator that pays somewhere else, a bound script that drops the
# escape branch — must be refused before any transaction is built. The on-chain recovery itself is
# proven separately against live preprod (see the escape runbook / recorded tx hashes).
# Run: bash maker_stake/escape.test.sh
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=/dev/null
source "$HERE/escape.sh"

AIKEN="${AIKEN:-$HOME/.aiken/bin/aiken}"
CS_PLUTUS="${CS_PLUTUS:-/home/worker/cardano-swaps/aiken/plutus.json}"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
pass=0; fail=0
check(){ if [ "$2" = "$3" ]; then pass=$((pass+1)); else fail=$((fail+1)); echo "FAIL $1: expected [$3] got [$2]"; fi; }
contains(){ if grep -qF -- "$2" <<<"$1"; then pass=$((pass+1)); else fail=$((fail+1)); echo "FAIL $3: [$1] lacks [$2]"; fi; }

# A skip is what a suite nobody runs looks like from the outside, and this one was
# red for ten cases before anybody noticed. Where the blueprint is meant to be
# present — CI — its absence is a failure.
[ -f "$CS_PLUTUS" ] || {
  [ "${ESCAPE_REQUIRE_BLUEPRINT:-0}" = 1 ] && {
    echo "FAIL: cardano-swaps blueprint not at $CS_PLUTUS and ESCAPE_REQUIRE_BLUEPRINT=1"; exit 1; }
  echo "SKIP: cardano-swaps blueprint not at $CS_PLUTUS"; exit 0; }

# The public ceremony artefact a real client holds, produced by the tool itself (not hand-written).
cat > "$WORK/params.json" <<'JSON'
{
  "adam_bot_pkh": "e5de5661f9d883a58189fb7947e6e45cbf862025d5d472bcd3006fb6",
  "client_owner_vkh": "559c89b84c94f8569039b74f54a3f7f6852a79aacf67e6cdf2b89823",
  "client_payout_address": "addr_test1vp2eezdcfj20s45s8xm5749r7lmg22ne4t8k0ekd72ufsgc7vj5pv",
  "dapp_hash": "11928a3ac3b65edbf103ea6bb3362e39b879a36f02897df31c40917b",
  "beacon_id": "8a199a17ef4517215945aaf3c8c5204c60fd94d34c46d341e99c8fcf",
  "min_asset1_price": {"numerator": 1, "denominator": 2600000},
  "min_asset2_price": {"numerator": 2700000, "denominator": 1},
  "fee_address": "addr_test1vru3jg02gk49p9t8vw345qr47w9czcaavja4mfh09zcch3guttqnu",
  "fee_bps": 20
}
JSON
# The rehearsal ceremony's APPLIED script hash, pinned INDEPENDENTLY on purpose: the checks below
# compare the escape hatch's own emitted bound.plutus against it, so deriving it from the same tool
# that produced that file would make them tautological.
#
# ⚠️ It is one of FIVE places this repo writes down a fact derived from the validator, and every one
# of them moves when the validator does. When `fee_ok` changed, four were updated and this was
# missed — found only because something finally ran the gate. They are:
#     escape.test.sh              APPLIED                (here)
#     verify_project.sh           EXPECTED_BOUND         (the UNAPPLIED hash)
#     verify_ceremony_test.py     GOLDEN_APPLIED_HASH, GOLDEN_UNAPPLIED_HASH, GOLDEN_REWARD_ADDR
#     verify_ceremony_test.py     GOLDEN_POSSESSION_PROOFS  (signatures — must be RE-MINTED, not edited)
#     verify_ceremony_test.py     the challenge pin in test_the_challenge_wire_format_is_pinned
APPLIED=3f699f24522ad436ff43dd0b03353a16d0ccca14163d0c0b358867b3
DAPP=11928a3ac3b65edbf103ea6bb3362e39b879a36f02897df31c40917b
BEACON=8a199a17ef4517215945aaf3c8c5204c60fd94d34c46d341e99c8fcf

# --- the client rebuilds all three scripts from public inputs and they match the ceremony ---
G="$WORK/good"; mkdir -p "$G"
out=$(rebuild_and_verify_scripts "$WORK/params.json" testnet "$CS_PLUTUS" "$HERE" "$AIKEN" "$G" 2>&1); rc=$?
check "the client rebuilds every script from public inputs" "$rc" 0
contains "$out" "verified bound.plutus == $APPLIED" "bound script matches the ceremony's applied hash"
contains "$out" "verified twoway_spend.plutus == $DAPP" "spend script matches dapp_hash"
contains "$out" "verified twoway_beacon.plutus == $BEACON" "beacon script matches beacon_id"
# and the emitted files independently hash to those credentials (the values the tx attaches)
check "bound.plutus really hashes to the applied credential" "$(script_hash "$G/bound.plutus" 3)" "$APPLIED"
check "twoway_spend.plutus really hashes to dapp_hash" "$(script_hash "$G/twoway_spend.plutus" 2)" "$DAPP"
check "twoway_beacon.plutus really hashes to beacon_id" "$(script_hash "$G/twoway_beacon.plutus" 2)" "$BEACON"
# the bound script the withdraw-0 attaches IS the stake credential of the address holding the funds
ORDER_STAKE=$(python3 -c "import json;print(json.load(open('$G/artefact.json'))['derived']['order_address'])" | python3 -c "
import sys
CH='qpzry9x8gf2tvdw0s3jn54khce6mua7l'; s=sys.stdin.read().strip(); d=[CH.index(c) for c in s[s.rfind('1')+1:]]
acc=bits=0; out=bytearray()
for v in d[:-6]:
    acc=(acc<<5)|v; bits+=5
    if bits>=8: bits-=8; out.append((acc>>bits)&0xff)
print(out[29:57].hex())")
check "bound.plutus IS the order address's stake credential" "$ORDER_STAKE" "$APPLIED"

# --- REFUSALS: a substituted cardano-swaps script must be caught before anything is built. The
# client rebuilds those from an EXTERNAL repo, and the ceremony's dapp_hash/beacon_id anchor them. ---
# (b) a cardano-swaps blueprint whose SPEND validator is a DIFFERENT but perfectly valid script
# (here the beacon's own compiled code, with its hash field made consistent so aiken accepts the
# blueprint). Only this tool's gate against the ceremony's dapp_hash stands between the client and it.
python3 -c "
import json,sys,hashlib
d=json.load(open(sys.argv[1]))
subst=next(v['compiledCode'] for v in d['validators'] if v['title']=='two_way_swap.beacon_script')
for v in d['validators']:
    if v['title']=='two_way_swap.swap_script':
        v['compiledCode']=subst
        v['hash']=hashlib.blake2b(b'\x02'+bytes.fromhex(subst),digest_size=28).hexdigest()
json.dump(d,open(sys.argv[2],'w'))" "$CS_PLUTUS" "$WORK/bad-spend-plutus.json"
B2="$WORK/b2"; mkdir -p "$B2"
out=$(rebuild_and_verify_scripts "$WORK/params.json" testnet "$WORK/bad-spend-plutus.json" "$HERE" "$AIKEN" "$B2" 2>&1); rc=$?
check "a substituted two-way spend script is refused" "$rc" 3
contains "$out" "rebuilt spend script hashes to" "the spend gate names the mismatch"

# (c) a ceremony that names the wrong beacon_id: dapp_hash (hence the spend script and the applied
# beacon) is genuine, but the beacon_id the artefact declares does not match, so only the beacon gate
# can catch it.
python3 -c "
import json,sys
d=json.load(open(sys.argv[1])); d['beacon_id']='ff'+d['beacon_id'][2:]
json.dump(d,open(sys.argv[2],'w'))" "$WORK/params.json" "$WORK/bad-beacon-params.json"
B3="$WORK/b3"; mkdir -p "$B3"
out=$(rebuild_and_verify_scripts "$WORK/bad-beacon-params.json" testnet "$CS_PLUTUS" "$HERE" "$AIKEN" "$B3" 2>&1); rc=$?
check "a ceremony naming the wrong beacon_id is refused" "$rc" 3
contains "$out" "rebuilt beacon script hashes to" "the beacon gate names the mismatch"


# --- RECOVERY FROM A CEREMONY THE VERIFIER REFUSES TO ENDORSE ---
# The escape branch reads the client's signature and nothing else, so a crossed
# band, a zero floor or a payout address that is not the client's does not stop
# recovery. The tool used to refuse hardest here, which helped nobody but the
# operator. Each of these has a paired aiken test proving the branch stays open.
for bad in "crossed" "zero-floor" "foreign-payout"; do
  python3 - "$WORK/params.json" "$WORK/$bad.json" "$bad" <<'PY'
import json, sys
p = json.load(open(sys.argv[1]))
if sys.argv[3] == "crossed":
    p["min_asset1_price"] = {"numerator": 1, "denominator": 3000000}
    p["min_asset2_price"] = {"numerator": 2000000, "denominator": 1}
elif sys.argv[3] == "zero-floor":
    p["min_asset1_price"] = {"numerator": 0, "denominator": 1}
elif sys.argv[3] == "foreign-payout":
    p["client_payout_address"] = "addr_test1vz46h2at4w46h2at4w46h2at4w46h2at4w46h2at4w46h2cw5nyuy"
json.dump(p, open(sys.argv[2], "w"))
PY
  BAD="$WORK/out-$bad"; mkdir -p "$BAD"
  out=$(rebuild_and_verify_scripts "$WORK/$bad.json" testnet "$CS_PLUTUS" "$HERE" "$AIKEN" "$BAD" 2>&1); rc=$?
  check "a $bad ceremony is still recoverable" "$rc" 0
  contains "$out" "WARNING: this ceremony is one the verifier refuses to endorse" \
           "the $bad ceremony's defect is stated, not hidden"
  [ -s "$BAD/bound.plutus" ] && pass=$((pass+1)) || { fail=$((fail+1)); echo "FAIL $bad: no bound.plutus emitted"; }
done

# --- A REFUSAL MUST SAY WHY ---
# Discarding verify_ceremony's stderr once turned "your params file is missing
# fee_address and fee_bps" into an unexplained "could not derive", and the
# staleness stayed invisible until someone ran the suite by hand.
python3 -c "
import json,sys
p=json.load(open(sys.argv[1])); del p['fee_bps']
json.dump(p,open(sys.argv[2],'w'))" "$WORK/params.json" "$WORK/short-params.json"
SHORT="$WORK/short"; mkdir -p "$SHORT"
out=$(rebuild_and_verify_scripts "$WORK/short-params.json" testnet "$CS_PLUTUS" "$HERE" "$AIKEN" "$SHORT" 2>&1); rc=$?
check "a params file missing a parameter is refused" "$rc" 3
contains "$out" "fee_bps" "the refusal names the missing parameter"

# --- BATCHING: what one round takes, and what it leaves ---
# A whole order address does not fit one transaction, so recovery runs in rounds.
# These are the decisions a round makes before anything is built.
# Shaped like real `cardano-cli query utxo --output-json`: an order carries an
# inline datum and this book's beacons. Both are load-bearing, see the poison
# case below.
cat > "$WORK/order.json" <<'JSON'
{
  "aa00000000000000000000000000000000000000000000000000000000000000#0": {
    "inlineDatumhash": "ba91bdca0000000000000000000000000000000000000000000000000000aaaa",
    "referenceScript": null,
    "value": {"lovelace": 3000000,
              "8a199a17ef4517215945aaf3c8c5204c60fd94d34c46d341e99c8fcf": {"5041495200": 1},
              "0ff71ae2bdba25bb5e1805983c8e7924edfc77f808f4f8f6cc421ce4": {"4144414d": 4}}},
  "bb00000000000000000000000000000000000000000000000000000000000000#1": {
    "inlineDatumhash": "ba91bdca0000000000000000000000000000000000000000000000000000bbbb",
    "referenceScript": null,
    "value": {"lovelace": 5000000,
              "8a199a17ef4517215945aaf3c8c5204c60fd94d34c46d341e99c8fcf": {"5041495200": 1},
              "0ff71ae2bdba25bb5e1805983c8e7924edfc77f808f4f8f6cc421ce4": {"4144414d": 6}}},
  "cc00000000000000000000000000000000000000000000000000000000000000#2": {
    "inlineDatumhash": "ba91bdca0000000000000000000000000000000000000000000000000000cccc",
    "referenceScript": null,
    "value": {"lovelace": 7000000,
              "8a199a17ef4517215945aaf3c8c5204c60fd94d34c46d341e99c8fcf": {"5041495200": 1}}}
}
JSON
R="$WORK/round"; mkdir -p "$R"
read -r took left < <(plan_round "$WORK/order.json" "$BEACON" "$R" 2 5000)
check "a round takes at most --max-orders-per-tx" "$took" 2
check "and reports what it leaves for the next round" "$left" 1
check "it spends exactly what it took" "$(wc -w < "$R/spends.txt")" 2
# 3 + 5 ADA, the two ADAM holdings summed, and both beacons burned (negative)
contains "$(cat "$R/outval.txt")" "8000000" "the round's payout is the value it actually took"
contains "$(cat "$R/outval.txt")" "10 0ff71ae2bdba25bb5e1805983c8e7924edfc77f808f4f8f6cc421ce4.4144414d" \
         "token holdings across the round's inputs are summed"
contains "$(cat "$R/burn.txt")" "-1 8a199a17ef4517215945aaf3c8c5204c60fd94d34c46d341e99c8fcf.5041495200" \
         "the round burns the beacons its own inputs carried"
check "a beacon is burned per input it came from" "$(grep -o -e '-1 8a199a17' "$R/burn.txt" | wc -l)" 2

R2="$WORK/round2"; mkdir -p "$R2"
read -r took2 left2 < <(plan_round "$WORK/order.json" "$BEACON" "$R2" 99 5000)
check "a round never takes more than exist" "$took2" 3
check "and leaves nothing when it took them all" "$left2" 0

# cardano-swaps requires a beacon execution in any tx spending one of its orders,
# so a round carrying none is unsubmittable and must be refused before it is built.
python3 -c "
import json,sys
u=json.load(open(sys.argv[1]))
for v in u.values(): v['value'].pop('8a199a17ef4517215945aaf3c8c5204c60fd94d34c46d341e99c8fcf',None)
json.dump(u,open(sys.argv[2],'w'))" "$WORK/order.json" "$WORK/beaconless.json"
R3="$WORK/round3"; mkdir -p "$R3"
out=$(plan_round "$WORK/beaconless.json" "$BEACON" "$R3" 2 5000 2>&1); rc=$?
check "a round with no beacon to burn is refused" "$rc" 4
contains "$out" "none is a spendable order of this book" "and says why"

# --- A POISON UTxO MUST NOT BRICK EVERY ROUND FOREVER ---
# The order address is a PlutusV2 script expecting a typed datum, so a UTxO with
# no datum can never be spent by ANYONE. Batching one makes every build fail, and
# because selection is deterministic the same poison is picked on every re-run —
# so a stranger could permanently brick a client's recovery for one min-UTxO.
python3 -c "
import json,sys
u=json.load(open(sys.argv[1]))
u['0000000000000000000000000000000000000000000000000000000000000000#0']={
  'referenceScript': None, 'value': {'lovelace': 1000000}}
u['1111111111111111111111111111111111111111111111111111111111111111#0']={
  'inlineDatumhash': 'cd'*32, 'referenceScript': None,
  'value': {'lovelace': 2000000, 'ff'*28: {'4e4f5045': 1}}}
json.dump(u,open(sys.argv[2],'w'))" "$WORK/order.json" "$WORK/poisoned.json"
R8="$WORK/round8"; mkdir -p "$R8"
out=$(plan_round "$WORK/poisoned.json" "$BEACON" "$R8" 99 5000 2>&1 >/dev/null)
read -r took8 left8 < <(plan_round "$WORK/poisoned.json" "$BEACON" "$R8" 99 5000 2>/dev/null)
check "a datumless UTxO does not enter the round" "$took8" 3
# k=3 so the remainder is only zero if the two poisons were excluded AND the
# three real orders all fit — with k=99 this said nothing at all.
read -r took9 left9 < <(plan_round "$WORK/poisoned.json" "$BEACON" "$R8" 3 5000 2>/dev/null)
check "and neither does another book's order" "$took9" 3
check "so the round takes the real orders and leaves nothing behind" "$left9" 0
contains "$out" "0000000000000000000000000000000000000000000000000000000000000000#0" \
         "the skipped poison is named, not silently dropped"
contains "$out" "nothing here can spend it" "and the client is told it is unrecoverable"
grep -q "0000000000000000000000000000000000000000000000000000000000000000" "$R8/spends.txt" \
  && { fail=$((fail+1)); echo "FAIL poison reached spends.txt"; } || pass=$((pass+1))

R4="$WORK/round4"; mkdir -p "$R4"
echo '{}' > "$WORK/empty.json"
out=$(plan_round "$WORK/empty.json" "$BEACON" "$R4" 2 5000 2>&1); rc=$?
check "an empty order address is refused" "$rc" 4

# --- THE BUDGET CHECK MUST READ THE UNITS THAT ARE ACTUALLY THERE ---
# testdata/escape-view.real.json is `cardano-cli debug transaction view` run by the
# real binary on a real preprod escape transaction (the one-order recovery of the
# live client instance 3227e143). Not hand-written: guessing this shape is what
# broke it. cardano-cli spells the key "execution units", with a space, and reading
# "executionUnits" summed to zero — which tripped the fail-closed guard below, so
# every round aborted before it was signed and the tool recovered nothing.
REALVIEW="$HERE/testdata/escape-view.real.json"
if [ -f "$REALVIEW" ]; then
  STUBR="$WORK/stubreal"; mkdir -p "$STUBR"
  cat > "$STUBR/cardano-cli" <<STUB
#!/bin/bash
for a in "\$@"; do [ "\$prev" = "--out-file" ] && out="\$a"; prev="\$a"; done
cat "$REALVIEW" > "\${out:-/dev/stdout}"
STUB
  chmod +x "$STUBR/cardano-cli"
  # the same transaction's real serialised length, so size is measured too
  printf '{"type":"Tx ConwayEra","description":"","cborHex":"%s"}\n' \
    "$(python3 -c "print('ab' * 13371)")" > "$WORK/real.tx"
  CLI="$STUBR/cardano-cli"
  read -r rbytes rmem rsteps < <(measure_tx "$WORK/real.tx" --tx-file); rc=$?
  check "a real transaction's execution units are read, not zero" "$rc" 0
  # independently confirmed by `calculate-plutus-script-cost online` against live
  # chain state: 110,147 + 71,951 + 23,400 mem, 36,305,051 + 21,239,747 + 6,323,456 steps
  check "and they total what the evaluator reported" "$rmem" 205498
  check "steps too" "$rsteps" 63868254
  check "the serialised length is the CBOR length, not the file's" "$rbytes" 13371
else
  fail=$((fail+1)); echo "FAIL: $REALVIEW is missing; the units shape would be unpinned"
fi

# --- THE BUDGET CHECK MUST FAIL CLOSED ---
# `transaction build` does NOT enforce maxTxSize or maxTxExecutionUnits — it fills
# ex-units in, balances, and returns a body the node will reject. So this tool is
# what stands between the client and an unsubmittable recovery, and a measurement
# it could not take must never read as zero.
STUBDIR="$WORK/stub"; mkdir -p "$STUBDIR"
cat > "$STUBDIR/cardano-cli" <<'STUB'
#!/bin/bash
# a `debug transaction view` that reports a transaction with no script legs at all
for a in "$@"; do [ "$prev" = "--out-file" ] && out="$a"; prev="$a"; done
printf '{"inputs": [], "outputs": []}\n' > "${out:-/dev/stdout}"
STUB
chmod +x "$STUBDIR/cardano-cli"
printf '{"type":"Unwitnessed Tx ConwayEra","description":"","cborHex":"84a0f5f6"}\n' > "$WORK/fake.body"
CLI="$STUBDIR/cardano-cli"
out=$(measure_tx "$WORK/fake.body" --tx-body-file 2>&1); rc=$?
check "a transaction whose execution units cannot be read is refused" "$rc" 4
contains "$out" "refusing to judge it against the budget" "and says so rather than scoring it zero"

# --- maxValueSize IS A THIRD LIMIT, AND NEITHER build NOR THE OTHER CHECKS SEE IT ---
# Everything recovered lands in ONE output. The protocol caps an output's value at
# maxValueSize independently of transaction size and of the execution budget;
# `transaction build` does not check it and the node answers OutputTooBigUTxO. A
# token-rich order address hits this first, so a round that would not fit must
# never be built.
# The fixture above holds ONE token across all three UTxOs, so its output value
# does not grow with the round — beacons are burned, not paid out. Distinct
# assets are what this limit counts, so the fixture has to carry them.
python3 - "$WORK/order.json" "$WORK/many-assets.json" <<'PY'
import json, sys
u = json.load(open(sys.argv[1]))
for i, (ref, o) in enumerate(sorted(u.items())):
    o["value"] = {"lovelace": o["value"]["lovelace"],
                  "8a199a17ef4517215945aaf3c8c5204c60fd94d34c46d341e99c8fcf": {"5041495200": 1},
                  f"{i:02d}" + "cc" * 27: {"544f4b" + f"{i:02d}": 5}}
    o.setdefault("inlineDatumhash", "ba" * 32)
json.dump(u, open(sys.argv[2], "w"))
PY
R5="$WORK/round5"; mkdir -p "$R5"
read -r took5 left5 < <(plan_round "$WORK/many-assets.json" "$BEACON" "$R5" 3 5000)
check "a round that fits the value limit takes everything" "$took5" 3
# three distinct policies cost ~118 bytes of value; one costs ~44
R6="$WORK/round6"; mkdir -p "$R6"
read -r took6 left6 < <(plan_round "$WORK/many-assets.json" "$BEACON" "$R6" 3 90)
[ "$took6" -lt 3 ] && pass=$((pass+1)) || { fail=$((fail+1)); echo "FAIL a round over the value limit is not shrunk: took $took6"; }
check "and the ones it could not carry are left for the next round" "$left6" "$((3 - took6))"
# a single UTxO that cannot fit is a refusal, not an infinite shrink
R7="$WORK/round7"; mkdir -p "$R7"
out=$(plan_round "$WORK/many-assets.json" "$BEACON" "$R7" 3 1 2>&1); rc=$?
check "one UTxO too big for an output is refused, not looped on" "$rc" 4
contains "$out" "per-output limit" "and says which limit stopped it"

# --- EVERY ORDER UTxO THE ROUND TOOK MUST REACH THE TRANSACTION ---
# `read` returns non-zero on a final line with no newline, so a plain
# `while read` loop dropped the LAST spend of every round while burn.txt and
# outval.txt still counted it. Nothing balanced, and escape.sh could not build a
# recovery at any batch size. At N=1 it emitted no --tx-in at all.
SPEND="$WORK/twoway_spend.plutus"; WORK_SAVE="$WORK"
for n in 1 2 3; do
  head -n "$n" <(printf 'aa#0\nbb#1\ncc#2\n') > "$WORK/spends.$n.txt"
  got=$(spend_args_for "$WORK/spends.$n.txt" | grep -c -x -- '--tx-in')
  check "a round of $n order UTxO(s) emits $n --tx-in flags" "$got" "$n"
done
# the shape that actually shipped: no terminating newline on the last line
printf 'aa#0\nbb#1' > "$WORK/spends.nonl.txt"
got=$(spend_args_for "$WORK/spends.nonl.txt" | grep -c -x -- '--tx-in')
check "an unterminated spends file still spends its last UTxO" "$got" 2
# and plan_round must not produce that shape in the first place
check "plan_round terminates every line it writes" \
      "$(tail -c 1 "$R/spends.txt" | xxd -p)" "0a"
got=$(spend_args_for "$R/spends.txt" | grep -c -x -- '--tx-in')
check "the round's own spends file spends all of them" "$got" 2
WORK="$WORK_SAVE"

# --- WHERE THE RECOVERED VALUE GOES ---
# The most consequential line in this file. --dest and --fund-addr exist so a
# client under duress can pay fees from a hot wallet and recover to a cold one;
# a transposed pair would route the whole recovery to the wallet the operator
# already knows, because it is where fills were paid.
DEST="addr_test1vcoldcoldcoldcoldcoldcoldcoldcoldcoldcoldcoldcoldcq0000"
FUND="addr_test1vhothothothothothothothothothothothothothothothotcq111"
REWARD_ADDR="stake_test17qreward"; CLIENT_VKH="aa"; BOUND="/b.plutus"; BEACONP="/p.plutus"
mapfile -t flags < <(round_flags "$R" "coll#0" "fee#1")
# after(FLAG) is the single argument that follows it — which is the whole point:
# a value that got word-split would land in a different slot
after(){ local i; for i in "${!flags[@]}"; do
    [ "${flags[$i]}" = "$1" ] && { printf '%s' "${flags[$((i+1))]}"; return; }; done; }
check "the recovery pays the destination the client named" "$(after --tx-out)" "$DEST+$(cat "$R/outval.txt")"
check "and only change returns to the funding wallet" "$(after --change-address)" "$FUND"
check "the fee comes from the funding input chosen for it" "$(after --tx-in)" "fee#1"
check "and collateral from its own UTxO" "$(after --tx-in-collateral)" "coll#0"
check "the client's signature is required" "$(after --required-signer-hash)" "$CLIENT_VKH"
check "and the withdraw-0 runs the bound script" "$(after --withdrawal)" "$REWARD_ADDR+0"
# the burn is ALWAYS multi-word, so it is the argument most likely to shatter
check "the whole burn list is ONE argument" "$(after --mint)" "$(cat "$R/burn.txt")"
[ "$(after --tx-out)" = "$FUND" ] \
  && { fail=$((fail+1)); echo "FAIL the funding wallet is named as a payout destination"; } \
  || pass=$((pass+1))
[ "$(after --change-address)" = "$DEST" ] \
  && { fail=$((fail+1)); echo "FAIL change is routed to the destination, not the funder"; } \
  || pass=$((pass+1))

# --- A REFERENCE SCRIPT IS A CLAIM, NOT A FACT ---
# Referencing the three scripts instead of attaching them removes 94% of a recovery
# transaction. It must not remove the guarantee: a script sitting at somebody else's
# UTxO is used ONLY if it hashes to the credential THIS ceremony names, and a reference
# that is missing, spent or wrong falls back to inline rather than failing — a client's
# recovery cannot depend on an operator continuing to host something.
REFDIR="$WORK/refs"; mkdir -p "$REFDIR/out"
DAPP_HASH="$DAPP"; APPLIED_HASH="$APPLIED"; MAGIC="--testnet-magic 1"
# a stub `query utxo --tx-in` that serves whatever referenceScript the case needs
cat > "$REFDIR/cli" <<'STUB'
#!/bin/bash
out=""; prev=""; txin=""
for a in "$@"; do
  [ "$prev" = "--out-file" ] && out="$a"
  [ "$prev" = "--tx-in" ] && txin="$a"
  prev="$a"
done
cat "$REFCLI_DIR/$txin.json" 2>/dev/null > "${out:-/dev/stdout}" || echo '{}' > "${out:-/dev/stdout}"
STUB
chmod +x "$REFDIR/cli"
# testdata/reference-utxos.real.json is `cardano-cli query utxo --output-json` over
# the three scripts we actually published on preprod (tx 7835e6b2…). NOT hand-built:
# the chain returns a reference script as the ledger stores it, which IS the hash
# preimage, while a local .plutus envelope carries an extra CBOR wrapper. Fixtures
# built from the envelope agreed with a bug that unwrapped one layer too many and
# refused every real reference we owned.
REAL_REFS="$HERE/testdata/reference-utxos.real.json"
[ -f "$REAL_REFS" ] || { echo "FAIL: $REAL_REFS missing; the reference gate would be unpinned"; fail=$((fail+1)); }
python3 - "$REAL_REFS" "$REFDIR" "$DAPP" "$BEACON" <<'PY'
import json, sys
refs = json.load(open(sys.argv[1])); out, dapp, beacon = sys.argv[2], sys.argv[3], sys.argv[4]
import hashlib
def h(sc, ver):
    return hashlib.blake2b(bytes([ver]) + bytes.fromhex(sc["cborHex"]), digest_size=28).hexdigest()
spend = beaconscript = None
for ref, o in refs.items():
    sc = o["referenceScript"]["script"]
    if h(sc, 2) == dapp: spend = o
    elif h(sc, 2) == beacon: beaconscript = o
assert spend and beaconscript, "the real fixture no longer carries both V2 scripts"
# the spend script where a spend script is expected: must verify
json.dump({"good#0": spend}, open(f"{out}/good#0.json", "w"))
# the BEACON script where the SPEND script is claimed to be — genuine, wrong credential
json.dump({"wrong#0": beaconscript}, open(f"{out}/wrong#0.json", "w"))
json.dump({}, open(f"{out}/spent#0.json", "w"))
PY

CLI="$REFDIR/cli"; export REFCLI_DIR="$REFDIR"
printf '{"spend": "good#0"}\n' > "$REFDIR/good.json"
REF_SPEND=""; REF_BEACON=""; REF_BOUND=""
resolve_reference_scripts "$REFDIR/good.json" "$REFDIR/out" >"$REFDIR/good.log" 2>&1
out=$(cat "$REFDIR/good.log")
check "a reference carrying the ceremony's own script is used" "$REF_SPEND" "good#0"
contains "$out" "verified == $DAPP" "and the verification is stated"

printf '{"spend": "wrong#0"}\n' > "$REFDIR/wrong.json"
REF_SPEND=""; REF_BEACON=""; REF_BOUND=""
resolve_reference_scripts "$REFDIR/wrong.json" "$REFDIR/out" >"$REFDIR/wrong.log" 2>&1
out=$(cat "$REFDIR/wrong.log")
check "a reference carrying a DIFFERENT script is refused" "$REF_SPEND" ""
contains "$out" "REFUSING that reference" "and the substitution is named"
contains "$out" "Attaching the rebuilt script inline instead" "and recovery continues"

printf '{"spend": "spent#0"}\n' > "$REFDIR/spent.json"
REF_SPEND=""; REF_BEACON=""; REF_BOUND=""
resolve_reference_scripts "$REFDIR/spent.json" "$REFDIR/out" >"$REFDIR/spent.log" 2>&1
out=$(cat "$REFDIR/spent.log")
check "a spent reference falls back to inline" "$REF_SPEND" ""
contains "$out" "spent or carries no script" "and says so"

REF_SPEND=""; REF_BEACON=""; REF_BOUND=""
resolve_reference_scripts "$REFDIR/nonexistent.json" "$REFDIR/out" >"$REFDIR/none.log" 2>&1
check "no reference file at all is not an error" "$?" 0
out=$(cat "$REFDIR/none.log")
contains "$out" "attaching all three inline" "it just inlines everything"

# and the flags actually change shape when a reference verified
SPEND="$G/twoway_spend.plutus"
REF_SPEND="good#0"
mapfile -t refargs < <(spend_args_for "$R/spends.txt")
printf '%s\n' "${refargs[@]}" | grep -qx -- "--spending-tx-in-reference" \
  && pass=$((pass+1)) || { fail=$((fail+1)); echo "FAIL referenced spend did not use --spending-tx-in-reference"; }
printf '%s\n' "${refargs[@]}" | grep -qx -- "--tx-in-script-file" \
  && { fail=$((fail+1)); echo "FAIL referenced spend still attached the script inline"; } \
  || pass=$((pass+1))
REF_SPEND=""
mapfile -t inlargs < <(spend_args_for "$R/spends.txt")
printf '%s\n' "${inlargs[@]}" | grep -qx -- "--tx-in-script-file" \
  && pass=$((pass+1)) || { fail=$((fail+1)); echo "FAIL the inline fallback stopped attaching the script"; }

# --- ALL THREE ARMS OF THE GATE, NOT JUST THE SPEND ONE ---
# The credential differs per role — dapp_hash, beacon_id, the client's own applied hash.
# Testing only the spend arm leaves two thirds of the gate unexercised, and the bound arm
# is the one carrying the CLIENT's own script.
python3 - "$REAL_REFS" "$REFDIR" "$BEACON" "$APPLIED" <<'PY'
import json, sys, hashlib
refs = json.load(open(sys.argv[1])); out, beacon, applied = sys.argv[2], sys.argv[3], sys.argv[4]
def h(sc, ver):
    return hashlib.blake2b(bytes([ver]) + bytes.fromhex(sc["cborHex"]), digest_size=28).hexdigest()
for ref, o in refs.items():
    sc = o["referenceScript"]["script"]
    if h(sc, 2) == beacon: json.dump({"beac#0": o}, open(f"{out}/beac#0.json", "w"))
    if "V3" in str(sc.get("type", "")): json.dump({"bnd#0": o}, open(f"{out}/bnd#0.json", "w"))
PY
# The published bound reference belongs to the LIVE preprod ceremony, not to this
# suite's golden one, so the bound arm is checked against the credential that script
# actually is — which is the point of the gate anyway.
REAL_APPLIED=$(python3 -c "
import json,sys,hashlib
for o in json.load(open(sys.argv[1])).values():
    sc=o['referenceScript']['script']
    if 'V3' in str(sc.get('type','')):
        print(hashlib.blake2b(bytes([3])+bytes.fromhex(sc['cborHex']),digest_size=28).hexdigest()); break" "$REAL_REFS")
SAVED_APPLIED="$APPLIED_HASH"
for arm in beacon bound; do
  case "$arm" in
    beacon) live="beac#0"; APPLIED_HASH="$SAVED_APPLIED";;
    bound)  live="bnd#0";  APPLIED_HASH="$REAL_APPLIED";;
  esac
  [ -f "$REFDIR/$live.json" ] || { fail=$((fail+1)); echo "FAIL no real $arm script in the fixture"; continue; }
  printf '{"%s": "%s"}\n' "$arm" "$live" > "$REFDIR/$arm-good.json"
  REF_SPEND=""; REF_BEACON=""; REF_BOUND=""
  resolve_reference_scripts "$REFDIR/$arm-good.json" "$REFDIR/out" >"$REFDIR/$arm.log" 2>&1
  case "$arm" in
    beacon) got="$REF_BEACON";; bound) got="$REF_BOUND";;
  esac
  check "the $arm arm accepts its own credential" "$got" "$live"
  # and refuses the spend script standing in for it
  printf '{"%s": "good#0"}\n' "$arm" > "$REFDIR/$arm-bad.json"
  REF_SPEND=""; REF_BEACON=""; REF_BOUND=""
  resolve_reference_scripts "$REFDIR/$arm-bad.json" "$REFDIR/out" >"$REFDIR/$arm-bad.log" 2>&1
  case "$arm" in
    beacon) got="$REF_BEACON";; bound) got="$REF_BOUND";;
  esac
  check "the $arm arm refuses another script" "$got" ""
  contains "$(cat "$REFDIR/$arm-bad.log")" "REFUSING that reference" "the $arm refusal is named"
done
APPLIED_HASH="$SAVED_APPLIED"

# --- THE MINT AND WITHDRAWAL REFERENCE LEGS ---
# round_flags has three reference branches and only the spend one was ever exercised.
# A wrong flag here builds a transaction the ledger cannot resolve.
REF_SPEND=""; REF_BEACON="beac#0"; REF_BOUND="bnd#0"
mapfile -t rflags < <(round_flags "$R" "coll#0" "fee#1")
after2(){ local i; for i in "${!rflags[@]}"; do
    [ "${rflags[$i]}" = "$1" ] && { printf '%s' "${rflags[$((i+1))]}"; return; }; done; }
check "the mint leg references the beacon policy" "$(after2 --mint-tx-in-reference)" "beac#0"
check "and declares its language" "$(printf '%s\n' "${rflags[@]}" | grep -c -x -- '--mint-plutus-script-v2')" 1
check "and names the policy id, which the reference path requires" "$(after2 --policy-id)" "$BEACON"
check "the withdrawal leg references the bound script" "$(after2 --withdrawal-tx-in-reference)" "bnd#0"
check "and declares V3" "$(printf '%s\n' "${rflags[@]}" | grep -c -x -- '--withdrawal-plutus-script-v3')" 1
printf '%s\n' "${rflags[@]}" | grep -qx -- "--mint-script-file" \
  && { fail=$((fail+1)); echo "FAIL the referenced mint leg still attached the policy inline"; } \
  || pass=$((pass+1))
printf '%s\n' "${rflags[@]}" | grep -qx -- "--withdrawal-script-file" \
  && { fail=$((fail+1)); echo "FAIL the referenced withdrawal leg still attached the script inline"; } \
  || pass=$((pass+1))
REF_BEACON=""; REF_BOUND=""
mapfile -t iflags < <(round_flags "$R" "coll#0" "fee#1")
printf '%s\n' "${iflags[@]}" | grep -qx -- "--mint-script-file" && pass=$((pass+1)) \
  || { fail=$((fail+1)); echo "FAIL the inline mint leg stopped attaching the policy"; }
printf '%s\n' "${iflags[@]}" | grep -qx -- "--withdrawal-script-file" && pass=$((pass+1)) \
  || { fail=$((fail+1)); echo "FAIL the inline withdrawal leg stopped attaching the script"; }

# --- THE DECLARED LANGUAGE IS PART OF THE IDENTITY ---
# The ledger hashes a script under the language it is stored as, so the same bytes
# tagged V3 have a different on-chain hash from the same bytes tagged V2. Choosing the
# version byte from the ROLE we wanted the script for let a V3-tagged copy of the V2
# spend script hash to dapp_hash and pass as "verified", while the ledger could never
# resolve it — a permanent phase-1 denial that the tool had announced as verified.
python3 - "$REFDIR/good#0.json" "$REFDIR/mislabelled#0.json" <<'PY'
import json, sys
u = json.load(open(sys.argv[1]))
o = next(iter(u.values()))
o["referenceScript"]["script"]["type"] = "PlutusScriptV3"
o["referenceScript"]["scriptLanguage"] = "PlutusScriptLanguage PlutusScriptV3"
json.dump({"mislabelled#0": o}, open(sys.argv[2], "w"))
PY
printf '{"spend": "mislabelled#0"}
' > "$REFDIR/mislabelled.json"
REF_SPEND=""; REF_BEACON=""; REF_BOUND=""
resolve_reference_scripts "$REFDIR/mislabelled.json" "$REFDIR/out" >"$REFDIR/mis.log" 2>&1
check "the same bytes tagged with another language are refused" "$REF_SPEND" ""
contains "$(cat "$REFDIR/mis.log")" "REFUSING that reference" "and refused by name"

# --- A REFERENCE THAT VANISHES MID-RUN MUST FALL BACK, NOT STRAND ---
# The references belong to the operator, who can spend them between our rounds. Resolved
# once, they become a dependency for the rest of the run: the next round builds against a
# spent UTxO and the halving loop misreads that as "too big". So resolution repeats every
# round, and this proves it by serving a valid reference the first time and a spent one
# after.
VAN="$WORK/vanish"; mkdir -p "$VAN/out"
cp "$REFDIR/good#0.json" "$VAN/live.json"
printf '{}\n' > "$VAN/gone.json"
cat > "$VAN/cli" <<'STUB'
#!/bin/bash
out=""; prev=""
for a in "$@"; do [ "$prev" = "--out-file" ] && out="$a"; prev="$a"; done
n=$(cat "$VANDIR/calls" 2>/dev/null || echo 0)
echo $((n+1)) > "$VANDIR/calls"
# first resolution sees it live, every later one sees it spent
if [ "$n" -lt 1 ]; then cat "$VANDIR/live.json" > "${out:-/dev/stdout}"
else cat "$VANDIR/gone.json" > "${out:-/dev/stdout}"; fi
STUB
chmod +x "$VAN/cli"
printf '{"spend": "good#0"}\n' > "$VAN/refs.json"
export VANDIR="$VAN"; CLI="$VAN/cli"; echo 0 > "$VAN/calls"

# NOTE: no manual reset between the calls. Resetting here is what hid the real defect —
# the function assigned the globals on success and never cleared them, so a reference
# that died mid-run stayed in use while stderr claimed it had been inlined. The
# production code must do the clearing, so the test must not.
REF_SPEND=""; REF_BEACON=""; REF_BOUND=""
resolve_reference_scripts "$VAN/refs.json" "$VAN/out" >"$VAN/r1.log" 2>&1
check "round 1 uses a live reference" "$REF_SPEND" "good#0"
resolve_reference_scripts "$VAN/refs.json" "$VAN/out" >"$VAN/r2.log" 2>&1
check "round 2 clears it once it has been spent" "$REF_SPEND" ""
contains "$(cat "$VAN/r2.log")" "spent or carries no script" "and says why rather than failing"
# and the resolution really is inside the round loop, not before it
awk '/^ROUND=0/{r=NR} /resolve_reference_scripts "\$REFS"/{c=NR} END{exit !(c>r)}' "$HERE/escape.sh" \
  && pass=$((pass+1)) \
  || { fail=$((fail+1)); echo "FAIL resolve_reference_scripts is called before the round loop"; }
unset VANDIR

# --- THE TOOL MUST ACTUALLY RUN ---
# Everything above tests the five sourced helpers. Nothing executed escape.sh, and
# three separate blockers shipped behind 66 green assertions: a Python SyntaxError
# in the rewards guard, a KeyError in fee selection, and argv word-splitting that
# shattered --mint and --tx-out into stray positionals. None was reachable by a
# function-level test; the first two are not reachable by a STRING assertion at
# all, and the third is invisible to one by construction. So this runs the whole
# script against a cardano-cli that records its argv.
FAKE="$WORK/fake"; mkdir -p "$FAKE/out"
cat > "$FAKE/cardano-cli" <<'STUB'
#!/bin/bash
# every invocation, one file per call, argv NUL-free one-per-line
n=$(ls "$FAKECLI_OUT" | grep -c '^argv\.' || true)
printf '%s\n' "$@" > "$FAKECLI_OUT/argv.$n"
out=""; prev=""
for a in "$@"; do [ "$prev" = "--out-file" ] && out="$a"; prev="$a"; done
case "$*" in
  *"query utxo"*--address\ addr_test1x*)
    # addr_test1x... is a type-3 script-payment/script-stake address: the order address
    cat "$FAKECLI_OUT/../order.json" > "${out:-/dev/stdout}";;
  *"query utxo"*)
    cat "$FAKECLI_OUT/../fund.json" > "${out:-/dev/stdout}";;
  *"query protocol-parameters"*)
    printf '{"maxTxSize":16384,"maxValueSize":5000,"maxTxExecutionUnits":{"memory":17500000,"steps":10000000000}}\n' > "${out:-/dev/stdout}";;
  *"query stake-address-info"*)
    # FAKE_REWARDS: a number = that balance; "fail" = the node is unreachable, which is the
    # case the guard used to wave through with a note.
    case "${FAKE_REWARDS:-0}" in
      fail) exit 1;;
      *) printf '[{"rewardAccountBalance":%s}]\n' "${FAKE_REWARDS:-0}" > "${out:-/dev/stdout}";;
    esac;;
  *"transaction build"*)
    printf '{"type":"Unwitnessed Tx ConwayEra","description":"","cborHex":"84a0f5f6"}\n' > "${out:-/dev/stdout}";;
  *"debug transaction view"*)
    printf '{"redeemers":[{"redeemer":{"execution units":{"memory":200000,"steps":60000000}}}]}\n' > "${out:-/dev/stdout}";;
  *"transaction txid"*) printf '{"txhash":"%s"}\n' "$(printf 'ab%.0s' {1..32})";;
  *"transaction witness"*|*"transaction assemble"*)
    printf '{"type":"Tx ConwayEra","description":"","cborHex":"84a0f5f6"}\n' > "${out:-/dev/stdout}";;
  *"transaction submit"*) echo "Transaction successfully submitted.";;
  *) exit 0;;
esac
STUB
chmod +x "$FAKE/cardano-cli"
# one order, carrying a token — the shape that makes --tx-out multi-word
cat > "$FAKE/order.json" <<'JSON'
{"ab00000000000000000000000000000000000000000000000000000000000000#0": {
  "inlineDatumhash": "cd0000000000000000000000000000000000000000000000000000000000cdcd",
  "referenceScript": null,
  "value": {"lovelace": 10000000,
            "8a199a17ef4517215945aaf3c8c5204c60fd94d34c46d341e99c8fcf": {"5041495200": 1},
            "0ff71ae2bdba25bb5e1805983c8e7924edfc77f808f4f8f6cc421ce4": {"4144414d4d4b54": 100}}}}
JSON
cat > "$FAKE/fund.json" <<'JSON'
{"cc00000000000000000000000000000000000000000000000000000000000000#0": {
   "referenceScript": null, "value": {"lovelace": 6000000}},
 "dd00000000000000000000000000000000000000000000000000000000000000#1": {
   "referenceScript": null, "value": {"lovelace": 20000000}}}
JSON
# drive the executable half directly with the ceremony already derived, so this
# exercises the round loop rather than re-deriving scripts
( export FAKECLI_OUT="$FAKE/out"
  cd "$FAKE" && FAKE_CEREMONY=1 bash "$HERE/escape.sh" \
    --params "$WORK/params.json" --cardano-swaps-plutus "$CS_PLUTUS" \
    --project "$HERE" --network testnet --testnet-magic 1 \
    --dest addr_test1vdestination --fund-addr addr_test1vfunding \
    --signing-key /dev/null --cardano-cli "$FAKE/cardano-cli" \
    --aiken "$AIKEN" --out-dir "$FAKE/work" --build-only ) >"$FAKE/run.log" 2>&1
rc=$?
BUILDARGV=$(grep -l -x -- "--tx-out" "$FAKE/out"/argv.* 2>/dev/null | head -1)
if [ -n "$BUILDARGV" ]; then
  pass=$((pass+1))
  # --mint and --tx-out each have to be ONE argument, whatever they contain
  m=$(grep -n -x -- "--mint" "$BUILDARGV" | cut -d: -f1)
  mval=$(sed -n "$((m+1))p" "$BUILDARGV")
  case "$mval" in
    -1\ *" + "*|-1\ *) pass=$((pass+1));;
    *) fail=$((fail+1)); echo "FAIL --mint was split into argv: got [$mval]";;
  esac
  o=$(grep -n -x -- "--tx-out" "$BUILDARGV" | cut -d: -f1)
  oval=$(sed -n "$((o+1))p" "$BUILDARGV")
  case "$oval" in
    addr_test1vdestination+*4144414d4d4b54*) pass=$((pass+1));;
    *) fail=$((fail+1)); echo "FAIL --tx-out lost its token to argv splitting: got [$oval]";;
  esac
  grep -qx -- "--tx-in" "$BUILDARGV" && pass=$((pass+1)) \
    || { fail=$((fail+1)); echo "FAIL no --tx-in reached the build"; }
else
  fail=$((fail+1)); echo "FAIL escape.sh never reached transaction build (rc=$rc)"
  echo "--- its output ---"; tail -20 "$FAKE/run.log"
fi
grep -q "SyntaxError\|Traceback" "$FAKE/run.log" \
  && { fail=$((fail+1)); echo "FAIL escape.sh raised a python error: $(grep -m1 'SyntaxError\|Error' "$FAKE/run.log")"; } \
  || pass=$((pass+1))

echo "escape.test.sh: $pass passed, $fail failed"
[ "$fail" -eq 0 ]

# --- the rewards guard: it must REFUSE, and it must not fail open --------------
#
# Every round withdraws +0 to run the bound script, and Conway only accepts a
# withdrawal that drains the whole balance. So one accrued reward makes every
# round unbuildable — with a bare phase-1 error and no diagnosis unless this
# guard speaks first. A client who delegated is exactly the client who most
# needs the answer, and the browser path cannot help them here at all.
run_escape(){
  ( export FAKECLI_OUT="$FAKE/out" FAKE_REWARDS="$1"
    cd "$FAKE" && FAKE_CEREMONY=1 bash "$HERE/escape.sh" \
      --params "$WORK/params.json" --cardano-swaps-plutus "$CS_PLUTUS" \
      --project "$HERE" --network testnet --testnet-magic 1 \
      --dest addr_test1vdestination --fund-addr addr_test1vfunding \
      --signing-key /dev/null --cardano-cli "$FAKE/cardano-cli" \
      --aiken "$AIKEN" --out-dir "$FAKE/work2" --build-only ) >"$FAKE/run.$2.log" 2>&1
  rc=$?
  cp "$FAKE/run.$2.log" "/tmp/esc.$2.log" 2>/dev/null || true
  echo $rc
}

rc_rewards=$(run_escape 1234567 rewards)
check "an unclaimed reward balance REFUSES with exit 4" "$rc_rewards" 4
# ...and refuses AT THE GUARD. Exit 4 alone is not proof: other failures downstream
# exit 4 too, so deleting the guard's own sys.exit left this green. Pin the ordering
# instead — nothing may be BUILT once the guard has spoken.
grep -q "protocol limits:" "$FAKE/run.rewards.log" \
  && { fail=$((fail+1)); echo "FAIL the guard printed but planning continued anyway"; } \
  || pass=$((pass+1))
grep -q "1234567 lovelace of unclaimed staking rewards" "$FAKE/run.rewards.log" \
  && pass=$((pass+1)) || { fail=$((fail+1)); echo "FAIL the refusal does not name the amount owed"; }
grep -qi "withdraw them first with your own key" "$FAKE/run.rewards.log" \
  && pass=$((pass+1)) || { fail=$((fail+1)); echo "FAIL the refusal does not name the remedy"; }

# An UNREADABLE balance is not a balance of zero. This used to print a note and
# carry on, which delivers the client to the exact undiagnosable phase-1 failure
# the guard exists to prevent — the same fail-open shape as a browser gate that
# reads an indexer outage as "no rewards".
rc_unreadable=$(run_escape fail unreadable)
check "an UNREADABLE reward balance refuses too, not proceeds" "$rc_unreadable" 4

rc_zero=$(run_escape 0 zero)
check "a genuinely zero balance proceeds" "$rc_zero" 0
