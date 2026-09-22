#!/bin/bash
# maker_stake_bound ESCAPE HATCH — a bound MMaaS client unilaterally recovers 100% of their resting
# inventory with ZERO operator cooperation, using only their own signing key, PUBLIC chain data, and
# the PUBLIC applied scripts this tool rebuilds and hash-verifies.
#
# A client's inventory rests at a cardano-swaps two-way order address whose stake credential is their
# bound maker_stake_bound script. maker_stake_bound.withdraw returns True unconditionally when the
# client signs — the first disjunct of the `or` in its withdraw handler, which short-circuits before
# payout_bound is reached — so a withdraw-0 the client signs authorises spending every resting order
# at that address. That disjunct reads the client's signature and nothing else, which is why a
# ceremony with a crossed band, a zero floor or a payout address that is not the client's is still
# recoverable: --for-escape derives its addresses instead of refusing to endorse it. This tool:
#
#   1. Rebuilds and HASH-VERIFIES the three scripts recovery needs, from public sources only:
#        - bound.plutus     maker_stake_bound applied, via verify_ceremony.py --emit-applied-script;
#                           its hash MUST equal the ceremony's applied_script_hash.
#        - twoway_spend.plutus   the (unparameterised) cardano-swaps two-way spend validator, from
#                           the PUBLIC cardano-swaps blueprint; its hash MUST equal dapp_hash.
#        - twoway_beacon.plutus  the two-way beacon policy, `aiken blueprint apply`'d with dapp_hash;
#                           its hash MUST equal beacon_id.
#      Any mismatch is fatal — the client attaches only scripts that provably match the on-chain
#      instance the ceremony named, so a substituted script cannot redirect the funds.
#   2. Spends the order UTxOs (SpendWithMint), burns their beacons (CreateOrCloseSwaps), runs the
#      bound withdraw-0 (client escape branch), and pays 100% of the recovered value to --dest.
#      A whole address rarely fits one transaction — three attached scripts and a 16 KB ceiling —
#      so recovery runs in rounds, each measured against the node's own limits before it is sent
#      and halved if it does not fit. Rounds are independent, so an interrupted run is resumed by
#      running this again.
#   3. The client signs the body OFFLINE — `transaction witness` needs no node, no network, no
#      docker, exactly as the possession proof does — then it is assembled and submitted. The
#      operator's wallet and key are NEVER referenced.
#
# --params is the public nine-field ceremony parameters file (the same input verify_ceremony.py
# takes). A ceremony predating the fee-leg parameters has seven fields and must be recovered with a
# checkout of this tool from before they were added — the derivation rebuilds from source, so it can
# only reproduce instances made from the source it ships with.
# Point --cardano-cli at a NODE YOU TRUST (your own, or any relay you choose): every input to the
# recovery is public and checked here, so a hostile node can at most refuse service, never redirect
# the funds. --sign-cli defaults to --cardano-cli but may be a standalone, air-gapped binary.
#
# Usage:
#   escape.sh --params <params.json> --cardano-swaps-plutus <plutus.json> \
#             --project <maker_stake dir> --dest <addr> --fund-addr <your wallet> \
#             --signing-key <your.skey> --network mainnet|testnet [--cardano-cli "cardano-cli"] \
#             [--sign-cli "cardano-cli"] [--aiken ~/.aiken/bin/aiken] [--testnet-magic 1] \
#             [--out-dir DIR] [--build-only] [--max-orders-per-tx N] \
#             [--reference-scripts refs.json]
set -uo pipefail

# Resolve the verifier from THIS script's own directory, never from --project.
# The published recovery selector `--project generations/<applied_hash>`
# deliberately ships no verify_ceremony.py copy, so reading it from $project made
# the documented generation selector die on a missing file. escape.sh and
# verify_ceremony.py always ship together.
ESCAPE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# blake2b-224 over (version byte ‖ the compiled code a .plutus envelope wraps once). Args: file version(2|3).
script_hash(){ python3 - "$1" "$2" <<'PY'
import json, hashlib, sys
env = json.load(open(sys.argv[1])); ver = int(sys.argv[2])
raw = bytes.fromhex(env["cborHex"])
n = raw[0] & 0x1f
off = 1 if n < 24 else 2 if n == 24 else 3 if n == 25 else 5
print(hashlib.blake2b(bytes([ver]) + raw[off:], digest_size=28).hexdigest())
PY
}

# Wrap a blueprint compiledCode hex in one CBOR bytestring and write a cardano-cli .plutus envelope.
# Args: compiledCode_hex version(2|3) out_path.
wrap_plutus(){ python3 - "$1" "$2" "$3" <<'PY'
import json, sys
cc = bytes.fromhex(sys.argv[1]); ver = sys.argv[2]
head = bytes([0x59]) + len(cc).to_bytes(2, "big") if len(cc) < 65536 else bytes([0x5a]) + len(cc).to_bytes(4, "big")
json.dump({"type": f"PlutusScriptV{ver}", "description": "", "cborHex": (head + cc).hex()}, open(sys.argv[3], "w"))
PY
}

# Rebuild every script the recovery attaches, from PUBLIC inputs, and refuse unless each hashes to the
# credential the ceremony named. Args: PARAMS NETWORK CS_PLUTUS PROJECT AIKEN WORK. Writes
# WORK/artefact.json (the derived ceremony), bound/twoway_spend/twoway_beacon.plutus and the
# redeemer cbors. Exit 3 on any hash mismatch or rebuild failure.
rebuild_and_verify_scripts(){
  local params=$1 network=$2 cs_plutus=$3 project=$4 aiken=$5 work=$6
  mkdir -p "$work"
  # bound.plutus + the derived artefact, from the same rebuild verify_ceremony blesses
  # --for-escape, not --derive-only: the coherence gate refuses a crossed band, a
  # zero floor, a foreign payout key and a bot/client collision, and the validator
  # leaves the escape branch OPEN under every one of them. Those are the ceremonies
  # a client most needs to walk away from, so recovery derives the addresses and
  # says loudly what was wrong instead of refusing to help.
  #
  # The refusal is REPORTED. Discarding it here once made a nine-parameter tool
  # reading a seven-parameter file look like an unexplained "could not derive".
  if ! python3 "$ESCAPE_DIR/verify_ceremony.py" --params "$params" --network "$network" \
    --project "$project" --aiken "$aiken" --for-escape --decimals 0 \
    --emit-applied-script "$work/bound.plutus" --json-out "$work/artefact.json" \
    >"$work/verify.out" 2>"$work/verify.err"; then
      echo "REFUSING: verify_ceremony.py could not derive the ceremony from $params" >&2
      echo "--- what it said: ---" >&2
      cat "$work/verify.err" "$work/verify.out" >&2
      return 3
  fi
  # A ceremony this tool would not endorse is still recoverable, and the client
  # has to be told which one they are in.
  python3 - "$work/artefact.json" >&2 <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
if "coherence_refusal" in d:
    sys.stderr.write("WARNING: this ceremony is one the verifier refuses to endorse:\n"
                     f"  {d['coherence_refusal']}\n"
                     "Recovering from it anyway — your key is what the escape branch\n"
                     "reads, and it reads nothing else. Do not resume trading under it.\n")
PY
  local dapp beacon applied_hash
  read -r dapp beacon applied_hash < <(python3 - "$work/artefact.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
ap = {p["name"]: p for p in d["applied_parameters"]}
print(ap["dapp_hash"]["value"], ap["beacon_id"]["value"], d["derived"]["applied_script_hash"])
PY
)
  local got
  got=$(script_hash "$work/bound.plutus" 3)
  [ "$got" = "$applied_hash" ] || { echo "REFUSING: rebuilt bound script hashes to $got, ceremony says $applied_hash" >&2; return 3; }
  echo "verified bound.plutus == $applied_hash"

  # twoway_spend.plutus — the unparameterised cardano-swaps spend validator, straight from the public blueprint
  local spend_cc
  spend_cc=$(python3 -c "import json,sys;print(next(v['compiledCode'] for v in json.load(open(sys.argv[1]))['validators'] if v['title']=='two_way_swap.swap_script'))" "$cs_plutus") || return 3
  wrap_plutus "$spend_cc" 2 "$work/twoway_spend.plutus"
  got=$(script_hash "$work/twoway_spend.plutus" 2)
  [ "$got" = "$dapp" ] || { echo "REFUSING: rebuilt spend script hashes to $got, ceremony dapp_hash is $dapp" >&2; return 3; }
  echo "verified twoway_spend.plutus == $dapp"

  # twoway_beacon.plutus — the beacon policy applied with dapp_hash
  "$aiken" blueprint apply -i "$cs_plutus" -m two_way_swap -v beacon_script "581c$dapp" -o "$work/beacon_applied.json" >/dev/null 2>&1 || {
    echo "REFUSING: could not apply dapp_hash to the beacon policy from $cs_plutus" >&2; return 3; }
  local beacon_cc
  beacon_cc=$(python3 -c "import json,sys;print(next(v['compiledCode'] for v in json.load(open(sys.argv[1]))['validators'] if v['title']=='two_way_swap.beacon_script'))" "$work/beacon_applied.json") || return 3
  wrap_plutus "$beacon_cc" 2 "$work/twoway_beacon.plutus"
  got=$(script_hash "$work/twoway_beacon.plutus" 2)
  [ "$got" = "$beacon" ] || { echo "REFUSING: rebuilt beacon script hashes to $got, ceremony beacon_id is $beacon" >&2; return 3; }
  echo "verified twoway_beacon.plutus == $beacon"

  # cardano-swaps two-way redeemers + the () for the bound withdraw-0
  printf '\xd8\x79\x80' > "$work/spend_mint.cbor"      # SwapRedeemer::SpendWithMint
  printf '\xd8\x7a\x80' > "$work/create_close.cbor"    # BeaconRedeemer::CreateOrCloseSwaps (burn)
  printf '\xd8\x79\x80' > "$work/unit.cbor"            # () for maker_stake_bound withdraw
}

# One round's worth of order UTxOs: the first `k` of them, with the beacons they
# carry and the value they hold. Writes spends.txt / burn.txt / outval.txt into
# `work`. Prints how many it took and how many are left behind.
plan_round(){ python3 - "$1" "$2" "$3" "$4" "$5" <<'PY'
import json, sys
utxos = json.load(open(sys.argv[1])); beacon, work = sys.argv[2], sys.argv[3]
k, max_value_bytes = int(sys.argv[4]), int(sys.argv[5])
# Only a real cardano-swaps order can be spent here. The order address is a
# PlutusV2 script expecting a typed datum, so a UTxO with no inline datum can
# never be spent by anyone — and one carrying no beacon of this ceremony's policy
# is not this book's order. Batching either one poisons every round the tool will
# ever build: the spend leg fails, and because the selection is deterministic the
# same poison is picked again on every re-run. Anyone can create one by sending a
# datumless lovelace to a public address, so this filter is what stops a stranger
# bricking a client's recovery for the price of a min-UTxO.
def spendable(u):
    if u.get("inlineDatum") is None and u.get("inlineDatumhash") is None \
            and u.get("datum") is None and u.get("datumhash") is None:
        return False
    return beacon in u.get("value", {})


refs = sorted(r for r in utxos if spendable(utxos[r]))
skipped = sorted(r for r in utxos if r not in set(refs))
for ref in skipped:
    sys.stderr.write(
        f"  skipping {ref}: not a spendable order of this book (no inline datum, or no "
        f"beacon of policy {beacon[:16]}...). It is not recoverable by this tool and "
        f"nothing here can spend it.\n")
if not refs:
    sys.stderr.write(
        f"nothing to recover: the order address holds {len(utxos)} UTxO(s) and none is a "
        f"spendable order of this book\n" if utxos else
        "nothing to recover: the order address holds no UTxOs\n")
    sys.exit(4)


def head(n):
    """Bytes a canonical CBOR head costs for the argument n."""
    return 1 if n < 24 else 2 if n < 0x100 else 3 if n < 0x10000 else 5 if n < 0x100000000 else 9


def value_bytes(lovelace, toks):
    """The serialised length of an output's value, exactly.

    maxValueSize is a THIRD protocol limit, separate from transaction size and
    from the execution budget, and it is the one a token-rich order address hits
    first: everything recovered lands in one output, `transaction build` does not
    check it either, and the node answers OutputTooBigUTxO. Counted here so a
    round that would not fit is never built rather than never submitted."""
    by_policy = {}
    for unit, q in toks.items():
        pol, _, name = unit.partition(".")
        by_policy.setdefault(pol, {})[name] = q
    n = 1 + head(lovelace) + head(len(by_policy))          # [coin, {policy: ...}]
    for pol, assets in by_policy.items():
        n += head(len(pol) // 2) + len(pol) // 2 + head(len(assets))
        for name, q in assets.items():
            n += head(len(name) // 2) + len(name) // 2 + head(q)
    return n


def gather(refs_taken):
    burns, lovelace, toks = [], 0, {}
    for ref in refs_taken:
        v = utxos[ref]["value"]; lovelace += v.get("lovelace", 0)
        for pol, inner in v.items():
            if pol == "lovelace": continue
            for name, q in inner.items():
                unit = f"{pol}.{name}"
                if pol == beacon: burns.append(f"{-q} {unit}")
                else: toks[unit] = toks.get(unit, 0) + q
    return burns, lovelace, toks


taken, rest = refs[:k], refs[k:]
burns, lovelace, toks = gather(taken)
while len(taken) > 1 and value_bytes(lovelace, toks) > max_value_bytes:
    taken, rest = taken[:-1], refs[len(taken) - 1:]
    burns, lovelace, toks = gather(taken)
if value_bytes(lovelace, toks) > max_value_bytes:
    sys.stderr.write(
        f"a single order UTxO carries {value_bytes(lovelace, toks)} bytes of value, over the "
        f"{max_value_bytes}-byte per-output limit; it cannot be recovered into one output\n")
    sys.exit(4)
# cardano-swaps requires a beacon execution in every transaction that spends one
# of its orders, so a round carrying no beacon to burn cannot be submitted at all.
if not burns:
    sys.stderr.write(f"the {len(taken)} UTxO(s) in this round carry no beacon of policy "
                     f"{beacon}; a spend of a cardano-swaps order without a beacon "
                     f"execution is unsubmittable\n")
    sys.exit(4)
open(f"{work}/spends.txt", "w").write("".join(r + "\n" for r in taken))
open(f"{work}/burn.txt", "w").write(" + ".join(burns))
open(f"{work}/outval.txt", "w").write(
    "+".join([str(lovelace)] + [f"{q} {u}" for u, q in toks.items()]))
print(len(taken), len(rest))
PY
}

# What a built transaction actually costs: its serialised length, and the ex-units
# `build` already evaluated and wrote into it. Both read out of the artefact, so
# neither is an estimate and neither needs a second node round-trip. Args: tx file
# flag(--tx-file|--tx-body-file). Prints "bytes mem steps".
measure_tx(){
  $CLI debug transaction view "$2" "$1" --output-json --out-file "$1.view.json" 2>/dev/null || return 4
  python3 - "$1" "$1.view.json" <<'PY'
import json, sys
env = json.load(open(sys.argv[1]))
try:
    view = json.load(open(sys.argv[2]))
except (OSError, json.JSONDecodeError) as exc:
    sys.stderr.write(f"could not read the built transaction back: {exc}; "
                     "refusing to judge it against the budget\n")
    sys.exit(4)
size = len(env["cborHex"]) // 2
mem = steps = 0
# cardano-cli 11.0.0.0 spells this "execution units", with a space, like every
# other key in that renderer ("collateral inputs", "reference inputs"). Guessing
# camelCase here cost nothing loudly and everything quietly: the sum stayed 0,
# the fail-closed guard below fired, and every recovery round aborted before it
# was signed. The spelling is pinned by a test against a REAL transaction's view,
# captured from the binary rather than written by hand.
UNIT_KEYS = ("execution units", "executionUnits", "exUnits")


def walk(node):
    global mem, steps
    if isinstance(node, dict):
        for key in UNIT_KEYS:
            u = node.get(key)
            if isinstance(u, dict):
                mem += int(u.get("memory", u.get("mem", 0)))
                steps += int(u.get("steps", u.get("cpu", 0)))
                break
        for v in node.values():
            walk(v)
    elif isinstance(node, list):
        for v in node: walk(v)
walk(view)
# Every script leg carries a redeemer, so a transaction that spends a script
# input and reports no ex-units at all was not understood, and a limit check
# against zero would wave through anything.
if mem == 0 and steps == 0:
    sys.stderr.write("could not read execution units out of the built transaction; "
                     "refusing to judge it against the budget\n")
    sys.exit(4)
print(size, mem, steps)
PY
}

# The --tx-in flags for one round, one per line of `spends`. `read` returns
# non-zero on a final line with no newline and a plain `while read` loop then
# DROPS it — which cost this tool the last order UTxO of every round while
# burn.txt and outval.txt still counted it, so nothing balanced and no recovery
# could be built at all. The trailing newline is written now and the guard is
# here as well, because one silent missing input is a client's inventory.
# ONE ARGUMENT PER LINE, read into an array by the caller. Returning a single
# space-separated string and letting the shell split it into argv is correct only
# while every value is one word — and `--mint` never is (the burn list is
# " + "-joined), nor is `--tx-out` once the client holds any token, which is the
# only reason this tool exists. Splitting shattered both into stray positionals.
# A test that greps the returned STRING cannot see that; one that counts
# arguments can.
spend_args_for(){
  local ref
  while read -r ref || [ -n "$ref" ]; do
    [ -n "$ref" ] || continue
    if [ -n "$REF_SPEND" ]; then
      printf '%s\n' --tx-in "$ref" --spending-tx-in-reference "$REF_SPEND" \
        --spending-plutus-script-v2 --spending-reference-tx-in-inline-datum-present \
        --spending-reference-tx-in-redeemer-cbor-file "$WORK/spend_mint.cbor"
    else
      printf '%s\n' --tx-in "$ref" --tx-in-script-file "$SPEND" \
        --tx-in-inline-datum-present --tx-in-redeemer-cbor-file "$WORK/spend_mint.cbor"
    fi
  done < "$1"
}

# cardano-cli >= 10.16 prints `transaction txid` as {"txhash": "..."}; older ones
# print the bare hash. Take either.
tx_hash(){ python3 -c "
import json, sys
raw = sys.stdin.read().strip()
try: print(json.loads(raw)['txhash'])
except Exception: print(raw)
"; }

# Everything a round's transaction says apart from its spend legs. Separated from
# the build call so the suite can read it: this is where the recovered value is
# routed, and a transposed --tx-out/--change-address pair would send a client's
# whole recovery to the funding wallet the operator already knows.
# Args: work collateral fee-input.
round_flags(){
  local work=$1 coll=$2 fundin=$3
  printf '%s\n' --tx-in "$fundin" --tx-in-collateral "$coll" --mint "$(cat "$work/burn.txt")"
  if [ -n "$REF_BEACON" ]; then
    printf '%s\n' --mint-tx-in-reference "$REF_BEACON" --mint-plutus-script-v2 \
      --mint-reference-tx-in-redeemer-cbor-file "$WORK/create_close.cbor" \
      --policy-id "$BEACON"
  else
    printf '%s\n' --mint-script-file "$BEACONP" \
      --mint-redeemer-cbor-file "$WORK/create_close.cbor"
  fi
  printf '%s\n' --withdrawal "$REWARD_ADDR+0"
  if [ -n "$REF_BOUND" ]; then
    printf '%s\n' --withdrawal-tx-in-reference "$REF_BOUND" --withdrawal-plutus-script-v3 \
      --withdrawal-reference-tx-in-redeemer-cbor-file "$WORK/unit.cbor"
  else
    printf '%s\n' --withdrawal-script-file "$BOUND" \
      --withdrawal-redeemer-cbor-file "$WORK/unit.cbor"
  fi
  printf '%s\n' \
    --required-signer-hash "$CLIENT_VKH" \
    --tx-out "$DEST+$(cat "$work/outval.txt")" \
    --change-address "$FUND"
}

# --- reference scripts, when they exist and prove they are the right ones ---------
#
# The three attached scripts are 12,668 of a one-order recovery's ~14,000 bytes — 94% of
# the transaction, and the only reason SIZE is what limits a batch. Referencing them
# instead removes nearly all of it.
#
# The security argument does NOT change, because the gate does not change: a referenced
# script is used ONLY if the script actually sitting at that UTxO hashes to the very
# credential this ceremony names, checked here against chain data exactly as the rebuilt
# ones are checked against the blueprint. A reference UTxO is somebody else's output; it
# is therefore treated as a claim to be verified, never as a fact.
#
# And it is never a DEPENDENCY. Any reference that is missing, spent, or carries the
# wrong script falls back to attaching that script inline, per script, with a note. A
# client's recovery must not stop working because an operator stopped hosting something.
REF_SPEND=""; REF_BEACON=""; REF_BOUND=""

# Args: refs.json work. Sets the three REF_* variables for whichever references verify.
resolve_reference_scripts(){
  local refs=$1 work=$2 name ref got want ver
  # CLEARED FIRST, every time. These are re-resolved per round precisely because the
  # operator can spend a reference between rounds; leaving a stale value here made the
  # tool announce "attaching it inline" and then reference a UTxO that no longer exists.
  REF_SPEND=""; REF_BEACON=""; REF_BOUND=""
  [ -f "$refs" ] || { echo "  no reference scripts named; attaching all three inline"; return 0; }
  for name in spend beacon bound; do
    ref=$(python3 -c "
import json, sys
print(json.load(open(sys.argv[1])).get(sys.argv[2], ''))" "$refs" "$name")
    [ -n "$ref" ] || continue
    case "$name" in
      spend)  want="$DAPP_HASH";;
      beacon) want="$BEACON";;
      bound)  want="$APPLIED_HASH";;
    esac
    if ! $CLI query utxo --tx-in "$ref" $MAGIC --out-file "$work/ref.$name.json" 2>/dev/null; then
      echo "  reference $name ($ref) could not be read; attaching that script inline" >&2
      continue
    fi
    got=$(python3 - "$work/ref.$name.json" <<'PY'
import hashlib, json, sys
u = json.load(open(sys.argv[1]))
if not u:
    sys.exit(0)                       # spent or absent: no hash, caller inlines
script = next(iter(u.values())).get("referenceScript")
if not script:
    sys.exit(0)                       # a UTxO with no script attached
raw = script.get("script", script)
cbor = raw.get("cborHex") or raw.get("cbor")
if not cbor:
    sys.exit(0)
# The LANGUAGE the UTxO declares, never one assumed from the role we wanted it for.
# The ledger hashes a script under its actual language, so the same bytes stored as V3
# hash differently from V2 — and taking the version from the role let a V3-tagged copy
# of the V2 spend script hash to dapp_hash and pass as "verified", while the ledger
# could never resolve it. Unrecognised or absent means refuse.
declared = str(raw.get("type") or script.get("type") or script.get("scriptLanguage") or "")
version = 3 if "V3" in declared else 2 if "V2" in declared else 1 if "V1" in declared else 0
if not version:
    sys.exit(0)
# VERBATIM, no unwrapping. `query utxo` returns the reference script as the
# ledger stores it, which IS the hash preimage. The local .plutus envelopes are
# a DIFFERENT shape — wrap_plutus writes them with an extra CBOR bytestring
# around the compiled code — so script_hash() strips one header and this must
# not. Stripping here hashed bare flat UPLC and refused all three of our own
# published references; the unit tests agreed with it because their fixtures
# were built from the envelope rather than from real query output.
print(hashlib.blake2b(bytes([version]) + bytes.fromhex(cbor), digest_size=28).hexdigest())
PY
)
    if [ "$got" = "$want" ]; then
      case "$name" in
        spend)  REF_SPEND="$ref";;
        beacon) REF_BEACON="$ref";;
        bound)  REF_BOUND="$ref";;
      esac
      echo "  referencing $name at $ref (verified == $want)"
    elif [ -z "$got" ]; then
      echo "  reference $name ($ref) is spent or carries no script; attaching it inline" >&2
    else
      echo "  REFUSING that reference: $name at $ref carries script $got, this ceremony" >&2
      echo "  names $want. Attaching the rebuilt script inline instead." >&2
    fi
  done
}

# sourced by escape.test.sh = definitions only; executed = run the recovery
(return 0 2>/dev/null) && return 0

CLI="cardano-cli"; SIGN_CLI=""; AIKEN="${AIKEN:-$HOME/.aiken/bin/aiken}"; MAGIC_N=1; NETWORK=""
PARAMS=""; CS_PLUTUS=""; PROJECT="$(cd "$(dirname "$0")" && pwd)"; DEST=""; FUND=""; SKEY=""
OUTDIR=""; BUILD_ONLY=0; REFS=""
# How many resting orders one recovery transaction tries to carry. A starting
# point, not a safety property: every round is measured against the node's own
# limits before it is submitted and halves itself if it does not fit.
#
# SIZE is what runs out here, not the execution budget. MEASURED on preprod
# 2026-08-06 by recovering a real nine-parameter ceremony (order address
# addr_test1xqge9z36…c7p2rwdrq, recovery tx 62979a2e…, all three orders spent,
# 100% to the client):
#
#   one order   13,953-byte body, 14,059 fully witnessed
#   three       14,062-byte body, 14,168 fully witnessed
#   slope       54.5 bytes per additional order
#   ceiling     ~43 orders  (EXTRAPOLATED from those two measured points)
#
# The 16,384-byte limit applies to the WITNESSED transaction, not the body. At
# three orders the whole recovery used 2.51% of the memory budget and 1.45% of
# the step budget while sitting at 86% of the size limit, so execution units
# never come close. They are quadratic in the batch all the same — cardano-swaps
# rescans the input list once per input — which is why the ceiling is stated in
# bytes and the benches keep measuring both.
#
# 32 rather than 43: ~600 bytes of slack for a multi-pair client's extra beacon
# names (+35 each), a second or third collateral input and fee drift. A round
# that still does not fit halves itself, so being conservative costs one extra
# round; being wrong the other way used to strand a client. Raising this wants
# the three scripts published as reference scripts, which would remove 94% of
# the transaction.
MAXK="${MAXK:-32}"
# Bytes reserved in the body check for the witness set the client adds after it.
# One vkey witness is 100 bytes of CBOR; the rest is slack, and the finished
# transaction is measured again before submit anyway.
WITNESS_ALLOWANCE=512
CONFIRM_POLL_SECONDS=10
CONFIRM_TIMEOUT_SECONDS=1200
while [ $# -gt 0 ]; do
  case "$1" in
    --params) PARAMS="$2"; shift 2;;
    --cardano-swaps-plutus) CS_PLUTUS="$2"; shift 2;;
    --project) PROJECT="$2"; shift 2;;
    --network) NETWORK="$2"; shift 2;;
    --dest) DEST="$2"; shift 2;;
    --fund-addr) FUND="$2"; shift 2;;
    --signing-key) SKEY="$2"; shift 2;;
    --cardano-cli) CLI="$2"; shift 2;;
    --sign-cli) SIGN_CLI="$2"; shift 2;;
    --aiken) AIKEN="$2"; shift 2;;
    --testnet-magic) MAGIC_N="$2"; shift 2;;
    --out-dir) OUTDIR="$2"; shift 2;;
    --max-orders-per-tx) MAXK="$2"; shift 2;;
    --reference-scripts) REFS="$2"; shift 2;;
    --build-only) BUILD_ONLY=1; shift;;
    *) echo "unknown argument: $1" >&2; exit 2;;
  esac
done
: "${SIGN_CLI:=$CLI}"
for req in PARAMS CS_PLUTUS DEST FUND NETWORK; do
  [ -n "${!req}" ] || { echo "missing required --${req,,} (see header)" >&2; exit 2; }
done
[ "$BUILD_ONLY" = 1 ] || [ -n "$SKEY" ] || { echo "missing --signing-key (or pass --build-only)" >&2; exit 2; }
# Every node call has to carry the network the ceremony was derived for. This was
# `--testnet-magic` unconditionally, so `--network mainnet` derived a correct
# addr1... order address and then queried preprod for it: a mainnet client under
# duress was told, with no error, that their order address was empty.
case "$NETWORK" in
  mainnet) MAGIC="--mainnet";;
  testnet) MAGIC="--testnet-magic $MAGIC_N";;
  *) echo "unknown --network '$NETWORK' (mainnet|testnet)" >&2; exit 2;;
esac
WORK="${OUTDIR:-$(mktemp -d)}"; mkdir -p "$WORK"
# --build-only exists to hand a body to a machine with no node and no network, so
# it must not delete the body on the way out. It did: the client was told the path
# and found nothing there.
[ -n "$OUTDIR" ] || [ "$BUILD_ONLY" = 1 ] || trap 'rm -rf "$WORK"' EXIT

# 1. rebuild + hash-verify every attached script, from public inputs only
rebuild_and_verify_scripts "$PARAMS" "$NETWORK" "$CS_PLUTUS" "$PROJECT" "$AIKEN" "$WORK" || exit 3
BOUND="$WORK/bound.plutus"; SPEND="$WORK/twoway_spend.plutus"; BEACONP="$WORK/twoway_beacon.plutus"
read -r ORDER_ADDR REWARD_ADDR CLIENT_VKH BEACON DAPP_HASH APPLIED_HASH < <(python3 - "$WORK/artefact.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
ap = {p["name"]: p for p in d["applied_parameters"]}
print(d["derived"]["order_address"], d["derived"]["reward_address"],
      ap["client_owner_vkh"]["value"], ap["beacon_id"]["value"],
      ap["dapp_hash"]["value"], d["derived"]["applied_script_hash"])
PY
)
echo "order address: $ORDER_ADDR"

# Every round withdraws +0 from the bound credential — the withdraw-0 trick that
# runs the script. The ledger requires a withdrawal to drain the FULL balance, so
# one accrued reward makes every round unbuildable with a bare phase-1 error and
# no diagnosis. `publish` deliberately leaves delegation client-signable, so this
# is an ordinary permitted action rather than an unreachable one, and a client who
# delegated is exactly the client who most needs a clear answer here.
# Whether the registration positive control below actually ran. It is the only check that
# catches generation drift, and it needs a reward balance this tool may fail to read.
DRIFT_CHECKED=0
if $CLI conway query stake-address-info --address "$REWARD_ADDR" $MAGIC \
     --out-file "$WORK/reward.json" 2>/dev/null; then
  DRIFT_CHECKED=1
  python3 - "$WORK/reward.json" "$REWARD_ADDR" "$APPLIED_HASH" <<'PY' || exit $?
import json, sys
info = json.load(open(sys.argv[1]))
rows = info if isinstance(info, list) else [info]
# Positive control against generation drift. A funded book's bound stake credential
# is ALWAYS registered — an unregistered script stake credential cannot authorise
# the withdraw-0 and so bricks the orders. An empty stake-address-info therefore
# proves this is NOT the credential holding the funds, almost always because the
# ceremony ran on an EARLIER validator generation than the source this checkout
# rebuilds from. The parameters can be right and the source tree still wrong, so
# recovery must refuse HERE rather than query a wrong-but-plausible order address
# and report the false "nothing to recover".
# An unregistered credential is an empty list; a cardano-cli that answers with a
# single empty object counts the same, so treat any all-empty response as unregistered.
if not rows or all(not r for r in rows):
    sys.stderr.write(
        f"REFUSING: {sys.argv[2]} is not a registered stake credential on this network,\n"
        "  so it is not the credential holding the funds. A funded book's bound credential\n"
        "  is always registered; an unregistered derivation means this checkout rebuilt a\n"
        f"  DIFFERENT validator generation (applied hash {sys.argv[3]}) than the one behind\n"
        "  the funded book. The parameters may be right; the source tree is wrong. Recover\n"
        "  with the matching generation from the saturnswap-maker-verify repo: its\n"
        "  GENERATIONS.md lists every published SOURCE generation, and each is a directory\n"
        "  named after that source hash — not after the applied hash above, which is the one\n"
        "  this wrong tree just derived. Try them with --project generations/<source hash>\n"
        "  until the credential registers. Nothing was submitted.\n")
    sys.exit(3)
owed = sum(int(r.get("rewardAccountBalance") or 0) for r in rows)
if owed:
    sys.stderr.write(
        f"REFUSING: {sys.argv[2]} has {owed} lovelace of unclaimed staking rewards.\n"
        "  Every round here withdraws +0 to run the bound script, and the ledger only\n"
        "  accepts a withdrawal that drains the whole balance — so no round can be\n"
        "  built until these are claimed. Withdraw them first with your own key, then\n"
        "  re-run. Nothing was submitted.\n")
    sys.exit(4)
PY
else
  echo "REFUSING: could not read the reward balance for $REWARD_ADDR." >&2
  echo "  An unreadable balance is not a balance of zero. Every round here withdraws +0" >&2
  echo "  to run the bound script, and the ledger only accepts a withdrawal that drains" >&2
  echo "  the whole balance — so if this credential has accrued anything, every round" >&2
  echo "  fails phase 1 with no diagnosis at all. Proceeding on a guess is how a client" >&2
  echo "  ends up staring at that. Point --cardano-cli at a reachable node and re-run;" >&2
  echo "  if you are certain the balance is zero, ESCAPE_ASSUME_NO_REWARDS=1 says so" >&2
  echo "  explicitly. Nothing was submitted." >&2
  [ "${ESCAPE_ASSUME_NO_REWARDS:-0}" = 1 ] || exit 4
  echo "  ESCAPE_ASSUME_NO_REWARDS=1 — proceeding on your word." >&2
  # ⚠️ AND THE GENERATION WENT UNCHECKED WITH IT. The registration positive control is the
  # only thing that catches a wrong source tree, and it reads the very balance that just
  # failed to load — so this flag waives rewards AND drift together, which its name does not
  # say. An empty order address below is then indistinguishable from a book that is simply
  # somewhere else, so it is reported as unproven rather than as nothing.
  echo "  ⚠️ the generation-drift control could not run either: it reads the same balance." >&2
fi

# 2. plan the recovery against the protocol's own limits
#
# A transaction carrying every resting order is not a transaction: the three
# attached scripts alone are kilobytes, and each order adds an input, a redeemer
# and three beacon burns against a 16 KB ceiling and a per-transaction execution
# budget. `transaction build` does NOT enforce either — it fills in ex-units,
# balances, and hands back a body that the node will refuse — so the tool that
# must not strand a client is the one that measures.
#
# Recovery therefore runs in rounds. Each round takes what fits, and the batch
# that gets built is measured against the limits this node reports before it is
# submitted; anything over halves the batch and rebuilds. Rounds are independent
# whole recoveries, so an interrupted run is resumed by running this again.
$CLI query protocol-parameters $MAGIC --out-file "$WORK/pparams.json" || exit 4
read -r MAX_TX_BYTES MAX_MEM MAX_STEPS MAX_VALUE_BYTES < <(python3 - "$WORK/pparams.json" <<'PY'
import json, sys
p = json.load(open(sys.argv[1]))
ex = p.get("maxTxExecutionUnits") or {}
mem = ex.get("memory", ex.get("exUnitsMem"))
steps = ex.get("steps", ex.get("exUnitsSteps"))
value = p.get("maxValueSize")
if isinstance(value, dict): value = value.get("bytes")
if None in (p.get("maxTxSize"), mem, steps, value):
    sys.stderr.write("protocol parameters name no maxTxSize/maxTxExecutionUnits/maxValueSize; "
                     "refusing to guess the limits a recovery must fit under\n")
    sys.exit(4)
print(p["maxTxSize"], mem, steps, value)
PY
) || exit 4
echo "protocol limits: ${MAX_TX_BYTES} bytes, ${MAX_MEM} mem, ${MAX_STEPS} steps, ${MAX_VALUE_BYTES} bytes of value per output"



# Build one round from the files plan_round wrote. Args: work.
build_round(){
  local work=$1
  local -a spend_args=() flags=()
  mapfile -t spend_args < <(spend_args_for "$work/spends.txt")
  # fee + collateral from the CLIENT's own wallet (never the operator's), re-read
  # every round because the previous round's change is what pays for this one
  $CLI query utxo --address "$FUND" $MAGIC --out-file "$work/fund.json" || return 4
  local coll fundin
  read -r coll fundin < <(python3 - "$work/fund.json" <<'PY'
import json, sys
u = json.load(open(sys.argv[1]))
def refscript(v): return v.get("referenceScript") not in (None, {})
pure = sorted([(k, v["value"]["lovelace"]) for k, v in u.items()
               if list(v["value"].keys()) == ["lovelace"] and v["value"]["lovelace"] >= 5_000_000
               and not refscript(v)], key=lambda x: x[1])
if not pure:
    sys.stderr.write("no pure-ADA collateral (>=5 ADA) at the funding address\n"); sys.exit(4)
coll = pure[0][0]
# Everything on the fee input that is not paid to the destination lands in the
# change output, and nothing measures THAT output's value. A funding address is
# public — the operator knows it, it is where fills are paid — so one UTxO stuffed
# with junk assets and a lovelace more than the client's largest would be selected
# on size alone and bloat the change past maxValueSize. Prefer pure ADA; fall back
# to the leanest UTxO by asset count only if there is no pure one.
def assets(v):
    return sum(len(inner) for pol, inner in v["value"].items() if pol != "lovelace")


rest = [(k, v["value"]["lovelace"], assets(v))
        for k, v in u.items() if k != coll and not refscript(v)]
if not rest:
    sys.stderr.write("no funding UTxO for the fee\n"); sys.exit(4)
pure_fee = sorted([r for r in rest if r[2] == 0], key=lambda x: -x[1])
if pure_fee:
    print(coll, pure_fee[0][0])
else:
    lean = sorted(rest, key=lambda x: (x[2], -x[1]))
    sys.stderr.write(
        f"  no pure-ADA funding UTxO; paying the fee from {lean[0][0]}, which carries "
        f"{lean[0][2]} asset(s) that will ride into the change output\n")
    print(coll, lean[0][0])
PY
) || return 4
  mapfile -t flags < <(round_flags "$work" "$coll" "$fundin")
  # shellcheck disable=SC2086 -- $MAGIC is deliberately two words
  $CLI conway transaction build $MAGIC "${spend_args[@]}" "${flags[@]}" \
    --out-file "$work/escape.body"
}

ROUND=0
while :; do
  $CLI query utxo --address "$ORDER_ADDR" $MAGIC --out-file "$WORK/order.json" || exit 4
  python3 -c "import json,sys; sys.exit(0 if json.load(open(sys.argv[1])) else 9)" "$WORK/order.json"
  case $? in
    9) [ "$ROUND" -gt 0 ] && { echo "ESCAPE COMPLETE: the order address is empty"; exit 0; }
       if [ "$DRIFT_CHECKED" != 1 ]; then
         echo "UNPROVEN: $ORDER_ADDR holds no UTxOs, and the generation was never verified." >&2
         echo "  The registration control that catches a wrong validator generation could not" >&2
         echo "  run, because the reward balance it reads was unreadable and the run continued" >&2
         echo "  on ESCAPE_ASSUME_NO_REWARDS=1. An empty address on a WRONG generation looks" >&2
         echo "  exactly like this, so do NOT read it as 'the book is gone'. Point --cardano-cli" >&2
         echo "  at a reachable node and re-run, or try each source generation in the" >&2
         echo "  saturnswap-maker-verify GENERATIONS.md with --project. Nothing was submitted." >&2
         exit 3
       fi
       echo "nothing to recover: the order address holds no UTxOs" >&2; exit 4;;
    0) ;;
    *) exit 4;;
  esac
  ROUND=$((ROUND + 1))
  RD="$WORK/round.$ROUND"; mkdir -p "$RD"

  # Re-resolved EVERY round, not once. The references belong to the operator and the
  # operator can spend them — including between our rounds. Resolving once made them a
  # dependency for the rest of the run: round 2 would build against a spent UTxO, the
  # halving loop would read that as "too big" and shrink six times, and the client would
  # be told to look at cardano-cli. Three queries a round is the price of the claim that
  # a reference is an optimisation and never a dependency.
  resolve_reference_scripts "$REFS" "$RD"

  # Take what fits. A round that measures over the limits is not submitted; the
  # batch halves and rebuilds, so a wrong --max-orders-per-tx costs a rebuild
  # rather than a stranded client.
  K=$MAXK
  while :; do
    read -r TOOK LEFT < <(plan_round "$WORK/order.json" "$BEACON" "$RD" "$K" "$MAX_VALUE_BYTES") || exit 4
    if ! build_round "$RD" 2>"$RD/build.err"; then
      cat "$RD/build.err" >&2
      # A reference can die between resolving it and building with it — the operator
      # owns those UTxOs and that race cannot be closed by re-resolving sooner. So the
      # first thing to try is not a smaller batch but NO references: the scripts this
      # tool rebuilt and hash-verified itself always work. Halving a batch because a
      # reference vanished wastes six node round-trips and then blames cardano-cli.
      if [ -n "$REF_SPEND$REF_BEACON$REF_BOUND" ]; then
        echo "  build failed with reference scripts in use — retrying with all three"
        echo "  attached inline, which needs nothing from anyone else"
        REF_SPEND=""; REF_BEACON=""; REF_BOUND=""
        if build_round "$RD" 2>"$RD/build.inline.err"; then
          read -r TXBYTES TXMEM TXSTEPS < <(measure_tx "$RD/escape.body" --tx-body-file) || exit 4
          TXBYTES=$((TXBYTES + WITNESS_ALLOWANCE))
          echo "round $ROUND: $TOOK order UTxO(s), $LEFT left  ->  $TXBYTES/$MAX_TX_BYTES bytes, $TXMEM/$MAX_MEM mem, $TXSTEPS/$MAX_STEPS steps"
          if [ "$TXBYTES" -le "$MAX_TX_BYTES" ] && [ "$TXMEM" -le "$MAX_MEM" ] && [ "$TXSTEPS" -le "$MAX_STEPS" ]; then
            break
          fi
        else
          cat "$RD/build.inline.err" >&2
        fi
      fi
      [ "$K" -gt 1 ] || {
        echo "REFUSING: even a single order UTxO will not build. The error above is" >&2
        echo "  cardano-cli's own; nothing was submitted and this is not a batching" >&2
        echo "  problem." >&2
        exit 3; }
      K=$((K / 2))
      echo "  build failed at this batch size — retrying with $K order UTxO(s) per transaction"
      continue
    fi
    read -r TXBYTES TXMEM TXSTEPS < <(measure_tx "$RD/escape.body" --tx-body-file) || exit 4
    # The witness set the client is about to add is not in the body, so the body
    # is measured against a limit the finished transaction has to meet. Leave the
    # signature room rather than discovering it at submit.
    TXBYTES=$((TXBYTES + WITNESS_ALLOWANCE))
    echo "round $ROUND: $TOOK order UTxO(s), $LEFT left  ->  $TXBYTES/$MAX_TX_BYTES bytes, $TXMEM/$MAX_MEM mem, $TXSTEPS/$MAX_STEPS steps"
    if [ "$TXBYTES" -le "$MAX_TX_BYTES" ] && [ "$TXMEM" -le "$MAX_MEM" ] && [ "$TXSTEPS" -le "$MAX_STEPS" ]; then
      break
    fi
    [ "$K" -gt 1 ] || {
      echo "REFUSING: a single order UTxO does not fit under this node's limits" >&2
      echo "  ($TXBYTES/$MAX_TX_BYTES bytes, $TXMEM/$MAX_MEM mem, $TXSTEPS/$MAX_STEPS steps)." >&2
      echo "  Nothing was submitted. This is not a batching problem and lowering" >&2
      echo "  --max-orders-per-tx will not help." >&2
      exit 3; }
    K=$((K / 2))
    echo "  over the limits — retrying this round with $K order UTxO(s) per transaction"
  done

  TXID=$($SIGN_CLI conway transaction txid --tx-body-file "$RD/escape.body" | tx_hash) || exit 4
  echo "round $ROUND body -> $RD/escape.body   txid: $TXID"
  if [ "$BUILD_ONLY" = 1 ]; then
    echo "build-only: the body above is ready to witness offline; it is kept, not cleaned up"
    [ "$LEFT" -gt 0 ] && echo "note: $LEFT further order UTxO(s) need their own rounds; run without --build-only to recover them all"
    exit 0
  fi

  # 3. sign OFFLINE with the client's key, assemble, submit. `transaction witness`
  # reads only the body and the key — no node, no network, no docker — so this
  # step can run on an air-gapped machine.
  $SIGN_CLI conway transaction witness --tx-body-file "$RD/escape.body" \
    --signing-key-file "$SKEY" $MAGIC --out-file "$RD/escape.witness" || exit 4
  $CLI conway transaction assemble --tx-body-file "$RD/escape.body" \
    --witness-file "$RD/escape.witness" --out-file "$RD/escape.signed" || exit 4
  # The signed transaction is the object the protocol limits, so it is measured
  # too — the body check above only reserved room for this witness set.
  read -r SIGNEDBYTES _ _ < <(measure_tx "$RD/escape.signed" --tx-file) || exit 4
  [ "$SIGNEDBYTES" -le "$MAX_TX_BYTES" ] || {
    echo "REFUSING: witnessed this round to $SIGNEDBYTES bytes, over the ${MAX_TX_BYTES}-byte limit." >&2
    echo "  Nothing was submitted. Re-run with --max-orders-per-tx $(( K > 1 ? K / 2 : 1 ))." >&2
    exit 3; }
  $CLI conway transaction submit $MAGIC --tx-file "$RD/escape.signed" || { echo "SUBMIT FAILED" >&2; exit 4; }
  echo "round $ROUND SUBMITTED -> $TXID  ($(cat "$RD/outval.txt") to $DEST)"

  # `transaction submit` returning 0 means one node took it into ITS mempool. The
  # header invites the client to point --cardano-cli at any relay they choose, on
  # the grounds that a hostile node can at most refuse service — which is only
  # true if acceptance is never mistaken for inclusion. So the LAST round is
  # confirmed like every other one before anything claims completion.
  if [ "$LEFT" -gt 0 ]; then
    echo "  waiting for round $ROUND to land before funding round $((ROUND + 1))..."
  else
    echo "  waiting for round $ROUND to land before calling this done..."
  fi
  WAITED=0
  while :; do
    sleep "$CONFIRM_POLL_SECONDS"
    WAITED=$((WAITED + CONFIRM_POLL_SECONDS))
    $CLI query utxo --address "$ORDER_ADDR" $MAGIC --out-file "$WORK/order.after.json" || exit 4
    python3 -c "
import json,sys
after = json.load(open(sys.argv[1]))
spent = [r for r in open(sys.argv[2]).read().split() if r]
sys.exit(0 if not any(r in after for r in spent) else 9)" \
      "$WORK/order.after.json" "$RD/spends.txt" && break
    [ "$WAITED" -lt "$CONFIRM_TIMEOUT_SECONDS" ] || {
      echo "REFUSING: round $ROUND ($TXID) has not landed after ${WAITED}s." >&2
      echo "  A node accepting a transaction is not the chain including one, so this" >&2
      echo "  round may have been dropped rather than delayed — check $TXID on an" >&2
      echo "  explorer before assuming anything about it." >&2
      echo "  Earlier rounds that WERE confirmed are final and their value is at $DEST." >&2
      echo "  Re-run this tool to recover whatever is still resting." >&2
      exit 4; }
  done
  [ "$LEFT" -gt 0 ] || { echo "ESCAPE COMPLETE: $ROUND transaction(s) confirmed, $DEST holds the inventory"; exit 0; }
done
