#!/bin/bash
# MMaaS Phase-0 fee channel, CLIENT side (FEE_COLLECTION_DESIGN.md, "Phase 0 draw — D"): a prepaid
# native-script channel the client funds and the operator's keeper draws metered fees from. What
# production ships is `any[ all[opA, opB], client ]` — the operator branch needs TWO independently
# held keys — and the legacy `any[opA, client]` remains for a one-key operator.
#
# What this tool PROVES: the channel you fund is derived LOCALLY from the operator's published key
# hashes and yours, in the CANONICAL ordering — operator key(s) FIRST, client key LAST. That
# ordering is a cross-repo contract; the backend keeper derives the identical script, and
# reordering the keys changes the hash and the address. The channel address is ALWAYS re-derived
# from those keys and never accepted as an input, so nobody can hand you a lookalike address only
# they control.
#
# What this tool CANNOT prove: a fee bound. No native script can express one. Under the 2-of-2, a
# compromise of ONE operator key or host draws nothing — the second key lives on separate
# infrastructure behind a service that judges each draw against a published destination, per-draw
# ceiling and rolling window (GET /identity states them, and codeDigest says what code answers). A
# deliberate operator using both keys can still draw the balance, so the metered fee remains a
# commercial promise rather than a ledger rule: fund only what you are prepared to see drawn. Your
# hard guarantees are (1) exposure is capped at the balance you chose and (2) --mode reclaim
# returns every channel UTxO to you with your key alone, zero operator cooperation.
#
# What you must obtain YOURSELF: the operator's fee vkh over a channel you trust — verify it
# out-of-band before funding, because funding a channel built on a stranger's vkh lets that
# stranger drain it — and a node you trust behind --cardano-cli. A hostile node can refuse
# service, never redirect: the address is derived locally and every output is explicit. --sign-cli
# may be a standalone, air-gapped binary — `transaction witness` reads only the body and the key.
# Before witnessing, the sign cli views the body and the tool refuses one whose outputs pay past
# the expected destination and change addresses; if the view is unavailable (no view command, or
# an unrecognized view schema) the tool REFUSES by default, and FEE_CHANNEL_REQUIRE_VIEW=0
# proceeds unverified. The view is produced and parsed on the ONLINE host, so it catches mistakes
# and is a weak tamper tripwire — NOT a defence against a compromised online host; only the
# air-gapped signer's own inspection of the body is.
#
# Modes:
#   derive  (default)  write channel.json, print its script hash + enterprise channel address
#   fund               plain payment of --amount lovelace from your wallet to the derived address
#   reclaim            drain EVERY channel UTxO back to --dest, largest first, at most 40 UTxOs
#                      per tx (a dust-griefed channel cannot outgrow maxTxSize), your witness only
#
# Usage:
#   fee_channel.sh [--mode derive] --operator-fee-vkh <56hex> [--operator-fee-vkh-b <56hex>] \
#                  (--my-vkh <56hex> | --my-vkey-file <payment.vkey>) \
#                  [--network mainnet|preprod] [--out-dir DIR] [--cardano-cli "cardano-cli"]
#
# Give BOTH operator keys and the channel is any[all[opA,opB],client]: the operator needs
# two independently-held keys to draw, so one stolen operator key spends nothing. Give one
# and it is the legacy any[opA,client]. Use whichever your operator published — the shape
# IS the address, so the wrong one funds a channel they cannot draw from.
#   fee_channel.sh --mode fund    <derive args> --amount <lovelace> --fund-addr <your wallet> \
#                  --signing-key <your.skey> [--sign-cli "cardano-cli"] [--testnet-magic 1]
#   fee_channel.sh --mode reclaim <derive args> --dest <addr> --signing-key <your.skey>
#     [--max-batches N]  Reclaim drains 40 channel UTxOs per transaction. The channel address is
#                        public and anyone can dust it, so an unbounded drain can cost you a fee per
#                        batch to recover your own float. N stops after N batches and reports what
#                        is left; every batch already submitted keeps its reclaim, and re-running
#                        resumes. Exit 5 means "stopped at the cap", not "failed". Default 0 = drain
#                        until the channel is empty.
#
# derive without --out-dir keeps its temp dir (channel.json is the artefact); fund/reclaim without
# --out-dir clean up on exit. Exit codes: 2 usage, 3 refusal/mismatch, 4 chain-IO.
set -uo pipefail

# A key hash is exactly 56 lowercase hex chars; anything else is refused before a script exists.
# Args: label vkh.
validate_vkh(){
  case "$2" in
    ''|*[!0-9a-f]*) echo "REFUSING: $1 is not lowercase hex: [$2]" >&2; return 3;;
  esac
  [ ${#2} -eq 56 ] || { echo "REFUSING: $1 must be exactly 56 hex chars, got ${#2}: [$2]" >&2; return 3; }
}

# The CANONICAL channel script bytes: operator key FIRST, client key SECOND — the cross-repo
# contract the backend keeper derives against. Args: operator_vkh client_vkh out_path.
write_channel_script(){
  printf '{"type":"any","scripts":[{"type":"sig","keyHash":"%s"},{"type":"sig","keyHash":"%s"}]}\n' "$1" "$2" > "$3"
}

# Option C channel bytes: any[ all[opA, opB], client ]. The OPERATOR branch is 2-of-2 across
# independent infrastructure, so one stolen operator key signs nothing; the CLIENT branch stays a
# single key, because our key hygiene must never make your unilateral reclaim harder. Order is part
# of the hash: opA, opB, then you. Args: opA opB client out_path.
write_channel_script_2of2(){
  printf '{"type":"any","scripts":[{"type":"all","scripts":[{"type":"sig","keyHash":"%s"},{"type":"sig","keyHash":"%s"}]},{"type":"sig","keyHash":"%s"}]}\n' "$1" "$2" "$3" > "$4"
}

# As derive_channel, for the 2-of-2 operator branch. Refuses key collisions before a script exists:
# two equal operator keys are a 2-of-2 that one stolen key satisfies, and an operator key equal to
# yours collapses the branches. Sets CHANNEL_HASH and CHANNEL_ADDR.
# Args: cli opA opB client network_flags work.
derive_channel_2of2(){
  local cli=$1 opa=$2 opb=$3 client=$4 magic=$5 work=$6
  validate_vkh "operator fee vkh A" "$opa" || return 3
  validate_vkh "operator fee vkh B" "$opb" || return 3
  validate_vkh "client vkh" "$client" || return 3
  [ "$opa" != "$opb" ] || { echo "REFUSING: the two operator fee keys are identical — that is a 2-of-2 one stolen key satisfies" >&2; return 3; }
  [ "$opa" != "$client" ] && [ "$opb" != "$client" ] || { echo "REFUSING: an operator fee key equals the client key — the channel's branches stop being independent" >&2; return 3; }
  write_channel_script_2of2 "$opa" "$opb" "$client" "$work/channel.json"
  CHANNEL_HASH=$($cli conway transaction policyid --script-file "$work/channel.json") || return 4
  CHANNEL_ADDR=$($cli address build --payment-script-file "$work/channel.json" $magic) || return 4
  echo "channel script:  $work/channel.json"
  echo "channel hash:    $CHANNEL_HASH"
  echo "channel address: $CHANNEL_ADDR"
}

# Validate both keys, write WORK/channel.json, and derive its hash + enterprise address for the
# network — the address is computed here every run, never taken as input. Sets CHANNEL_HASH and
# CHANNEL_ADDR. Args: cli operator_vkh client_vkh network_flags work.
derive_channel(){
  local cli=$1 operator=$2 client=$3 magic=$4 work=$5
  validate_vkh "operator fee vkh" "$operator" || return 3
  validate_vkh "client vkh" "$client" || return 3
  write_channel_script "$operator" "$client" "$work/channel.json"
  CHANNEL_HASH=$($cli conway transaction policyid --script-file "$work/channel.json") || return 4
  CHANNEL_ADDR=$($cli address build --payment-script-file "$work/channel.json" $magic) || return 4
  echo "channel script:  $work/channel.json"
  echo "channel hash:    $CHANNEL_HASH"
  echo "channel address: $CHANNEL_ADDR"
}

# The pre-witness gate: BEFORE any key touches a body, the SIGN cli decodes it and every output
# must pay an expected address — anything else is refused unsigned, as is a body with no outputs
# at all (everything would burn as fee). An unavailable view — a cli without a view command, or a
# view schema the parser does not recognize — is itself a refusal (exit 3) unless
# FEE_CHANNEL_REQUIRE_VIEW=0 downgrades it to a loud warning naming the skipped check.
# Args: sign_cli body allowed_addr...
verify_body_outputs(){
  local cli=$1 body=$2; shift 2
  if ! $cli debug transaction view --tx-file "$body" > "$body.view" 2>/dev/null &&
     ! $cli transaction view --tx-file "$body" > "$body.view" 2>/dev/null; then
    if [ "${FEE_CHANNEL_REQUIRE_VIEW:-1}" != 0 ]; then
      echo "REFUSING: pre-witness output check unavailable (set FEE_CHANNEL_REQUIRE_VIEW=0 to proceed unverified)" >&2
      return 3
    fi
    echo "WARNING: the sign cli cannot view a transaction; SKIPPING the pre-witness output-address check" >&2
    return 0
  fi
  python3 - "$body.view" "$@" <<'PY'
import json, os, sys
try:
    outs = [(o["address"], o["amount"]["lovelace"]) for o in json.load(open(sys.argv[1]))["outputs"]]
except (ValueError, KeyError, TypeError) as e:
    if os.environ.get("FEE_CHANNEL_REQUIRE_VIEW", "1") != "0":
        sys.stderr.write("REFUSING: pre-witness output check unavailable "
                         "(set FEE_CHANNEL_REQUIRE_VIEW=0 to proceed unverified)\n")
        sys.exit(3)
    sys.stderr.write(f"WARNING: unrecognized transaction view output ({e}); "
                     "SKIPPING the pre-witness output-address check\n")
    sys.exit(0)
for addr, lovelace in outs:
    print(f"  body output: {addr}  {lovelace} lovelace")
if not outs:
    sys.stderr.write("REFUSING: the body has no outputs at all — the whole spend would burn as fee\n")
    sys.exit(3)
bad = [a for a, _ in outs if a not in set(sys.argv[2:])]
if bad:
    sys.stderr.write("REFUSING: the body pays outside " + " / ".join(sys.argv[2:]) + ": " + " ".join(bad) + "\n")
    sys.exit(3)
print(f"verified: all {len(outs)} body output(s) pay the expected addresses")
PY
}

# cardano-cli >= 10.16 prints the txid as JSON where older versions printed bare hex; both reduce
# to the same 64-hex hash. Anything else is refused rather than echoed as if it were a tx id.
bare_txid(){
  local raw="$1" hash
  hash=$(printf '%s' "$raw" | tr -d ' \n\r\t"{}' | sed 's/.*txhash://; s/.*txId://')
  case "$hash" in
    *[!0-9a-f]* | "") echo "REFUSING: cardano-cli txid output is not a 64-hex hash: $raw" >&2; return 4;;
  esac
  [ ${#hash} -eq 64 ] || { echo "REFUSING: cardano-cli txid output is not a 64-hex hash: $raw" >&2; return 4; }
  printf '%s' "$hash"
}

# sourced by fee_channel.test.sh = definitions only; executed = run the requested mode
(return 0 2>/dev/null) && return 0

CLI="cardano-cli"; SIGN_CLI=""; MODE=derive; NETWORK=preprod; MAGIC_N=1
OP_VKH=""; OP_VKH_B=""; MY_VKH=""; MY_VKEY=""; AMOUNT=""; FUND=""; DEST=""; SKEY=""; OUTDIR=""
MAX_BATCHES=0   # 0 = drain until empty
while [ $# -gt 0 ]; do
  case "$1" in
    --mode) MODE="$2"; shift 2;;
    --operator-fee-vkh) OP_VKH="$2"; shift 2;;
    --operator-fee-vkh-b) OP_VKH_B="$2"; shift 2;;
    --my-vkh) MY_VKH="$2"; shift 2;;
    --my-vkey-file) MY_VKEY="$2"; shift 2;;
    --network) NETWORK="$2"; shift 2;;
    --amount) AMOUNT="$2"; shift 2;;
    --fund-addr) FUND="$2"; shift 2;;
    --dest) DEST="$2"; shift 2;;
    --signing-key) SKEY="$2"; shift 2;;
    --cardano-cli) CLI="$2"; shift 2;;
    --sign-cli) SIGN_CLI="$2"; shift 2;;
    --testnet-magic) MAGIC_N="$2"; shift 2;;
    --out-dir) OUTDIR="$2"; shift 2;;
    --max-batches) MAX_BATCHES="${2:-}"; shift 2;;
    *) echo "unknown argument: $1" >&2; exit 2;;
  esac
done
: "${SIGN_CLI:=$CLI}"
case "$MODE" in
  derive|fund|reclaim) ;;
  *) echo "unknown --mode: $MODE (derive|fund|reclaim)" >&2; exit 2;;
esac
case "$NETWORK" in
  mainnet) MAGIC="--mainnet";;
  preprod) MAGIC="--testnet-magic $MAGIC_N";;
  *) echo "unknown --network: $NETWORK (mainnet|preprod)" >&2; exit 2;;
esac
[ -n "$OP_VKH" ] || { echo "missing required --operator-fee-vkh (see header)" >&2; exit 2; }
[ -n "$MY_VKH" ] || [ -n "$MY_VKEY" ] || { echo "missing required --my-vkh or --my-vkey-file (see header)" >&2; exit 2; }
[ -n "$MY_VKH" ] && [ -n "$MY_VKEY" ] && { echo "pass --my-vkh or --my-vkey-file, not both" >&2; exit 2; }
case "$MODE" in
  fund)
    case "$AMOUNT" in ''|*[!0-9]*) echo "--amount must be a whole number of lovelace" >&2; exit 2;; esac
    [ "$AMOUNT" -gt 0 ] || { echo "--amount must be positive" >&2; exit 2; }
    [ -n "$FUND" ] || { echo "missing required --fund-addr (see header)" >&2; exit 2; }
    [ -n "$SKEY" ] || { echo "missing required --signing-key (see header)" >&2; exit 2; };;
  reclaim)
    [ -n "$DEST" ] || { echo "missing required --dest (see header)" >&2; exit 2; }
    [ -n "$SKEY" ] || { echo "missing required --signing-key (see header)" >&2; exit 2; }
    case "$MAX_BATCHES" in ''|*[!0-9]*) echo "--max-batches must be a whole number (0 = no cap)" >&2; exit 2;; esac;;
esac
WORK="${OUTDIR:-$(mktemp -d)}"; mkdir -p "$WORK"
[ -n "$OUTDIR" ] || [ "$MODE" = derive ] || trap 'rm -rf "$WORK"' EXIT

if [ -n "$MY_VKEY" ]; then
  MY_VKH=$($CLI address key-hash --payment-verification-key-file "$MY_VKEY") || exit 4
fi
# Two operator keys means the 2-of-2 channel any[all[opA,opB],client]; one means the
# legacy any[opA,client]. Dispatching here rather than at each call site is deliberate:
# the shape IS the address, and a tool that can derive both but always calls one sends
# a client's funds to an address the keeper cannot draw from.
if [ -n "$OP_VKH_B" ]; then
  derive_channel_2of2 "$CLI" "$OP_VKH" "$OP_VKH_B" "$MY_VKH" "$MAGIC" "$WORK" || exit $?
else
  derive_channel "$CLI" "$OP_VKH" "$MY_VKH" "$MAGIC" "$WORK" || exit $?
fi
CHANNEL="$WORK/channel.json"
[ "$MODE" = derive ] && exit 0

# Gate, witness, assemble, submit ONE body: the sign cli views the body and refuses unexpected
# outputs (exit 3), then witnesses OFFLINE with the client's key — `transaction witness` reads
# only the body and the key, so that step can run on an air-gapped machine — and the trusted node
# assembles and submits. Sets TXID. Args: body stem allowed_addr...
send_body(){
  local body=$1 stem=$2; shift 2
  verify_body_outputs "$SIGN_CLI" "$body" "$@" || exit 3
  TXID=$(bare_txid "$($SIGN_CLI conway transaction txid --tx-body-file "$body")") || exit 4
  echo "$stem txid: $TXID"
  $SIGN_CLI conway transaction witness --tx-body-file "$body" \
    --signing-key-file "$SKEY" $MAGIC --out-file "$WORK/$stem.witness" || exit 4
  $CLI conway transaction assemble --tx-body-file "$body" \
    --witness-file "$WORK/$stem.witness" --out-file "$WORK/$stem.signed" || exit 4
  $CLI conway transaction submit $MAGIC --tx-file "$WORK/$stem.signed" || { echo "SUBMIT FAILED" >&2; exit 4; }
}

if [ "$MODE" = fund ]; then
  $CLI query utxo --address "$FUND" $MAGIC --out-file "$WORK/fund.json" || exit 4
  FUND_INS=$(python3 - "$WORK/fund.json" "$AMOUNT" <<'PY'
import json, sys
u = json.load(open(sys.argv[1])); need = int(sys.argv[2]) + 5_000_000
avail = sorted([(k, v["value"].get("lovelace", 0)) for k, v in u.items()
                if v.get("referenceScript") in (None, {})], key=lambda x: -x[1])
picked, total = [], 0
for ref, lovelace in avail:
    picked.append(ref); total += lovelace
    if total >= need: break
if total < need:
    sys.stderr.write(f"funding address holds {total} lovelace, need {need} (amount + fee headroom)\n"); sys.exit(4)
print(" ".join(picked))
PY
) || exit 4
  BUILD_INS=""
  for ref in $FUND_INS; do BUILD_INS="$BUILD_INS --tx-in $ref"; done
  $CLI conway transaction build $MAGIC \
    $BUILD_INS \
    --tx-out "$CHANNEL_ADDR+$AMOUNT" \
    --change-address "$FUND" --out-file "$WORK/fund.body" || { echo "BUILD FAILED" >&2; exit 4; }
  send_body "$WORK/fund.body" fund "$CHANNEL_ADDR" "$FUND"
  echo "FUNDED $CHANNEL_ADDR with $AMOUNT lovelace -> $TXID"
else
  # A griefer can dust the public channel address with hundreds of tiny UTxOs to push one
  # spend-everything tx past maxTxSize, so reclaim drains in batches: largest UTxOs first, at most
  # 40 script inputs per tx, re-querying between batches. Inputs a submitted batch already spent
  # are excluded rather than awaited — the node chains mempool batches — and a failing batch
  # aborts (exit 4) with every earlier batch keeping its reclaim.
  SPENT=""; BATCH=0
  while :; do
    BATCH=$((BATCH+1))
    $CLI query utxo --address "$CHANNEL_ADDR" $MAGIC --out-file "$WORK/channel-utxos.json" || exit 4
    CHANNEL_INS=$(python3 - "$WORK/channel-utxos.json" "$BATCH" $SPENT <<'PY'
import json, sys
u = json.load(open(sys.argv[1])); batch = int(sys.argv[2]); spent = set(sys.argv[3:])
live = sorted(((k, v["value"].get("lovelace", 0)) for k, v in u.items() if k not in spent),
              key=lambda kv: -kv[1])
if not live:
    if batch == 1:
        sys.stderr.write("nothing to reclaim: the channel address holds no UTxOs\n"); sys.exit(4)
    sys.exit(0)
take = live[:40]
sys.stderr.write(f"batch {batch}: reclaiming {len(take)} of {len(live)} channel UTxO(s), "
                 f"{sum(l for _, l in take)} lovelace\n")
print(" ".join(k for k, _ in take))
PY
) || exit 4
    [ -n "$CHANNEL_INS" ] || break
    BUILD_INS=""
    for ref in $CHANNEL_INS; do BUILD_INS="$BUILD_INS --tx-in $ref --tx-in-script-file $CHANNEL"; done
    $CLI conway transaction build $MAGIC \
      $BUILD_INS \
      --required-signer-hash "$MY_VKH" \
      --change-address "$DEST" --out-file "$WORK/reclaim.$BATCH.body" || { echo "BUILD FAILED" >&2; exit 4; }
    send_body "$WORK/reclaim.$BATCH.body" "reclaim.$BATCH" "$DEST"
    SPENT="$SPENT $CHANNEL_INS"
    # Stop on a batch boundary, never mid-batch: everything reclaimed so far has already been
    # submitted, so a capped run is a partial success and re-running resumes from what is left.
    if [ "$MAX_BATCHES" -gt 0 ] && [ "$BATCH" -ge "$MAX_BATCHES" ]; then
      $CLI query utxo --address "$CHANNEL_ADDR" $MAGIC --out-file "$WORK/channel-utxos.json" || exit 4
      LEFT=$(python3 -c "
import json, sys
u = json.load(open(sys.argv[1]))
print(sum(1 for k in u if k not in set(sys.argv[2:])))" "$WORK/channel-utxos.json" $SPENT) || exit 4
      [ "$LEFT" -eq 0 ] && break
      echo "RECLAIMED $BATCH batch(es) to $DEST -> $TXID" >&2
      echo "STOPPED at --max-batches $MAX_BATCHES: $LEFT channel UTxO(s) remain. Re-run to continue." >&2
      exit 5
    fi
  done
  echo "RECLAIMED the channel to $DEST in $((BATCH-1)) batch(es) -> $TXID"
fi
