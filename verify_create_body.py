#!/usr/bin/env python3
# maker_stake_bound CREATE-BODY VERIFIER — a bound MMaaS client refuses to witness an operator-built
# funding transaction unless every lovelace and token it moves lands either at the ceremony's own
# order address or back in the client's own wallet.
#
# A create is UNCONSTRAINED on chain: no validator runs when the inventory is first seeded, so the
# operator builds the body and the client's signature is the only thing standing between the client's
# funding wallet and an operator output. `escape.sh` proves the client can always get inventory OUT
# with their key alone; this is its sibling for getting inventory IN — it decodes the unsigned body
# the operator emitted and, exactly like escape.sh rebuilds-and-hash-verifies every script it
# attaches, it RE-DERIVES the order address from the client's own ceremony parameters (never trusting
# an address the operator supplies) and refuses the body unless ALL of these hold:
#
#   1. exactly ONE output pays the re-derived order address, carrying an inline two-way SwapDatum that
#      names the ceremony's beacon_id and prices BOTH legs at or above the ceremony floors (the same
#      per-leg check maker_stake_bound.is_spendable_continuation_datum enforces on every reprice — an
#      out-of-band seed below a floor rests as a free round-trip the first reprice cannot fix);
#   2. every OTHER output — and any collateral-return output — is change to the client's own funding
#      address; NO output pays any other address;
#   3. the transaction mints EXACTLY the three pair beacons the order datum names (pair, asset1,
#      asset2), each once, under beacon_id and nothing else; and
#   4. the fee does not exceed --max-fee-lovelace (a body with no change and a wallet-sized fee burns
#      the client's funds to the protocol just as surely as an operator output steals them).
#
# WITNESSING IS GATED ON THIS. With --witness the tool runs the verification FIRST and only calls
# `cardano-cli conway transaction witness` if every check passes; a refused body yields NO witness, so
# the documented happy path cannot blind-sign. The order address is re-derived by the same
# verify_ceremony.py the client already trusts (--derive-only), so this tool trusts nothing new.
#
# Usage:
#   verify_create_body.py --body body.tx --params params.json --fund-addr <your wallet> \
#       --network testnet [--project <maker_stake dir>] [--aiken ~/.aiken/bin/aiken] \
#       [--max-fee-lovelace 5000000] [--json-out FILE]
#   # verify AND witness offline in one gated step (no witness is produced unless it PASSES):
#   verify_create_body.py --body body.tx --params params.json --fund-addr <your wallet> \
#       --network testnet --witness your.skey --out-file client.witness [--testnet-magic 1] \
#       [--sign-cli cardano-cli]
import argparse
import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import verify_ceremony as vc  # noqa: E402  reuse the ceremony derivation + datum semantics the client already trusts


class Refusal(Exception):
    pass


# ---------------------------------------------------------------------------
# A minimal CBOR reader — enough for a Conway transaction body and the Plutus
# Data an inline datum wraps. Hand-rolled for the same reason escape.sh hashes
# its own scripts: the client's funding safety must not depend on a decoder the
# operator could influence, only on python3.
# ---------------------------------------------------------------------------

class _Tag:
    __slots__ = ("tag", "value")

    def __init__(self, tag, value):
        self.tag = tag
        self.value = value


class _Cbor:
    def __init__(self, buf):
        self.b = buf
        self.i = 0

    def _u(self, n):
        v = int.from_bytes(self.b[self.i:self.i + n], "big")
        self.i += n
        return v

    def _head(self):
        first = self.b[self.i]
        self.i += 1
        major, info = first >> 5, first & 0x1F
        if info < 24:
            return major, info, False
        if info == 24:
            return major, self._u(1), False
        if info == 25:
            return major, self._u(2), False
        if info == 26:
            return major, self._u(4), False
        if info == 27:
            return major, self._u(8), False
        if info == 31:
            return major, None, True  # indefinite
        raise Refusal(f"unsupported CBOR additional-info {info}")

    def read(self):
        major, arg, indefinite = self._head()
        if major == 0:
            return arg
        if major == 1:
            return -1 - arg
        if major == 2:
            if indefinite:
                chunks = bytearray()
                while not self._at_break():
                    chunks += self.read()
                return bytes(chunks)
            raw = self.b[self.i:self.i + arg]
            self.i += arg
            return bytes(raw)
        if major == 3:
            if indefinite:
                parts = []
                while not self._at_break():
                    parts.append(self.read())
                return "".join(parts)
            raw = self.b[self.i:self.i + arg]
            self.i += arg
            return raw.decode("utf-8", "surrogatepass")
        if major == 4:
            items = []
            if indefinite:
                while not self._at_break():
                    items.append(self.read())
            else:
                for _ in range(arg):
                    items.append(self.read())
            return items
        if major == 5:
            out = {}
            if indefinite:
                while not self._at_break():
                    k = _hashable(self.read())
                    if k in out:
                        raise Refusal("duplicate CBOR map key — cardano-node rejects these, so refuse "
                                      "rather than silently pick one value the node would not")
                    out[k] = self.read()
            else:
                for _ in range(arg):
                    k = _hashable(self.read())
                    if k in out:
                        raise Refusal("duplicate CBOR map key — cardano-node rejects these, so refuse "
                                      "rather than silently pick one value the node would not")
                    out[k] = self.read()
            return out
        if major == 6:
            return _Tag(arg, self.read())
        if major == 7:
            if arg == 20:
                return False
            if arg == 21:
                return True
            if arg in (22, 23):
                return None
            raise Refusal(f"unsupported CBOR simple/float value {arg}")
        raise Refusal(f"unsupported CBOR major type {major}")

    def _at_break(self):
        if self.b[self.i] == 0xFF:
            self.i += 1
            return True
        return False


def _hashable(key):
    """CBOR map keys are rarely composite, but Conway's redeemers map is keyed by [tag, index]
    arrays. This verifier only ever looks up int and byte-string keys; composite keys just need a
    hashable stand-in so decoding does not abort."""
    if isinstance(key, list):
        return tuple(_hashable(k) for k in key)
    if isinstance(key, _Tag):
        return ("__tag__", key.tag, _hashable(key.value))
    if isinstance(key, dict):
        return tuple(sorted((repr(k), _hashable(v)) for k, v in key.items()))
    return key


def cbor_load(buf):
    return _Cbor(buf).read()


# ---------------------------------------------------------------------------
# Decoded Plutus Data (CBOR) -> the detailed-JSON shape verify_ceremony.py's
# swap_datum_problems already speaks, so the twelve-field SwapDatum decode is
# the one the tool pins against a live preprod order, not a second copy.
# ---------------------------------------------------------------------------

def plutus_to_detailed(node):
    if isinstance(node, _Tag):
        tag = node.tag
        if 121 <= tag <= 127:
            return {"constructor": tag - 121, "fields": [plutus_to_detailed(f) for f in _as_fields(node.value)]}
        if 1280 <= tag <= 1400:
            return {"constructor": tag - 1280 + 7, "fields": [plutus_to_detailed(f) for f in _as_fields(node.value)]}
        if tag == 102:
            fields = node.value
            if not isinstance(fields, list) or len(fields) != 2 or not isinstance(fields[0], int):
                raise Refusal("malformed general-form constructor in the inline datum")
            return {"constructor": fields[0], "fields": [plutus_to_detailed(f) for f in _as_fields(fields[1])]}
        raise Refusal(f"inline datum carries unexpected CBOR tag {tag}")
    if isinstance(node, bool):
        raise Refusal("inline datum carries a boolean, which Plutus Data has no form for")
    if isinstance(node, int):
        return {"int": node}
    if isinstance(node, bytes):
        return {"bytes": node.hex()}
    if isinstance(node, list):
        return {"list": [plutus_to_detailed(x) for x in node]}
    if isinstance(node, dict):
        return {"map": [{"k": plutus_to_detailed(k), "v": plutus_to_detailed(v)} for k, v in node.items()]}
    raise Refusal("inline datum contains a value with no Plutus Data form")


def _as_fields(value):
    if not isinstance(value, list):
        raise Refusal("a constructor's fields are not an array")
    return value


# ---------------------------------------------------------------------------
# The validator's own per-leg floor test, cross-multiplied for positive
# rationals exactly as maker_stake_bound.rational_geq does it.
# ---------------------------------------------------------------------------

def rational_geq(price, floor):
    return price[0] * floor[1] >= floor[0] * price[1]


# ---------------------------------------------------------------------------
# Re-derive the ceremony truth locally. The order address, beacon_id and both
# floors come from the client's own parameters through verify_ceremony.py, never
# from the operator or the body under audit.
# ---------------------------------------------------------------------------

def derive_ceremony(params, network, project, aiken, workdir):
    artefact = os.path.join(workdir, "artefact.json")
    proc = subprocess.run(
        [sys.executable, os.path.join(project, "verify_ceremony.py"),
         "--params", params, "--network", network, "--project", project,
         "--aiken", aiken, "--derive-only", "--decimals", "0", "--json-out", artefact],
        capture_output=True, text=True)
    if proc.returncode != 0 or not os.path.exists(artefact):
        raise Refusal(f"verify_ceremony.py could not derive the ceremony from {params}:\n{proc.stderr.strip()}")
    doc = json.load(open(artefact))
    ap = {p["name"]: p["value"] for p in doc["applied_parameters"]}
    a1 = vc._rational_pair(ap["min_asset1_price"])
    a2 = vc._rational_pair(ap["min_asset2_price"])
    if a1 is None or a2 is None:
        raise Refusal("the derived ceremony floors are not rationals")
    return {
        "order_address": doc["derived"]["order_address"],
        "beacon_id": ap["beacon_id"],
        "min_asset1_price": a1,
        "min_asset2_price": a2,
    }


# ---------------------------------------------------------------------------
# Body decoding
# ---------------------------------------------------------------------------

def load_body(path):
    doc = json.load(open(path))
    cbor_hex = doc.get("cborHex") if isinstance(doc, dict) else None
    if not isinstance(cbor_hex, str):
        raise Refusal(f"{path} is not a cardano-cli transaction envelope (no cborHex)")
    top = cbor_load(bytes.fromhex(cbor_hex))
    if isinstance(top, list) and top and isinstance(top[0], dict):
        return top[0]
    if isinstance(top, dict):
        return top
    raise Refusal(f"{path} does not decode to a transaction body")


def parse_value(amount):
    """(lovelace, {policy_hex: {name_hex: qty}}) from a CBOR value."""
    if isinstance(amount, int):
        return amount, {}
    if isinstance(amount, list) and len(amount) == 2 and isinstance(amount[0], int):
        assets = {}
        for pol, inner in amount[1].items():
            assets[pol.hex()] = {name.hex(): qty for name, qty in inner.items()}
        return amount[0], assets
    raise Refusal("an output value is neither a coin nor a [coin, multiasset] pair")


def parse_output(out):
    """(address_bytes, lovelace, assets, inline_datum_node_or_None). inline_datum_node is the
    DECODED Plutus Data, or None when the output has no inline datum."""
    if isinstance(out, dict):
        addr = out.get(0)
        lovelace, assets = parse_value(out.get(1))
        inline = None
        d = out.get(2)
        if isinstance(d, list) and len(d) == 2 and d[0] == 1:
            wrapped = d[1]
            if isinstance(wrapped, _Tag) and wrapped.tag == 24 and isinstance(wrapped.value, bytes):
                inline = cbor_load(wrapped.value)
        return addr, lovelace, assets, inline
    if isinstance(out, list) and len(out) in (2, 3):
        lovelace, assets = parse_value(out[1])
        return out[0], lovelace, assets, None  # legacy outputs cannot carry an inline datum
    raise Refusal("a transaction output has an unrecognised shape")


def parse_mint(mint):
    if mint is None:
        return {}
    out = {}
    for pol, inner in mint.items():
        out[pol.hex()] = {name.hex(): qty for name, qty in inner.items()}
    return out


# ---------------------------------------------------------------------------
# The verification itself. Returns (refusals, assertions). An empty refusals
# list means the body is safe to witness.
# ---------------------------------------------------------------------------

def verify_body(body, ceremony, fund_bech32, max_fee):
    refusals = []
    order_raw = vc.bech32_decode(ceremony["order_address"])[1]
    fund_raw = vc.bech32_decode(fund_bech32)[1]
    beacon_id = ceremony["beacon_id"]

    # A create's INPUTS reference off-body UTxOs, so this tool cannot balance inputs against outputs the
    # way the ledger does. Its guarantee — every lovelace lands at the order address, returns to you, or
    # is a capped fee / bounded collateral — therefore holds only if EVERY value sink is one it models.
    # Any Conway body field that consumes value without a modelled output (a treasury donation, a
    # certificate or governance deposit, a withdrawal) would escape it. Fail closed: refuse a body that
    # carries any field this verifier does not model, and refuse new ledger fields until it is extended.
    ALLOWED_BODY_KEYS = {0, 1, 2, 3, 7, 8, 9, 11, 13, 14, 15, 16, 17, 18}
    UNMODELLED = {4: "certificates", 5: "a withdrawal", 19: "voting procedures",
                  20: "a governance proposal", 21: "a current-treasury-value assertion",
                  22: "a treasury donation"}
    if any(type(key) is not int for key in body):
        raise Refusal("the transaction body has a non-integer field key, so it is not a well-formed "
                      "Conway body — refuse rather than guess what the node would make of it")
    for key in sorted(body):
        if key not in ALLOWED_BODY_KEYS:
            what = UNMODELLED.get(key, f"an unmodelled body field ({key})")
            refusals.append(
                f"the body carries {what} — a value sink this tool cannot bound against your inputs; "
                f"a create must carry none")

    outputs = body.get(1)
    if not isinstance(outputs, list) or not outputs:
        raise Refusal("the transaction body has no outputs")

    order_indexes = []
    for idx, out in enumerate(outputs):
        addr, lovelace, assets, inline = parse_output(out)
        if not isinstance(addr, (bytes, bytearray)):
            refusals.append(f"output {idx} has no decodable address")
            continue
        if bytes(addr) == order_raw:
            order_indexes.append((idx, out))
        elif bytes(addr) == fund_raw:
            continue  # change back to the client's own wallet
        else:
            refusals.append(
                f"output {idx} pays {addr.hex()} — neither the ceremony order address nor your "
                f"funding address; a create must pay only the order and change to you")

    coll_return = body.get(16)
    if coll_return is not None:
        caddr = parse_output(coll_return)[0]
        if not (isinstance(caddr, (bytes, bytearray)) and bytes(caddr) == fund_raw):
            refusals.append("the collateral-return output does not go back to your funding address")

    # Collateral inputs (13) are forfeited whole if the beacon mint's phase-2 script fails, so an
    # operator who supplies a large collateral UTxO with no return — or a bad mint redeemer this tool
    # cannot evaluate — can burn it. Bound the exposure: a body pledging collateral must return it to you
    # (16) and cap the amount at risk (17) at twice the fee cap; without both, the loss is unbounded.
    if body.get(13) is not None:
        coll_cap = 2 * max_fee
        total_coll = body.get(17)
        if coll_return is None:
            refusals.append(
                "the body pledges collateral but returns none to you; a failed script would forfeit all "
                "of it — refuse")
        if not isinstance(total_coll, int):
            refusals.append(
                "the body pledges collateral without a total-collateral field, so the amount at risk on a "
                "failed script is unbounded — refuse")
        elif total_coll > coll_cap:
            refusals.append(
                f"the total collateral {total_coll} lovelace exceeds the {coll_cap} cap (2x the fee cap); "
                f"a failed script would burn it — refuse")

    fee = body.get(2)
    if not isinstance(fee, int) or fee < 0:
        refusals.append("the transaction body has no readable fee")
    elif fee > max_fee:
        refusals.append(
            f"the fee is {fee} lovelace, above the {max_fee} cap — a body with a wallet-sized fee "
            f"burns your funds to the protocol; pass --max-fee-lovelace to raise the cap if intended")

    assertions = {
        "orderAddress": ceremony["order_address"],
        "beaconId": beacon_id,
        "minAsset1Price": f"{ceremony['min_asset1_price'][0]}/{ceremony['min_asset1_price'][1]}",
        "minAsset2Price": f"{ceremony['min_asset2_price'][0]}/{ceremony['min_asset2_price'][1]}",
        "fundingAddress": fund_bech32,
        "fee": fee if isinstance(fee, int) else None,
    }

    if len(order_indexes) != 1:
        refusals.append(
            f"the body pays the order address {len(order_indexes)} times; a create seeds exactly one order")
        return refusals, assertions

    _, out = order_indexes[0]
    _, order_lovelace, order_assets, inline = parse_output(out)
    assertions["orderLovelace"] = order_lovelace

    if inline is None:
        refusals.append("the order output carries no inline datum, so it is an unspendable deposit, not an order")
        return refusals, assertions

    try:
        detailed = plutus_to_detailed(inline)
    except Refusal as exc:
        refusals.append(f"the order output's inline datum does not decode as Plutus Data: {exc}")
        return refusals, assertions

    problems = vc.swap_datum_problems(detailed, beacon_id, order_assets)
    refusals.extend(f"order datum: {p}" for p in problems)
    if problems:
        return refusals, assertions

    fields = detailed["fields"]
    a1 = vc._pd_rational(fields[8])
    a2 = vc._pd_rational(fields[9])
    assertions["asset1Price"] = f"{a1[0]}/{a1[1]}"
    assertions["asset2Price"] = f"{a2[0]}/{a2[1]}"
    if not rational_geq(a2, ceremony["min_asset2_price"]):
        refusals.append(
            f"order datum: asset2_price (ask) {a2[0]}/{a2[1]} is below the ceremony floor "
            f"{ceremony['min_asset2_price'][0]}/{ceremony['min_asset2_price'][1]} — the seed would rest "
            f"as a free round-trip the first reprice cannot lift")
    if not rational_geq(a1, ceremony["min_asset1_price"]):
        refusals.append(
            f"order datum: asset1_price (bid) {a1[0]}/{a1[1]} is below the ceremony floor "
            f"{ceremony['min_asset1_price'][0]}/{ceremony['min_asset1_price'][1]} — the seed would rest "
            f"as a free round-trip the first reprice cannot lift")

    # The three pair beacons the datum names: pair (field 1), asset1 (field 4), asset2 (field 7).
    expected_beacons = {fields[1]["bytes"], fields[4]["bytes"], fields[7]["bytes"]}
    assertions["beacons"] = sorted(expected_beacons)
    held = order_assets.get(beacon_id, {})
    if {n: q for n, q in held.items()} != {n: 1 for n in expected_beacons}:
        refusals.append(
            f"the order output does not hold exactly the three pair beacons its datum names under "
            f"{beacon_id}; it holds {held}")

    mint = parse_mint(body.get(9))
    if set(mint) != {beacon_id} or mint.get(beacon_id) != {n: 1 for n in expected_beacons}:
        refusals.append(
            f"the mint is not exactly the three pair beacons under {beacon_id}; it mints {mint}")

    return refusals, assertions


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def run(args):
    workdir = tempfile.mkdtemp(prefix="mmaas-create-verify-")
    ceremony = derive_ceremony(args.params, args.network, args.project, args.aiken, workdir)
    body = load_body(args.body)
    refusals, assertions = verify_body(body, ceremony, args.fund_addr, args.max_fee_lovelace)
    return refusals, assertions


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="verify_create_body.py",
        description="Verify an operator-built MMaaS create transaction body before witnessing it.")
    parser.add_argument("--body", required=True, help="the unsigned body.tx the operator emitted")
    parser.add_argument("--params", required=True, help="your seven-field ceremony parameters file")
    parser.add_argument("--fund-addr", required=True, help="YOUR funding wallet — the only address change may return to")
    parser.add_argument("--network", required=True, choices=sorted(vc.NETWORKS))
    parser.add_argument("--project", default=os.path.dirname(os.path.abspath(__file__)),
                        help="the maker_stake aiken project directory")
    parser.add_argument("--aiken", default=os.environ.get("AIKEN") or "aiken")
    parser.add_argument("--max-fee-lovelace", type=int, default=5_000_000,
                        help="refuse a body whose fee exceeds this (default 5 ADA)")
    parser.add_argument("--json-out", help="also write the machine-readable result here")
    parser.add_argument("--witness", metavar="SKEY",
                        help="on PASS, witness the body offline with this signing key (gated: a refused "
                             "body yields no witness)")
    parser.add_argument("--out-file", help="where to write the witness with --witness")
    parser.add_argument("--sign-cli", default="cardano-cli", help="cardano-cli invocation for --witness")
    parser.add_argument("--testnet-magic", type=int, default=1)
    args = parser.parse_args(argv)

    if args.witness and not args.out_file:
        parser.error("--witness needs --out-file to write the witness to")

    try:
        refusals, assertions = run(args)
    except (Refusal, vc.CeremonyError) as exc:
        print(f"REFUSING TO VERIFY: {exc}", file=sys.stderr)
        return 3

    result = {"ok": not refusals, "refusals": refusals, "expected": assertions}
    if args.json_out:
        json.dump(result, open(args.json_out, "w"), indent=2)

    if refusals:
        print("REFUSED — do NOT witness this body:", file=sys.stderr)
        for r in refusals:
            print(f"  - {r}", file=sys.stderr)
        return 3

    print("VERIFIED — the body pays only your order address and change to you.")
    print(f"  order address : {assertions['orderAddress']}")
    print(f"  beacon policy : {assertions['beaconId']}")
    print(f"  ask asset2_price {assertions.get('asset2Price')} >= floor {assertions['minAsset2Price']}")
    print(f"  bid asset1_price {assertions.get('asset1Price')} >= floor {assertions['minAsset1Price']}")
    print(f"  fee           : {assertions['fee']} lovelace")

    if args.witness:
        net = ["--mainnet"] if args.network == "mainnet" else ["--testnet-magic", str(args.testnet_magic)]
        try:
            proc = subprocess.run(
                args.sign_cli.split() + ["conway", "transaction", "witness", "--tx-body-file", args.body,
                                         "--signing-key-file", args.witness, "--out-file", args.out_file] + net,
                capture_output=True, text=True)
        except OSError as exc:
            print(f"witness step failed: could not run '{args.sign_cli}': {exc}", file=sys.stderr)
            return 4
        if proc.returncode != 0:
            print(f"witness step failed: {proc.stderr.strip()}", file=sys.stderr)
            return 4
        print(f"WITNESSED -> {args.out_file} (verification passed first)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
