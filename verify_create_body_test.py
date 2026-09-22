#!/usr/bin/env python3
# Tests for verify_create_body.py, written from the CLIENT/ATTACKER side: every case asserts what a
# malicious operator's body must NOT be able to make the client witness.
#
# The fixture DERIVES everything from whatever the source currently compiles to — four ephemeral
# keypairs, a nine-parameter ceremony, and both anchor bodies built by the real cardano-cli. Nothing
# is committed and no key ever enters the repo.
#
# That is not convenience. The previous fixture read a params file and two .tx anchors captured
# against a SEVEN-parameter ceremony; when the fee bound moved on chain and the validator took nine,
# the params file was refused outright and the anchors' order address became underivable. The suite
# went red at setup and stayed there, because nothing ran it. A committed artefact derived from a
# parameter surface that moves without it is the bug, so the fixture derives instead.
#
# The beacon policy is a generated NATIVE sig script, which is what lets the bodies be built offline:
# a native mint needs no redeemer, no execution units and no protocol parameters. The cost is stated
# in full — see "what this fixture does not prove" at the bottom.
#
# Run: pytest maker_stake/verify_create_body_test.py   (or through verify_project.sh)
import hashlib
import json
import os
import shutil
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import verify_ceremony as vc  # noqa: E402
import verify_create_body as vcb  # noqa: E402

# The cardano-swaps two_way_swap.swap_script hash — the payment credential of every order address.
# Opaque to this verifier, which only needs it to differ from the beacon policy; kept real so the
# derived address stays legible against the deployed one.
DAPP_HASH = "11928a3ac3b65edbf103ea6bb3362e39b879a36f02897df31c40917b"

# Decorative inventory the order carries: any policy that is not the beacon policy.
TOK_POL = bytes.fromhex("0ff71ae2bdba25bb5e1805983c8e7924edfc77f808f4f8f6cc421ce4")
TOK_NAME = b"ADAMMKT"

# cardano-swaps names the two asset beacons by hashing the asset they stand for, so these are
# computed rather than pasted: asset1 is ADA (the empty asset), asset2 is the token.
A1B = hashlib.sha256(b"").digest()
A2B = hashlib.sha256(TOK_POL + TOK_NAME).digest()
# The pair beacon's name is opaque to verify_body — it only requires that the datum names it, the
# mint mints it and the output holds it — and is not derivable from the pair, so it stays literal.
PB = bytes.fromhex("2c973472600b564e14ae330f49bbacf6865006fc316263b1bc5329b5973828cd")

MIN_A1 = (1, 2600000)          # bid ceiling
MIN_A2 = (2700000, 1)          # ask floor; uncrossed against the bid
FEE_BPS = 100                  # inside the validator's 500 ceiling, and not tracking it


def _cardano_cli():
    cli = os.environ.get("CARDANO_CLI") or shutil.which("cardano-cli")
    if not cli:
        pytest.fail("cardano-cli is required: the fixture's value is that the bodies are genuine "
                    "CLI output. verify_project.sh installs it pinned by SHA256.")
    return cli


def _aiken():
    for cand in (os.environ.get("AIKEN"), os.path.expanduser("~/.aiken/bin/aiken"), shutil.which("aiken")):
        if cand and os.path.exists(cand):
            return cand
    pytest.fail("aiken is required to derive the ceremony; verify_project.sh installs it pinned.")


def _run(*args):
    p = subprocess.run(args, capture_output=True, text=True)
    if p.returncode != 0:
        raise AssertionError(f"{args[0]} failed ({p.returncode}): {p.stderr.strip()}")
    return p.stdout.strip()


class _Fixture:
    pass


def _keypair(cli, workdir, name):
    vkey = os.path.join(workdir, name + ".vkey")
    skey = os.path.join(workdir, name + ".skey")
    prev = os.umask(0o077)
    try:
        _run(cli, "address", "key-gen", "--verification-key-file", vkey, "--signing-key-file", skey)
    finally:
        os.umask(prev)
    return {
        "skey": skey,
        "vkh": _run(cli, "address", "key-hash", "--payment-verification-key-file", vkey),
        "addr": _run(cli, "address", "build", "--payment-verification-key-file", vkey,
                     "--testnet-magic", "1"),
    }


def _datum_json(beacon_hex, a1=MIN_A1, a2=MIN_A2):
    rat = lambda n, d: {"constructor": 0, "fields": [{"int": n}, {"int": d}]}
    none = {"constructor": 1, "fields": []}
    return {"constructor": 0, "fields": [
        {"bytes": beacon_hex}, {"bytes": PB.hex()}, {"bytes": ""}, {"bytes": ""},
        {"bytes": A1B.hex()}, {"bytes": TOK_POL.hex()}, {"bytes": TOK_NAME.hex()}, {"bytes": A2B.hex()},
        rat(*a1), rat(*a2), none, none]}


@pytest.fixture(scope="session")
def fx(tmp_path_factory):
    cli, aiken = _cardano_cli(), _aiken()
    w = str(tmp_path_factory.mktemp("createbody"))
    keys = {n: _keypair(cli, w, n) for n in ("client", "operator", "fee", "beacon")}

    # A native sig policy, so the mint carries no redeemer and build-raw needs no node.
    native = os.path.join(w, "beacon.native.json")
    with open(native, "w") as fh:
        json.dump({"type": "sig", "keyHash": keys["beacon"]["vkh"]}, fh)
    beacon_id = _run(cli, "conway", "transaction", "policyid", "--script-file", native)

    params_path = os.path.join(w, "params.json")
    with open(params_path, "w") as fh:
        json.dump({
            "adam_bot_pkh": keys["operator"]["vkh"],
            "client_owner_vkh": keys["client"]["vkh"],
            # Its payment credential must equal client_owner_vkh, which is why one key supplies both.
            "client_payout_address": keys["client"]["addr"],
            "dapp_hash": DAPP_HASH,
            "beacon_id": beacon_id,
            "min_asset1_price": {"numerator": MIN_A1[0], "denominator": MIN_A1[1]},
            "min_asset2_price": {"numerator": MIN_A2[0], "denominator": MIN_A2[1]},
            "fee_address": keys["fee"]["addr"],
            "fee_bps": FEE_BPS,
        }, fh)

    # Derive against a COPY of the project, not the repo. verify_ceremony.py refuses to derive from a
    # dirty tree, so deriving in place would redden all of these cases the moment anyone edits the
    # validator — i.e. exactly during the red step of a change to the thing under test.
    project = os.path.join(w, "project")
    os.makedirs(project, exist_ok=True)
    for item in ("aiken.toml", "aiken.lock", "plutus.json", "verify_ceremony.py"):
        shutil.copy(os.path.join(HERE, item), os.path.join(project, item))
    shutil.copytree(os.path.join(HERE, "validators"), os.path.join(project, "validators"))
    ceremony = vcb.derive_ceremony(params_path, "testnet", project, aiken, w)

    datum_path = os.path.join(w, "swapdatum.json")
    with open(datum_path, "w") as fh:
        json.dump(_datum_json(beacon_id), fh)

    beacons = " + ".join(f"1 {beacon_id}.{n.hex()}" for n in (PB, A1B, A2B))
    order_out = f"{ceremony['order_address']}+7000000+{beacons} + 4 {TOK_POL.hex()}.{TOK_NAME.hex()}"
    # build-raw balances nothing and resolves no input, so the txids and lovelace are free; they keep
    # the real preprod create's arithmetic so the shape stays comparable to it.
    common = [
        cli, "conway", "transaction", "build-raw",
        "--tx-in", "404e3b7f4e1571e8d74c6eedc19de1c42f3f13559b125a11cadee13b6bf62aea#0",
        "--tx-in-collateral", "449dc433aa41a35278245344acf56c0b0823c3a15b09f8ef64540e0788ea8376#4",
        "--tx-out", order_out, "--tx-out-inline-datum-file", datum_path,
    ]
    tail = ["--mint", beacons, "--mint-script-file", native,
            "--tx-out-return-collateral", f"{keys['client']['addr']}+5317006",
            "--tx-total-collateral", "682994"]

    honest = os.path.join(w, "create-body-honest.tx")
    _run(*common, "--tx-out", f"{keys['client']['addr']}+5703528", *tail,
         "--fee", "455329", "--out-file", honest)
    # The operator's variant: one extra output to themselves, taken out of the client's change.
    malicious = os.path.join(w, "create-body-malicious.tx")
    _run(*common, "--tx-out", f"{keys['operator']['addr']}+3000000",
         "--tx-out", f"{keys['client']['addr']}+2700554", *tail,
         "--fee", "458303", "--out-file", malicious)

    f = _Fixture()
    f.workdir, f.project, f.params, f.ceremony = w, project, params_path, ceremony
    f.honest, f.malicious = honest, malicious
    f.client_skey, f.fund = keys["client"]["skey"], keys["client"]["addr"]
    f.operator_raw = vc.bech32_decode(keys["operator"]["addr"])[1]
    f.order_raw = vc.bech32_decode(ceremony["order_address"])[1]
    f.beacon = bytes.fromhex(beacon_id)
    return f


# ----------------------------------------------------------------------------
# Body builders. Every one takes the fixture: the order address, the beacon policy and the funding
# address all move with the ceremony, and hardcoding any of them is what silently unhooked 18 of
# these cases from the validator they are supposed to judge.
# ----------------------------------------------------------------------------

def _head(major, n):
    if n < 24:
        return bytes([major << 5 | n])
    if n < 0x100:
        return bytes([major << 5 | 24, n])
    if n < 0x10000:
        return bytes([major << 5 | 25]) + n.to_bytes(2, "big")
    return bytes([major << 5 | 26]) + n.to_bytes(4, "big")


def _enc(v):
    if v is None:
        return b"\xf6"
    if isinstance(v, int):
        return _head(0, v) if v >= 0 else _head(1, -1 - v)
    if isinstance(v, bytes):
        return _head(2, len(v)) + v
    if isinstance(v, list):
        return _head(4, len(v)) + b"".join(_enc(x) for x in v)
    if isinstance(v, tuple):  # ("tag", n, value)
        return _head(6, v[1]) + _enc(v[2])
    raise TypeError(v)


def _datum(fx, beacon=None, a1=MIN_A1, a2=MIN_A2, asset1=(b"", b""), asset2=(TOK_POL, TOK_NAME),
           pair_beacon=PB, asset1_beacon=A1B, asset2_beacon=A2B, expiration=None):
    rat = lambda n, d: ("tag", 121, [n, d])
    none = ("tag", 122, [])
    # tag 121 is constructor 0 = Some; tag 122 is constructor 1 = None
    expiry = none if expiration is None else ("tag", 121, [expiration])
    fields = [beacon or fx.beacon, pair_beacon, asset1[0], asset1[1], asset1_beacon,
              asset2[0], asset2[1], asset2_beacon, rat(*a1), rat(*a2), none, expiry]
    return _enc(("tag", 121, fields))


def _inline(datum_cbor):
    return [1, vcb._Tag(24, datum_cbor)]


def _order_out(fx, datum_cbor=None, beacons=None, lovelace=7000000):
    beacons = beacons if beacons is not None else {PB: 1, A1B: 1, A2B: 1}
    val = [lovelace, {fx.beacon: dict(beacons), TOK_POL: {TOK_NAME: 4}}]
    out = {0: fx.order_raw, 1: val}
    if datum_cbor is not None:
        out[2] = _inline(datum_cbor)
    return out


def _change_out(fx, raw=None, lovelace=5000000):
    return {0: raw if raw is not None else vc.bech32_decode(fx.fund)[1], 1: [lovelace, {}]}


def _body(fx, outputs, mint=None, fee=455329, coll_return=None, total_collateral=682994, expect_pair=None):
    mint = mint if mint is not None else {fx.beacon: {PB: 1, A1B: 1, A2B: 1}}
    # A real create pledges collateral for the beacon mint's phase-2 script, so it carries collateral
    # inputs (13), a collateral return to the funder (16) and a bounded total_collateral (17). Model that
    # safe shape by default; the collateral-attack tests delete or inflate those fields.
    body = {0: [[bytes(32), 0]], 1: outputs, 2: fee, 9: mint, 13: [[bytes(32), 1]]}
    body[16] = coll_return if coll_return is not None else _change_out(fx)
    if total_collateral is not None:
        body[17] = total_collateral
    return body


DEFAULT_PAIR = (("", ""), (TOK_POL.hex(), TOK_NAME.hex()))


def _refusals(fx, body, max_fee=5_000_000, expect_pair=None):
    return vcb.verify_body(body, fx.ceremony, fx.fund, max_fee, expect_pair or DEFAULT_PAIR)[0]


def _only(refusals, *needles):
    """The body must be refused for exactly ONE reason, and it must be this one.

    `any(needle in r for r in refusals)` passes while the body is simultaneously refused for
    unrelated reasons — which is how the donation case stayed green against an anchor that was
    already being refused five other ways. Every negative case here produces exactly one refusal
    under a correct fixture, so the count is what makes the assertion discriminating.
    """
    assert len(refusals) == 1, f"expected exactly one refusal, got {len(refusals)}: {refusals}"
    for n in needles:
        assert n in refusals[0], f"{n!r} not in {refusals[0]!r}"


# ----------------------------------------------------------------------------
# Anchors on the generated bodies, through the actual CLI (the gate itself).
# ----------------------------------------------------------------------------

def _run_cli(fx, body_path, extra=()):
    return subprocess.run(
        [sys.executable, os.path.join(HERE, "verify_create_body.py"),
         "--body", body_path, "--params", fx.params, "--fund-addr", fx.fund,
         "--expect-pair", f".,{TOK_POL.hex()}.{TOK_NAME.hex()}",
         "--network", "testnet", "--aiken", _aiken(), "--project", fx.project, *extra],
        capture_output=True, text=True)


def test_a_seed_that_names_an_expiration_is_refused(fx):
    """A create is unconstrained on chain, so this gate is the last place it can be caught.

    The bound validator's continuation gate requires `sd.expiration == None` on every reprice, and
    the keeper's reprice carries the seed's datum forward — so a seed naming ANY expiration produces
    a book whose first reprice the validator refuses, and every one after it. The dApp goes on
    accepting fills against a quote nobody can move, until the expiry passes and it refuses those
    too. The client witnesses this body themselves; after that it is on chain and permanent.
    """
    body = _body(fx, [_order_out(fx, datum_cbor=_datum(fx, expiration=1_800_000_000))])
    refusals, _ = vcb.verify_body(body, fx.ceremony, fx.fund, 5_000_000, DEFAULT_PAIR)
    _only(refusals, "expiration is set", "expiration = None")


def test_a_seed_with_no_expiration_is_untouched_by_that_gate(fx):
    refusals, _ = vcb.verify_body(vcb.load_body(fx.honest), fx.ceremony, fx.fund, 5_000_000, DEFAULT_PAIR)
    assert refusals == []


def test_real_honest_body_verifies(fx):
    refusals, assertions = vcb.verify_body(vcb.load_body(fx.honest), fx.ceremony, fx.fund, 5_000_000, DEFAULT_PAIR)
    assert refusals == []
    assert assertions["asset2Price"] == "2700000/1"
    assert assertions["orderAddress"] == fx.ceremony["order_address"]


def test_the_generated_datum_keeps_the_indefinite_length_shape(fx):
    # The reader's info==31 / break branches only stay exercised while cardano-cli emits
    # indefinite-length constructor arrays. That is undocumented; if a future release canonicalises
    # Plutus Data to definite length, this reddens instead of the coverage evaporating in silence.
    out = vcb.load_body(fx.honest)[1][0]
    inline = (out[2] if isinstance(out, dict) else out.get(2))[1]
    raw = inline.value if hasattr(inline, "value") else bytes(inline)
    assert raw[:1] == b"\xd8" and b"\x9f" in raw[:4] and raw[-1:] == b"\xff", raw[:8].hex()


def test_real_malicious_body_is_refused_naming_the_operator_output(fx):
    _only(_refusals(fx, vcb.load_body(fx.malicious)),
          fx.operator_raw.hex(), "neither the ceremony order address")


def test_gate_refuses_malicious_body_and_writes_no_witness(fx, tmp_path):
    # The load-bearing gate: run --witness on the operator's malicious body and confirm NO witness is
    # produced. This is the exact step the runbook tells the client to run in place of a raw
    # `cardano-cli transaction witness`, which (proven separately) blind-signs this body today.
    out = str(tmp_path / "should_not_exist.witness")
    proc = _run_cli(fx, fx.malicious, extra=["--witness", fx.client_skey, "--out-file", out,
                                             "--sign-cli", _cardano_cli(), "--testnet-magic", "1"])
    assert proc.returncode == 3, proc.stderr
    assert "REFUSED" in proc.stderr
    # main() also exits 3 when it cannot READ the ceremony at all, so a broken params file would
    # otherwise satisfy every assertion above without the body ever being judged.
    assert "REFUSING TO VERIFY" not in proc.stderr, proc.stderr
    assert fx.operator_raw.hex() in proc.stderr, proc.stderr
    assert not os.path.exists(out), "a refused body must yield NO witness"


def test_gate_opens_for_honest_body(fx, tmp_path):
    out = str(tmp_path / "client.witness")
    proc = _run_cli(fx, fx.honest, extra=["--witness", fx.client_skey, "--out-file", out,
                                          "--sign-cli", _cardano_cli(), "--testnet-magic", "1"])
    assert "VERIFIED" in proc.stdout, proc.stderr
    assert proc.returncode == 0, proc.stderr
    assert os.path.exists(out), "a verified body must produce a witness"
    assert os.path.getsize(out) > 0


# ----------------------------------------------------------------------------
# Refusal matrix — each isolates one guard so a mutation of it reddens a named test.
# ----------------------------------------------------------------------------

def test_synthetic_honest_passes(fx):
    assert _refusals(fx, _body(fx, [_order_out(fx, _datum(fx)), _change_out(fx)])) == []


def test_below_ask_floor_refused(fx):
    body = _body(fx, [_order_out(fx, _datum(fx, a2=(2500000, 1))), _change_out(fx)])
    _only(_refusals(fx, body), "asset2_price (ask)", "below the ceremony floor")


def test_below_bid_floor_refused(fx):
    body = _body(fx, [_order_out(fx, _datum(fx, a1=(1, 3000000))), _change_out(fx)])
    _only(_refusals(fx, body), "asset1_price (bid)", "below the ceremony floor")


def test_extra_mint_refused(fx):
    mint = {fx.beacon: {PB: 1, A1B: 1, A2B: 1}, TOK_POL: {TOK_NAME: 1000}}
    body = _body(fx, [_order_out(fx, _datum(fx)), _change_out(fx)], mint=mint)
    _only(_refusals(fx, body), "mint is not exactly the three pair beacons")


def test_missing_inline_datum_refused(fx):
    body = _body(fx, [_order_out(fx, datum_cbor=None), _change_out(fx)])
    _only(_refusals(fx, body), "carries no inline datum")


def test_two_order_outputs_refused(fx):
    body = _body(fx, [_order_out(fx, _datum(fx)), _order_out(fx, _datum(fx)), _change_out(fx)])
    _only(_refusals(fx, body), "pays the order address 2 times")


def test_change_to_operator_refused(fx):
    body = _body(fx, [_order_out(fx, _datum(fx)), _change_out(fx, raw=fx.operator_raw)])
    _only(_refusals(fx, body), fx.operator_raw.hex(), "neither the ceremony order address")


def test_wrong_beacon_id_in_datum_refused(fx):
    other = bytes([fx.beacon[0] ^ 0xFF]) + fx.beacon[1:]
    body = _body(fx, [_order_out(fx, _datum(fx, beacon=other)), _change_out(fx)])
    _only(_refusals(fx, body), "order datum:", "beacon policy")


def test_extraneous_asset_in_order_output_refused(fx):
    """The chain hard-errors on it, at phase 2, after the client has signed.

    extract_ask_and_offer_quantity (two_way_swap/utils.ak) raises
    `error @"No extraneous assets allowed in the UTxO"` for any policy that is not
    beacon_id / ada / asset1_id / asset2_id. This gate exists to refuse before a
    signature, so a body it blesses must not be one the validator rejects: the
    client would forfeit their pledged collateral on a phase-2 failure.
    """
    junk_pol, junk_name = bytes.fromhex("ff" * 28), b"JUNK"
    out = _order_out(fx, _datum(fx))
    out[1][1][junk_pol] = {junk_name: 7}
    _only(_refusals(fx, _body(fx, [out, _change_out(fx)])), "extraneous", junk_pol.hex())


def test_extraneous_asset_name_under_the_token_policy_refused(fx):
    """The validator matches the asset NAME too, not just the policy."""
    out = _order_out(fx, _datum(fx))
    out[1][1][TOK_POL][b"OTHER"] = 3
    _only(_refusals(fx, _body(fx, [out, _change_out(fx)])), "extraneous")


def test_order_holding_only_beacons_and_ada_is_allowed(fx):
    """A pure ADA bid seeds the buy side with no token, and the chain accepts it.

    Asserting "no refusals" alone passes with the whole extraneous-asset hunk
    deleted, so it is paired with the case the hunk exists to catch: the same body
    plus one junk asset MUST be refused. Together they pin the boundary rather than
    the absence of a check."""
    out = _order_out(fx, _datum(fx))
    del out[1][1][TOK_POL]
    assert _refusals(fx, _body(fx, [out, _change_out(fx)])) == []

    junk = bytes.fromhex("ee" * 28)
    out[1][1][junk] = {b"X": 1}
    _only(_refusals(fx, _body(fx, [out, _change_out(fx)])), "extraneous", junk.hex())


def test_datum_declaring_a_foreign_asset2_is_refused(fx):
    """The gate must not take the traded pair from the body it is auditing.

    `traded` was read out of the datum's own asset1/asset2 fields, and nothing
    upstream constrains those — so an operator declares whatever they want to park
    as asset2 and the extraneous-asset check waves it through. The pair has to come
    from the CLIENT, the same way --my-address is what makes a possession proof
    about the client rather than about whoever wrote the params file.
    """
    junk = bytes.fromhex("ff" * 28)
    out = _order_out(fx, _datum(fx, asset2=(junk, TOK_NAME)))
    out[1][1][junk] = {TOK_NAME: 4}
    del out[1][1][TOK_POL]
    refusals = _refusals(fx, _body(fx, [out, _change_out(fx)]))
    assert any("asset2" in r or "pair" in r for r in refusals), refusals


def test_swapped_beacon_roles_are_refused(fx):
    """expected_beacons was a SET read from the datum and only checked against the
    holdings and the mint — all three of which the operator controls together. No
    name was ever derived from the pair, so swapping the pair and asset1 beacons is
    self-consistent and passed."""
    datum = _datum(fx, pair_beacon=A1B, asset1_beacon=PB)
    out = _order_out(fx, datum)
    refusals = _refusals(fx, _body(fx, [out, _change_out(fx)]))
    assert any("beacon" in r for r in refusals), refusals


def test_same_policy_pair_is_not_reported_as_extraneous(fx):
    """Two-way cardano-swaps supports a token/token pair under ONE policy. Keying
    the traded map by policy id collapsed the two legs, so the gate refused the
    asset1 leg the datum itself names."""
    other = b"AAAA"
    datum = _datum(fx, asset1=(TOK_POL, other))
    out = _order_out(fx, datum)
    out[1][1][TOK_POL] = {TOK_NAME: 4, other: 9}
    refusals = _refusals(fx, _body(fx, [out, _change_out(fx)]), expect_pair=((TOK_POL.hex(), other.hex()), (TOK_POL.hex(), TOK_NAME.hex())))
    assert not any("extraneous" in r for r in refusals), refusals


def test_reference_script_on_the_order_output_refused(fx):
    """A create must not park a reference script in the order output; the browser
    mirror refuses it and the gate discarded output field 3 entirely."""
    out = _order_out(fx, _datum(fx))
    out[3] = vcb._Tag(24, b"\x01\x02")
    _only(_refusals(fx, _body(fx, [out, _change_out(fx)])), "reference script")


def test_datum_on_a_change_output_refused(fx):
    """Change is plain value returning to the client; a datum on it means the value
    is going somewhere with a script's rules attached."""
    change = _change_out(fx)
    change[2] = _inline(_datum(fx))
    _only(_refusals(fx, _body(fx, [_order_out(fx, _datum(fx)), change])), "datum")


def test_unsorted_pair_refused(fx):
    """The validator requires asset1 < asset2; an unsorted datum can never validate,
    so a gate that blesses it hands the client a create that dies on chain."""
    pair = ((TOK_POL.hex(), TOK_NAME.hex()), ("", ""))
    datum = _datum(fx, asset1=(TOK_POL, TOK_NAME), asset2=(b"", b""),
                   asset1_beacon=A2B, asset2_beacon=A1B)
    out = _order_out(fx, datum)
    refusals = _refusals(fx, _body(fx, [out, _change_out(fx)]), expect_pair=pair)
    assert any("sorted" in r for r in refusals), refusals


def test_non_positive_traded_quantity_refused(fx):
    """A zero-quantity entry is not admissible in a Conway output value at all, and a
    negative one is not a holding — neither is something to bless into a signature."""
    out = _order_out(fx, _datum(fx))
    out[1][1][TOK_POL] = {TOK_NAME: 0}
    _only(_refusals(fx, _body(fx, [out, _change_out(fx)])), "quantity")


def test_high_fee_refused(fx):
    body = _body(fx, [_order_out(fx, _datum(fx)), _change_out(fx)], fee=6_000_000)
    _only(_refusals(fx, body), "fee is 6000000 lovelace, above")


def test_collateral_return_to_operator_refused(fx):
    body = _body(fx, [_order_out(fx, _datum(fx)), _change_out(fx)],
                 coll_return=_change_out(fx, raw=fx.operator_raw))
    _only(_refusals(fx, body), "collateral-return output does not go back")


# ----------------------------------------------------------------------------
# Value sinks that produce NO checked output. The verifier cannot see input values, so it must fail
# closed: refuse any body field it does not model, and bound the collateral it cannot otherwise see.
# ----------------------------------------------------------------------------

def test_treasury_donation_refused(fx):
    # The round-6 CRITICAL: a Conway treasury donation (body field 22) burns client ADA to the treasury
    # with no output and no extra witness. The output-only value model missed it; fail-closed catches it.
    body = _body(fx, [_order_out(fx, _datum(fx)), _change_out(fx)])
    body[22] = 4_194_304
    _only(_refusals(fx, body), "donation")


def test_real_honest_body_with_donation_is_refused(fx):
    # The exact proven break, on the REAL generated body shape: honest body + field 22. The single-
    # refusal assertion doubles as proof the honest anchor is otherwise clean.
    body = vcb.load_body(fx.honest)
    body[22] = 4_194_304
    _only(_refusals(fx, body), "donation")


def test_certificates_refused(fx):
    body = _body(fx, [_order_out(fx, _datum(fx)), _change_out(fx)])
    body[4] = [[0, [0, bytes(28)]]]
    _only(_refusals(fx, body), "certificate")


def test_withdrawals_refused(fx):
    body = _body(fx, [_order_out(fx, _datum(fx)), _change_out(fx)])
    body[5] = {bytes(29): 1_000_000}
    _only(_refusals(fx, body), "withdrawal")


def test_governance_proposal_refused(fx):
    body = _body(fx, [_order_out(fx, _datum(fx)), _change_out(fx)])
    body[20] = [[1_000_000_000, bytes(29)]]
    assert len(_refusals(fx, body)) == 1
    assert any(n in _refusals(fx, body)[0].lower() for n in ("proposal", "unmodelled"))


def test_collateral_without_return_refused(fx):
    body = _body(fx, [_order_out(fx, _datum(fx)), _change_out(fx)])
    del body[16]  # collateral inputs (13) remain but nothing returns → full forfeit on script failure
    _only(_refusals(fx, body), "collateral")


def test_collateral_without_total_refused(fx):
    body = _body(fx, [_order_out(fx, _datum(fx)), _change_out(fx)], total_collateral=None)
    r = _refusals(fx, body)
    assert len(r) == 1 and "collateral" in r[0].lower()
    assert "unbounded" in r[0].lower() or "total" in r[0].lower(), r


def test_oversized_total_collateral_refused(fx):
    body = _body(fx, [_order_out(fx, _datum(fx)), _change_out(fx)], total_collateral=50_000_000)
    r = _refusals(fx, body)
    assert len(r) == 1 and "collateral" in r[0].lower()
    assert "exceed" in r[0].lower() or "cap" in r[0].lower(), r


def test_composite_body_key_refused(fx):
    # A composite (tag/array) body-map key must yield a clean Refusal, not an uncaught TypeError from
    # sorted(body). Fail-closed either way, but the refusal must be intentional, not a traceback.
    body = _body(fx, [_order_out(fx, _datum(fx)), _change_out(fx)])
    body[("__tag__", 2, b"\x16")] = 4_194_304  # a bignum-tagged (composite) key
    with pytest.raises(vcb.Refusal):
        vcb.verify_body(body, fx.ceremony, fx.fund, 5_000_000, DEFAULT_PAIR)


def test_duplicate_map_key_refused():
    # The hand-rolled reader must reject duplicate CBOR map keys (cardano-node does), so the two decoders
    # can never disagree about which value a repeated key carries. There is now only ONE reader — it lives
    # in verify_ceremony and raises that module's error, which run() already catches alongside Refusal.
    buf = bytes([0xA2, 0x00, 0x01, 0x00, 0x02])  # {0:1, 0:2} — key 0 twice
    with pytest.raises((vcb.Refusal, vc.CeremonyError)):
        vcb.cbor_load(buf)


def test_the_reader_is_the_one_verify_ceremony_ships():
    # Two decoders in one tree is how a duplicate COSE label ends up picking a different
    # value than the signer used in one tool and not the other.
    assert vcb.cbor_load is vc.cbor_load


def test_indefinite_empty_constructor_decodes():
    # cardano-cli 11 emits d87a80 for None, so the indefinite-empty form d87a9fff no longer appears in
    # generated bodies. Older bodies carry it, and the reader must still accept it.
    assert vcb.cbor_load(bytes.fromhex("d87a9fff")) is not None


# ----------------------------------------------------------------------------
# What this fixture does NOT prove, stated so nothing here is read as more than it is:
#   - The beacon policy is a generated native sig script, not the real cardano-swaps PlutusV2 policy.
#     The bodies therefore carry no script_data_hash and no redeemer. verify_body reads neither, so no
#     guard loses coverage — but nothing here asserts anything about the deployed policy id.
#   - It proves SHAPE, never BYTES. A generated body cannot be diffed against a known-good hex, so
#     every assertion lands on decoded structure and on the exact refusal list.
#   - derive_ceremony passes --decimals 0 and no band anchor, so the ceremony's price-LEVEL check is
#     inert on this path; these cases only compare the datum's floors to the ceremony's.
# ----------------------------------------------------------------------------

if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
