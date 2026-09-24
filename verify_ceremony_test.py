#!/usr/bin/env python3
"""Tests for verify_ceremony.py — the client-side MMaaS ceremony verifier.

The golden vector is the real preprod rehearsal of 2026-07-25. Every value below
is public (verification-key hashes, script hashes, bech32 addresses, price
floors); no key material appears here or in the repository.

Run: python3 maker_stake/verify_ceremony_test.py
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "verify_ceremony.py")
AIKEN = os.environ.get("AIKEN", os.path.expanduser("~/.aiken/bin/aiken"))

sys.path.insert(0, HERE)

# --- Golden vector: the proven preprod rehearsal ceremony -------------------

GOLDEN_PARAMS = {
    "adam_bot_pkh": "e5de5661f9d883a58189fb7947e6e45cbf862025d5d472bcd3006fb6",
    "client_owner_vkh": "559c89b84c94f8569039b74f54a3f7f6852a79aacf67e6cdf2b89823",
    "client_payout_address": "addr_test1vp2eezdcfj20s45s8xm5749r7lmg22ne4t8k0ekd72ufsgc7vj5pv",
    "dapp_hash": "11928a3ac3b65edbf103ea6bb3362e39b879a36f02897df31c40917b",
    "beacon_id": "8a199a17ef4517215945aaf3c8c5204c60fd94d34c46d341e99c8fcf",
    # Bid ceiling 2.6 ADA / ask floor 2.7 ADA per ADAMMKT (0 decimals), around a
    # ~2.6 ADA mid: non-crossed, product 2_700_000/2_600_000 > 1.
    "min_asset1_price": {"numerator": 1, "denominator": 2600000},
    "min_asset2_price": {"numerator": 2700000, "denominator": 1},
    # Phase 1 A. Declared LAST, matching the validator: `aiken blueprint apply` is
    # positional, and fee_address is the SAME TYPE as client_payout above, so a
    # swap between them is silent and type-compatible — see the permutation test.
    "fee_address": "addr_test1vru3jg02gk49p9t8vw345qr47w9czcaavja4mfh09zcch3guttqnu",
    "fee_bps": 20,
}

# The pair applied to the FIRST preprod instance (87a61b9b…). Bid ceiling 3 ADA
# against an ask floor of 2 ADA: a filler buys the token at 2 and sells it back
# at 3, risk-free and repeatable. Kept here as the regression fixture.
CROSSED_FLOORS = {
    "min_asset1_price": {"numerator": 1, "denominator": 3000000},
    "min_asset2_price": {"numerator": 2000000, "denominator": 1},
}

# Re-derived AGAIN for the fee-basis change (G6, task #379): staking yield leaves
# the fee basis, which moves fee_ok, which moves the applied-parameter surface,
# which moves every hash below. Derived by running verify_ceremony.py --derive-only
# over GOLDEN_PARAMS above — the same tool a client runs — never by hand-editing a
# hash to match a failing test.
#
# The one before this was the nine-parameter (Phase 1 A) re-derivation. The one
# before THAT — unapplied 6206e819…, applied 3227e143… — is the live preprod bound client, a
# SEVEN-parameter instance. This tool rebuilds the validator from source, so it
# verifies instances made from the source it ships with: a seven-parameter
# ceremony must be checked out at a pre-A commit and verified with that tool.
# That is a real operational constraint, stated rather than papered over, and the
# refusal a client would hit is asserted below.
GOLDEN_UNAPPLIED_HASH = "19cc10abe5dfedee65c53d82548a1e6e2997f52c52a70af4170321fe"
GOLDEN_APPLIED_HASH = "f9eba40078f64fe86f2b8ecb513b3b96fafddc21e8019a47885d5c09"
GOLDEN_ORDER_ADDR = (
    "addr_test1xqge9z36cwm9akl3q04xhvek9cums7drdupgjl0nr3qfz7leawjqq"
    "78kfl5x72uwedgnkwuklt7acg0gqxdy0zzatsyszwgs3l"
)
GOLDEN_REWARD_ADDR = "stake_test17ru7hfqq0rmyl6r09w8vk5fm8wt04lwuy85qrxj83pw4czgjd2v9s"

# What the live preprod client is actually bound to, from the ceremony artefact
# at rehearsal/ceremony.3227e143.json.
LIVE_PREPROD_APPLIED_HASH = "3227e1438302c680307273d6dc2e3261e4b60c364d5eb5b0cf7b0151"

# The Plutus Data the rehearsal fed to `aiken blueprint apply` for client_payout
# (recorded in the rehearsal workspace as payout.addrdata).
GOLDEN_PAYOUT_CBOR = (
    "d8799fd8799f581c559c89b84c94f8569039b74f54a3f7f6852a79aacf67e6cdf2b89823ffd87a80ff"
)

# A second key the operator holds: used where a test needs a ceremony that is
# internally COHERENT but names a key the client does not hold. adam_bot_pkh
# itself cannot be used, because bot == client is refused on its own grounds.
OPERATOR_SECOND_KEY = "a1" * 28

# ADAMMKT has 0 decimals, so the rehearsal's floors are 2.6 / 2.7 ADA per whole
# token. The anchor is what the client sources from a price feed or an OTC quote
# — anything that is not the operator — and both floors must sit inside it.
DEFAULT_DECIMALS = 0
DEFAULT_BAND = "2.5:2.8"

# The same two floors in the WRONG SLOTS. `min_a1 * min_a2 >= 1` is symmetric, so
# this passes on chain and produces a valid, non-crossed ceremony whose ask floor
# is 1/2_600_000 lovelace per base unit: the whole token leg for less than a
# lovelace, taken by anyone through the permissionless TakeAsset path.
TRANSPOSED_FLOORS = {
    "min_asset1_price": GOLDEN_PARAMS["min_asset2_price"],
    "min_asset2_price": GOLDEN_PARAMS["min_asset1_price"],
}

# The rehearsal client's own verification key, so the escape-hatch parameter can
# be checked against a key file rather than a hex string. Public half only.
CLIENT_VKEY_ENVELOPE = {
    "type": "PaymentVerificationKeyShelley_ed25519",
    "description": "Payment Verification Key",
    "cborHex": "5820178735ffa6f4f462eb543ed51d41845c6e236c954bd373d0011c2cb00c01873d",
}


# RFC 8032 §7.1 test vectors: (seed, public key, message, signature). Published
# alongside the standard, so they are an oracle this repository did not write — which
# is the point. The tool's ed25519 verifier is pinned against them, and the signer
# below is a SEPARATE implementation, so a possession proof is minted by one body of
# code and judged by another.
RFC8032_VECTORS = [
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
     "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a3"
     "3bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
     "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15"
     "996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
     "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16"
     "f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
]
RFC8032_VEC1_SEED = RFC8032_VECTORS[0][0]
RFC8032_VEC2_SEED = RFC8032_VECTORS[1][0]

# Vector 1 stands in for a keypair the OPERATOR generated and kept the signing half
# of: the client is handed the .vkey file and nothing else, which is all a
# verification-key envelope has ever been. Its private half is published in the RFC,
# so these tests can hold both halves and exercise both sides of the check.
OPERATOR_KEYPAIR_VKH = "35dedd2982a03cf39e7dce03c839994ffdec2ec6b04f1cf2d40e61a3"
OPERATOR_VKEY_ENVELOPE = {
    "type": "PaymentVerificationKeyShelley_ed25519",
    "description": "Payment Verification Key",
    "cborHex": "5820" + RFC8032_VECTORS[0][1],
}

# The golden ceremony's escape-hatch key is the real preprod rehearsal client's, whose
# signing half is deliberately NOT in this repository. Its possession proofs are
# therefore committed as fixtures: a signature is public, a signing key is not. Each
# was minted with `maker_stake/rehearsal/client.skey` over the challenge printed
# below it, and `test_the_challenge_wire_format_is_pinned` fixes the challenge those
# signatures answer, so a change to the challenge rule invalidates them loudly.
GOLDEN_POSSESSION_PROOFS = {
    # the rehearsal ceremony on testnet
    "993774bf630ed50443e1168ecd18558a1bfed0ac27cc1d786008ce5964ecaba4":
        "3ae783a169cc4940c52b7b8d637033f7298ba4d2baed1d525cad72e8db2b423f"
        "f27a2b9c39ff5735bc65a56ae4c76945c4aef4e6415051fc706faa49cdb06007",
    # the same nine parameters with both addresses re-encoded for mainnet
    "cbd2744113e3449f5fd9f093a7fb17f3b832703063f82e79f9ffe90d49906bc7":
        "8169f27b3e681b5fa77b4e4b9d82445f9076e57c62070193d298ba0631644e43"
        "cf5a981903d6b7e72d9e6cf82f8711ca34958b7f9af2c4ba707b8aba2a798c0d",
}


# --- An ed25519 SIGNER, for tests only -------------------------------------
# RFC 8032 §5.1. Deliberately a second implementation: the tool verifies proofs with
# its own code, and if the two ever disagree the possession tests go red rather than
# agreeing with themselves. Nothing here is imported by the tool.

_ED_P = 2 ** 255 - 19
_ED_L = 2 ** 252 + 27742317777372353535851937790883648493
_ED_D = (-121665 * pow(121666, _ED_P - 2, _ED_P)) % _ED_P


def _ed_add(pt, other):
    x1, y1, z1, t1 = pt
    x2, y2, z2, t2 = other
    a = (y1 - x1) * (y2 - x2) % _ED_P
    b = (y1 + x1) * (y2 + x2) % _ED_P
    c = 2 * t1 * t2 * _ED_D % _ED_P
    d = 2 * z1 * z2 % _ED_P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _ED_P, g * h % _ED_P, f * g % _ED_P, e * h % _ED_P)


def _ed_mul(scalar, pt):
    out = (0, 1, 1, 0)
    while scalar > 0:
        if scalar & 1:
            out = _ed_add(out, pt)
        pt = _ed_add(pt, pt)
        scalar >>= 1
    return out


_ED_BY = 4 * pow(5, _ED_P - 2, _ED_P) % _ED_P
_ED_BX = pow((_ED_BY * _ED_BY - 1) * pow(_ED_D * _ED_BY * _ED_BY + 1,
                                         _ED_P - 2, _ED_P), (_ED_P + 3) // 8, _ED_P)
if (_ED_BX * _ED_BX - (_ED_BY * _ED_BY - 1) * pow(_ED_D * _ED_BY * _ED_BY + 1,
                                                  _ED_P - 2, _ED_P)) % _ED_P != 0:
    _ED_BX = _ED_BX * pow(2, (_ED_P - 1) // 4, _ED_P) % _ED_P
if _ED_BX % 2 != 0:
    _ED_BX = _ED_P - _ED_BX
_ED_B = (_ED_BX, _ED_BY, 1, _ED_BX * _ED_BY % _ED_P)


def _ed_encode(pt):
    x, y, z, _ = pt
    inv = pow(z, _ED_P - 2, _ED_P)
    x, y = x * inv % _ED_P, y * inv % _ED_P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _ed_clamp(digest):
    scalar = bytearray(digest[:32])
    scalar[0] &= 248
    scalar[31] &= 127
    scalar[31] |= 64
    return int.from_bytes(scalar, "little")


def ed25519_sign(seed, message):
    """RFC 8032 Ed25519ph-free `Sign(seed, M)`."""
    digest = hashlib.sha512(seed).digest()
    a = _ed_clamp(digest)
    public = _ed_encode(_ed_mul(a, _ED_B))
    r = int.from_bytes(hashlib.sha512(digest[32:] + message).digest(), "little") % _ED_L
    big_r = _ed_encode(_ed_mul(r, _ED_B))
    k = int.from_bytes(hashlib.sha512(big_r + public + message).digest(),
                       "little") % _ED_L
    return big_r + int.to_bytes((r + k * a) % _ED_L, 32, "little")


def ed25519_public(seed):
    return _ed_encode(_ed_mul(_ed_clamp(hashlib.sha512(seed).digest()), _ED_B))


def challenge_for(params, network="testnet"):
    """The 32 bytes the tool will demand a signature over, for these parameters."""
    from verify_ceremony import (encode_params, possession_challenge,
                                 possession_digest)
    encoded, _ = encode_params(params, network)
    return possession_digest(
        possession_challenge(network, GOLDEN_UNAPPLIED_HASH, encoded))


def sign_possession(params, seed_hex, network="testnet"):
    return ed25519_sign(bytes.fromhex(seed_hex), challenge_for(params, network))


def committed_proof(params, network="testnet"):
    """The committed signature answering this ceremony's challenge, if there is one."""
    try:
        digest = challenge_for(params, network).hex()
    except Exception:
        return None
    proof = GOLDEN_POSSESSION_PROOFS.get(digest)
    return None if proof is None else bytes.fromhex(proof)


def applied_hash_for(params):
    """Drive the nine-step apply chain directly, bypassing the tool's ceremony
    coherence gates, so a permutation's hash can be derived even when the tool
    would (rightly) refuse to endorse it."""
    from verify_ceremony import (apply_params, check_source_integrity,
                                 encode_params)
    tmp = tempfile.mkdtemp(prefix="mmaas-permute-")
    try:
        _, rebuilt_path, _ = check_source_integrity(HERE, AIKEN, tmp)
        encoded, _ = encode_params(params, "testnet")
        applied, _, _ = apply_params(AIKEN, rebuilt_path, encoded, tmp)
        return applied
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def write_params(params, path):
    with open(path, "w") as fh:
        json.dump(params, fh, indent=2)
    return path


def run_tool(params, *, network="testnet", extra=(), project=HERE,
             decimals=DEFAULT_DECIMALS, band=DEFAULT_BAND, vkey=CLIENT_VKEY_ENVELOPE,
             proof="auto"):
    """Invoke the tool; return (returncode, stdout, stderr, parsed_json_or_None).

    `decimals`, `band`, `vkey` and `proof` are the inputs only the CLIENT can supply,
    and the tool requires all of them for a verdict. Pass None to omit one and
    exercise what the tool does without it. `proof="auto"` supplies the committed
    signature for this ceremony when there is one, and nothing when there is not —
    so a test that expects a verdict and has no fixture fails on the missing
    possession proof rather than passing without one."""
    tmp = tempfile.mkdtemp(prefix="mmaas-verify-test-")
    try:
        params_path = write_params(params, os.path.join(tmp, "params.json"))
        json_path = os.path.join(tmp, "out.json")
        cmd = [sys.executable, TOOL, "--params", params_path, "--project", project,
               "--aiken", AIKEN, "--json-out", json_path]
        if network is not None:
            cmd += ["--network", network]
        if decimals is not None:
            cmd += ["--decimals", str(decimals)]
        if band is not None:
            cmd += ["--expect-band-ada-per-display-unit", band]
        if vkey is not None:
            cmd += ["--my-vkey-file", write_vkey(vkey, os.path.join(tmp, "client.vkey"))]
        if proof == "auto":
            proof = committed_proof(params, network)
        if proof is not None:
            proof_path = os.path.join(tmp, "possession.proof")
            with open(proof_path, "w") as fh:
                fh.write(proof.hex() + "\n")
            cmd += ["--possession-proof", proof_path]
        cmd += list(extra)
        proc = subprocess.run(cmd, capture_output=True, text=True)
        parsed = None
        if os.path.exists(json_path):
            with open(json_path) as fh:
                parsed = json.load(fh)
        return proc.returncode, proc.stdout, proc.stderr, parsed
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def golden_expectations():
    return ["--expect-script-hash", GOLDEN_APPLIED_HASH,
            "--expect-order-address", GOLDEN_ORDER_ADDR,
            "--expect-reward-address", GOLDEN_REWARD_ADDR]


def mainnet_payout():
    """The golden client payout key hash, re-encoded as a MAINNET enterprise address."""
    from verify_ceremony import bech32_encode
    return bech32_encode(
        "addr", bytes([0x61]) + bytes.fromhex(GOLDEN_PARAMS["client_owner_vkh"]))


def on_mainnet(address):
    """A testnet enterprise address re-encoded for mainnet: same credential, network
    id 1 in the low nibble of the header."""
    from verify_ceremony import bech32_decode, bech32_encode
    _, raw = bech32_decode(address)
    return bech32_encode("addr", bytes([(raw[0] & 0xF0) | 0x01]) + raw[1:])


def mainnet_params():
    """The golden ceremony on mainnet. BOTH addresses move: a params file mixing
    networks is refused, so a test that runs --network mainnet has to carry a
    mainnet fee address too."""
    return dict(GOLDEN_PARAMS,
                client_payout_address=on_mainnet(GOLDEN_PARAMS["client_payout_address"]),
                fee_address=on_mainnet(GOLDEN_PARAMS["fee_address"]))


def enterprise_addr(vkh):
    """A testnet enterprise address paying to `vkh`. The validator requires the
    payout address's payment credential to BE client_owner_vkh, so any test that
    moves one has to move the other."""
    from verify_ceremony import bech32_encode
    return bech32_encode("addr_test", bytes([0x60]) + bytes.fromhex(vkh))


def write_vkey(envelope, path):
    with open(path, "w") as fh:
        json.dump(envelope, fh)
    return path


class GoldenVector(unittest.TestCase):
    """The proven rehearsal ceremony must reproduce bit-for-bit."""

    @classmethod
    def setUpClass(cls):
        cls.rc, cls.out, cls.err, cls.js = run_tool(
            GOLDEN_PARAMS, extra=golden_expectations())

    def test_exits_zero(self):
        self.assertEqual(self.rc, 0, f"stdout:\n{self.out}\nstderr:\n{self.err}")

    def test_source_integrity_holds(self):
        self.assertTrue(self.js["source_integrity"]["ok"])
        self.assertEqual(self.js["source_integrity"]["unapplied_script_hash"],
                         GOLDEN_UNAPPLIED_HASH)

    def test_reproduces_applied_hash(self):
        self.assertEqual(self.js["derived"]["applied_script_hash"], GOLDEN_APPLIED_HASH)

    def test_reproduces_order_address(self):
        self.assertEqual(self.js["derived"]["order_address"], GOLDEN_ORDER_ADDR)

    def test_reproduces_reward_address(self):
        self.assertEqual(self.js["derived"]["reward_address"], GOLDEN_REWARD_ADDR)

    def test_payout_param_matches_rehearsal_cbor(self):
        cbor = self.js["applied_parameters"][2]
        self.assertEqual(cbor["name"], "client_payout")
        self.assertEqual(cbor["plutus_data_cbor_hex"], GOLDEN_PAYOUT_CBOR)

    def test_applies_nine_params_in_declared_order(self):
        self.assertEqual([p["name"] for p in self.js["applied_parameters"]],
                         ["adam_bot_pkh", "client_owner_vkh", "client_payout",
                          "dapp_hash", "beacon_id", "min_asset1_price",
                          "min_asset2_price", "fee_address", "fee_bps"])

    def test_human_output_names_what_each_value_protects(self):
        for needle in ["escape", "payout", "BID CEILING", "ASK FLOOR", "bot"]:
            self.assertIn(needle, self.out)

    def test_json_reports_verdict_and_no_mismatches(self):
        self.assertTrue(self.js["ok"])
        self.assertEqual(self.js["mismatches"], [])
        self.assertEqual(self.js["network"], "testnet")


class PreviousParameterSurface(unittest.TestCase):
    """The live preprod client was bound to the SEVEN-parameter validator. This
    tool rebuilds from the source it ships with, which is the nine-parameter one,
    so it cannot reproduce that instance — and the whole value of the tool is that
    it says so instead of endorsing a script the client is not actually bound to."""

    def test_the_live_seven_parameter_instance_is_reported_as_a_mismatch(self):
        rc, out, err, js = run_tool(
            GOLDEN_PARAMS,
            extra=["--expect-script-hash", LIVE_PREPROD_APPLIED_HASH])
        self.assertNotEqual(rc, 0)
        self.assertNotEqual(js["derived"]["applied_script_hash"],
                            LIVE_PREPROD_APPLIED_HASH)
        self.assertTrue(any("script hash" in m["what"] for m in js["mismatches"]))
        self.assertIn(LIVE_PREPROD_APPLIED_HASH, out)


class WrongFloorAttack(unittest.TestCase):
    """ATTACK 1: operator baked a different price floor than the client agreed."""

    def test_lower_ask_floor_changes_hash_and_fails(self):
        """Shaved 0.1 ADA off the ask floor: still a non-crossed band, so the
        address comparison is what catches it."""
        p = dict(GOLDEN_PARAMS, min_asset2_price={"numerator": 2600000, "denominator": 1})
        rc, out, err, js = run_tool(p, extra=golden_expectations())
        self.assertNotEqual(rc, 0)
        self.assertNotEqual(js["derived"]["applied_script_hash"], GOLDEN_APPLIED_HASH)
        self.assertTrue(any("script hash" in m["what"] for m in js["mismatches"]))
        self.assertIn("MISMATCH", out)

    def test_gutted_ask_floor_crosses_the_band_and_is_refused(self):
        p = dict(GOLDEN_PARAMS, min_asset2_price={"numerator": 1, "denominator": 1})
        rc, out, err, js = run_tool(p, extra=golden_expectations())
        self.assertNotEqual(rc, 0)
        self.assertIn("CROSSED", js["error"])

    def test_raised_bid_ceiling_changes_hash_and_fails(self):
        """A bid ceiling of 2.0 instead of 2.6: still non-crossed against a 2.7
        ask floor, so again it is the address comparison that catches it. The
        anchor here is deliberately wide enough (1.9–2.8) to let the run reach
        that comparison — a 2.5–2.8 anchor would refuse a 2.0 ceiling first,
        which is the level check doing its job, not this test's subject."""
        p = dict(GOLDEN_PARAMS, min_asset1_price={"numerator": 1, "denominator": 2000000})
        rc, out, err, js = run_tool(p, extra=golden_expectations(), band="1.9:2.8")
        self.assertNotEqual(rc, 0)
        self.assertNotEqual(js["derived"]["applied_script_hash"], GOLDEN_APPLIED_HASH)

    def test_bid_ceiling_above_the_ask_floor_is_refused(self):
        p = dict(GOLDEN_PARAMS, min_asset1_price={"numerator": 1, "denominator": 6000000})
        rc, out, err, js = run_tool(p, extra=golden_expectations())
        self.assertNotEqual(rc, 0)
        self.assertIn("CROSSED", js["error"])
        self.assertNotIn("derived", js)

    def test_zero_floor_is_refused_outright(self):
        p = dict(GOLDEN_PARAMS, min_asset1_price={"numerator": 0, "denominator": 1})
        rc, out, err, js = run_tool(p, extra=["--derive-only"])
        self.assertNotEqual(rc, 0)
        self.assertIn("floor", (out + err).lower())

    def test_negative_floor_is_refused_outright(self):
        p = dict(GOLDEN_PARAMS, min_asset2_price={"numerator": 1, "denominator": -1})
        rc, out, err, js = run_tool(p, extra=["--derive-only"])
        self.assertNotEqual(rc, 0)
        self.assertIn("min_asset2_price", js["error"])


class CrossedBandAttack(unittest.TestCase):
    """B2: the two floors are a BAND, and a crossed band is a standing arbitrage.

    min_asset1_price is token-per-lovelace, so flooring it CAPS the bid; only
    min_asset2_price floors the ask. Nothing related them, so the first preprod
    ceremony shipped a bid ceiling ABOVE its ask floor.
    """

    def test_the_deployed_crossed_pair_is_refused(self):
        p = dict(GOLDEN_PARAMS, **CROSSED_FLOORS)
        rc, out, err, js = run_tool(p, extra=["--derive-only"])
        self.assertNotEqual(rc, 0)
        self.assertIn("CROSSED", js["error"])
        self.assertIn("3000000/1", js["error"])
        self.assertIn("2000000/1", js["error"])
        self.assertNotIn("derived", js)

    def test_the_honest_pair_around_the_same_mid_is_accepted(self):
        rc, out, err, js = run_tool(GOLDEN_PARAMS, extra=["--derive-only"])
        self.assertEqual(rc, 0, f"{out}\n{err}")
        self.assertFalse(js["band"]["band_is_crossed"])
        self.assertEqual(js["band"]["bid_ceiling_lovelace_per_base_unit"], "2600000/1")
        self.assertEqual(js["band"]["ask_floor_lovelace_per_base_unit"], "2700000/1")

    def test_the_inequality_is_not_inverted(self):
        """The same relation read the other way accepts the crossed pair and refuses
        the honest one, so drive the real predicate both ways round.

        It has to CALL it to say that. An earlier version recomputed the product on
        the fixture constants instead, and stayed green both when the relation was
        inverted and when it was deleted outright."""
        from verify_ceremony import (CeremonyError, address_to_plutus_data,
                                     check_ceremony_coherence)
        _, payout = address_to_plutus_data(
            GOLDEN_PARAMS["client_payout_address"], "testnet")
        with self.assertRaises(CeremonyError) as caught:
            check_ceremony_coherence(dict(GOLDEN_PARAMS, **CROSSED_FLOORS), payout,
                                     DEFAULT_DECIMALS, None)
        self.assertIn("CROSSED band", str(caught.exception))
        band = check_ceremony_coherence(GOLDEN_PARAMS, payout, DEFAULT_DECIMALS, None)
        self.assertFalse(band["band_is_crossed"])

    def test_the_report_no_longer_claims_dust_protection_unconditionally(self):
        rc, out, err, js = run_tool(GOLDEN_PARAMS, extra=golden_expectations())
        self.assertEqual(rc, 0, f"{out}\n{err}")
        self.assertIn("round-tripped", out)
        self.assertIn("BASE UNIT", out)
        self.assertIn("ABSOLUTE, not market-relative", out)


class WrongPayoutAttack(unittest.TestCase):
    """ATTACK 2: operator baked a payout address it controls."""

    OPERATOR_CONTROLLED = "addr_test1vrjau4npl8vg8fvp38ahj3lxu3wtlp3qyh2agu4u6vqxlds065ldr"

    def test_payout_that_is_not_the_escape_key_is_refused(self):
        """B1: the validator requires client_payout to pay to client_owner_vkh, so
        an operator-controlled payout is refused without deriving anything."""
        p = dict(GOLDEN_PARAMS, client_payout_address=self.OPERATOR_CONTROLLED)
        rc, out, err, js = run_tool(p, extra=golden_expectations())
        self.assertNotEqual(rc, 0)
        self.assertIn("SAME", js["error"])
        self.assertNotIn("derived", js)

    def test_operator_payout_with_a_matching_escape_key_changes_the_address(self):
        """To make the parameters coherent the operator must ALSO claim a key it
        holds as the escape hatch — which changes the script hash and the address.
        (A second operator key, not adam_bot_pkh itself, which would trip the
        bot == client gate first.)"""
        operator_vkh = OPERATOR_SECOND_KEY
        p = dict(GOLDEN_PARAMS,
                 client_owner_vkh=operator_vkh,
                 client_payout_address=enterprise_addr(operator_vkh))
        # Derived without a verdict, to show the addresses move at all...
        rc, out, err, js = run_tool(p, extra=["--derive-only"], vkey=None)
        self.assertEqual(rc, 0, f"{out}\n{err}")
        self.assertNotEqual(js["derived"]["applied_script_hash"], GOLDEN_APPLIED_HASH)
        self.assertNotEqual(js["derived"]["order_address"], GOLDEN_ORDER_ADDR)
        self.assertNotEqual(js["derived"]["reward_address"], GOLDEN_REWARD_ADDR)
        # ...and refused outright when the client's own key is put to it, before
        # any address is derived at all.
        rc, out, err, js = run_tool(p, extra=golden_expectations())
        self.assertNotEqual(rc, 0)
        self.assertIn("is not yours", js["error"])
        self.assertNotIn("derived", js)

    def test_script_payout_is_refused(self):
        p = dict(GOLDEN_PARAMS, client_payout_address=GOLDEN_ORDER_ADDR)
        rc, out, err, js = run_tool(p, extra=["--derive-only"])
        self.assertNotEqual(rc, 0)
        self.assertIn("script", (out + err).lower())

    def test_payout_on_wrong_network_is_refused(self):
        p = dict(GOLDEN_PARAMS, client_payout_address=mainnet_payout())
        rc, out, err, js = run_tool(p, network="testnet", extra=["--derive-only"])
        self.assertNotEqual(rc, 0)
        self.assertIn("network", (out + err).lower())


class WrongEscapeHatchAttack(unittest.TestCase):
    """ATTACK 3: operator baked the wrong client_owner_vkh, killing self-custody."""

    def test_the_p1_p2_swap_is_refused_as_incoherent(self):
        """The bot/client swap as it appears in a params file: adam_bot_pkh holds
        the client's key and client_owner_vkh holds the bot's. The payout address
        is genuinely the client's, so the two no longer agree — and the validator
        requires them to. Caught with no chain access and no rebuild."""
        p = dict(GOLDEN_PARAMS,
                 adam_bot_pkh=GOLDEN_PARAMS["client_owner_vkh"],
                 client_owner_vkh=GOLDEN_PARAMS["adam_bot_pkh"])
        rc, out, err, js = run_tool(p, extra=golden_expectations())
        self.assertNotEqual(rc, 0)
        self.assertIn("swapped", js["error"])
        self.assertNotIn("derived", js)

    def test_one_key_for_both_roles_is_refused(self):
        """The degenerate swap: if the bot key IS the escape key, the 'escape hatch'
        disjunct is the bot, and nothing constrains it."""
        both = GOLDEN_PARAMS["adam_bot_pkh"]
        p = dict(GOLDEN_PARAMS, adam_bot_pkh=both, client_owner_vkh=both,
                 client_payout_address=enterprise_addr(both))
        rc, out, err, js = run_tool(p, extra=["--derive-only"])
        self.assertNotEqual(rc, 0)
        self.assertIn("same key", js["error"])
        self.assertNotIn("derived", js)

    def test_a_third_party_escape_key_changes_the_address(self):
        third = "0f" * 28
        p = dict(GOLDEN_PARAMS, client_owner_vkh=third,
                 client_payout_address=enterprise_addr(third))
        rc, out, err, js = run_tool(p, extra=["--derive-only"], vkey=None)
        self.assertEqual(rc, 0, f"{out}\n{err}")
        self.assertNotEqual(js["derived"]["order_address"], GOLDEN_ORDER_ADDR)
        # With the client's key in hand it never gets that far.
        rc, out, err, js = run_tool(p, extra=golden_expectations())
        self.assertNotEqual(rc, 0)
        self.assertIn("is not yours", js["error"])


class EscapeKeyOwnership(unittest.TestCase):
    """Naming the escape-hatch key: --my-vkey-file states WHICH key the ceremony
    means and refuses a file that hashes to a different one. Whether anyone can
    SIGN for it is a separate question, answered in EscapeKeyPossession below."""

    def test_the_clients_own_key_confirms_the_escape_hatch(self):
        rc, out, err, js = run_tool(GOLDEN_PARAMS, extra=golden_expectations())
        self.assertEqual(rc, 0, f"{out}\n{err}")
        self.assertEqual(js["my_vkh"], GOLDEN_PARAMS["client_owner_vkh"])
        self.assertIn("PROVED: its private half signed this ceremony's challenge",
                      out)

    def test_a_coherent_but_operator_owned_ceremony_is_still_caught(self):
        operator_vkh = OPERATOR_SECOND_KEY
        p = dict(GOLDEN_PARAMS,
                 client_owner_vkh=operator_vkh,
                 client_payout_address=enterprise_addr(operator_vkh))
        rc, out, err, js = run_tool(p, extra=["--derive-only"])
        self.assertNotEqual(rc, 0)
        self.assertIn("is not yours", js["error"])
        self.assertNotIn("derived", js)

    def test_an_extended_or_malformed_key_file_is_refused_not_guessed(self):
        bad = dict(CLIENT_VKEY_ENVELOPE, cborHex="5840" + "aa" * 64)
        rc, out, err, js = run_tool(GOLDEN_PARAMS, extra=["--derive-only"], vkey=bad)
        self.assertNotEqual(rc, 0)


class BotClientSwapEarnsNoVerdict(unittest.TestCase):
    """The p1<->p2 swap: adam_bot_pkh holds the client's key, client_owner_vkh
    holds the OPERATOR's, and the payout is the operator's own enterprise address
    so every coherence rule is satisfied. The applied hash is then whatever the
    operator applied, so the address matches too.

    Nothing on chain can see this — `withdraw` compares 28-byte strings for
    equality and cannot know which of them a human holds (pinned in
    maker_stake_bound.ak, `p1_p2_swap_is_a_relabelling_no_on_chain_predicate_can_see`).
    So the ONLY defence is the client hashing their own key file, and a verdict
    without it must not be obtainable.
    """

    @classmethod
    def setUpClass(cls):
        cls.params = dict(
            GOLDEN_PARAMS,
            adam_bot_pkh=GOLDEN_PARAMS["client_owner_vkh"],
            client_owner_vkh=GOLDEN_PARAMS["adam_bot_pkh"],
            client_payout_address=enterprise_addr(GOLDEN_PARAMS["adam_bot_pkh"]))
        cls.hash = applied_hash_for(cls.params)

    def test_the_swapped_ceremony_is_internally_coherent_and_derives(self):
        """The premise: nothing short of the key file objects to it."""
        rc, out, err, js = run_tool(self.params, extra=["--derive-only"], vkey=None)
        self.assertEqual(rc, 0, f"{out}\n{err}")
        self.assertEqual(js["derived"]["applied_script_hash"], self.hash)
        self.assertFalse(js["band"]["band_is_crossed"])

    def test_the_matching_address_earns_no_verdict_without_the_key_file(self):
        """Before this was mandatory, the first invocation below printed VERIFIED
        and exited 0 — naming the OPERATOR's key as 'your escape-hatch key'."""
        rc, out, err, js = run_tool(
            self.params, extra=["--expect-script-hash", self.hash],
            vkey=None, band=None, decimals=None)
        self.assertNotEqual(rc, 0)
        self.assertNotIn("VERIFIED", out)
        rc, out, err, js = run_tool(
            self.params, extra=["--expect-script-hash", self.hash], vkey=None)
        self.assertNotEqual(rc, 0)
        self.assertNotIn("VERIFIED", out)
        self.assertIn("no escape-hatch key was named at all", err)

    def test_the_key_file_names_the_operators_key_as_the_escape_hatch(self):
        rc, out, err, js = run_tool(
            self.params, extra=["--expect-script-hash", self.hash])
        self.assertNotEqual(rc, 0)
        self.assertNotIn("VERIFIED", out)
        self.assertIn("is not yours", js["error"])
        self.assertIn(GOLDEN_PARAMS["adam_bot_pkh"], js["error"])
        self.assertNotIn("derived", js)

    def test_derive_only_without_the_key_file_never_says_verified(self):
        rc, out, err, js = run_tool(self.params, extra=["--derive-only"], vkey=None)
        self.assertEqual(rc, 0)
        self.assertNotIn("VERIFIED", out)
        self.assertIn("DERIVED ONLY", out)
        self.assertIn("NOT PROVED", out)


class DappAndBeaconHashes(unittest.TestCase):

    def test_dapp_hash_equal_to_beacon_id_is_refused(self):
        same = GOLDEN_PARAMS["dapp_hash"]
        p = dict(GOLDEN_PARAMS, beacon_id=same)
        rc, out, err, js = run_tool(p, extra=["--derive-only"])
        self.assertNotEqual(rc, 0)
        self.assertIn("same hash", js["error"])


class PermutedParamOrderAttack(unittest.TestCase):
    """ATTACK 4: `aiken blueprint apply` is positional; a swap silently type-checks.

    Swapping adam_bot_pkh with client_owner_vkh hands the bot unconstrained
    authority and points the escape hatch at the bot. Swapping the two floors
    guts both protections. Both permutations produce a DIFFERENT script hash, so
    a client running this tool against the operator's address sees a mismatch
    instead of silently accepting the swap. The hashes are derived here rather
    than hardcoded, so the assertion cannot rot when the validator changes.
    """

    @classmethod
    def setUpClass(cls):
        cls.bot_client = applied_hash_for(dict(
            GOLDEN_PARAMS,
            adam_bot_pkh=GOLDEN_PARAMS["client_owner_vkh"],
            client_owner_vkh=GOLDEN_PARAMS["adam_bot_pkh"]))
        cls.floors = applied_hash_for(dict(
            GOLDEN_PARAMS,
            min_asset1_price=GOLDEN_PARAMS["min_asset2_price"],
            min_asset2_price=GOLDEN_PARAMS["min_asset1_price"]))

    def test_bot_client_swap_produces_a_different_hash(self):
        self.assertNotEqual(self.bot_client, GOLDEN_APPLIED_HASH)

    def test_floor_swap_produces_a_different_hash(self):
        self.assertNotEqual(self.floors, GOLDEN_APPLIED_HASH)

    def test_tool_refuses_a_bot_client_permuted_hash(self):
        rc, out, err, js = run_tool(
            GOLDEN_PARAMS, extra=["--expect-script-hash", self.bot_client])
        self.assertNotEqual(rc, 0)
        self.assertEqual(js["derived"]["applied_script_hash"], GOLDEN_APPLIED_HASH)
        self.assertTrue(any(m["expected"] == self.bot_client
                            for m in js["mismatches"]))

    def test_tool_refuses_a_floor_permuted_hash(self):
        rc, out, err, js = run_tool(
            GOLDEN_PARAMS, extra=["--expect-script-hash", self.floors])
        self.assertNotEqual(rc, 0)
        self.assertTrue(any(m["expected"] == self.floors
                            for m in js["mismatches"]))


class FloorTranspositionAttack(unittest.TestCase):
    """The band relation bounds the SPREAD, never the LEVEL.

    `min_a1 * min_a2 >= 1` is symmetric, so the honest pair applied in the wrong
    slots satisfies it. The result is a ceremony that is not crossed, is accepted
    on chain (maker_stake_bound.ak,
    `transposed_floors_are_accepted_on_chain_with_a_dust_ask`), and whose applied
    hash matches the address the operator hands over — with an ask floor of
    1/2_600_000 lovelace per base unit, i.e. the whole token leg for a lovelace.

    Nothing inside the ceremony can see it: the floors are raw base units, no
    parameter carries a unit, and the decimals are not on chain. Only an
    externally sourced price band can, so the tool now requires one.
    """

    @classmethod
    def setUpClass(cls):
        cls.params = dict(GOLDEN_PARAMS, **TRANSPOSED_FLOORS)
        cls.hash = applied_hash_for(cls.params)

    def test_the_on_chain_relation_accepts_the_transposition(self):
        """The premise, arithmetically: the product test is symmetric."""
        def product_ge_one(f):
            a1, a2 = f["min_asset1_price"], f["min_asset2_price"]
            return (a1["numerator"] * a2["numerator"]
                    >= a1["denominator"] * a2["denominator"])
        self.assertTrue(product_ge_one(GOLDEN_PARAMS))
        self.assertTrue(product_ge_one(self.params))
        self.assertNotEqual(self.hash, GOLDEN_APPLIED_HASH)

    def test_the_matching_address_earns_no_verdict_without_a_band(self):
        """Before the anchor existed, this exact invocation — every flag the tool
        offered, including --my-vkey-file — printed VERIFIED and exited 0."""
        rc, out, err, js = run_tool(
            self.params, extra=["--expect-script-hash", self.hash],
            band=None, decimals=None)
        self.assertNotEqual(rc, 0)
        self.assertNotIn("VERIFIED", out)

    def test_the_transposition_is_refused_against_its_own_matching_address(self):
        rc, out, err, js = run_tool(
            self.params, extra=["--expect-script-hash", self.hash])
        self.assertNotEqual(rc, 0)
        self.assertNotIn("VERIFIED", out)
        self.assertIn("TRANSPOSITION", js["error"])
        self.assertIn("2.5", js["error"])
        self.assertNotIn("derived", js)

    def test_the_refusal_reports_the_dust_ask_in_human_units(self):
        rc, out, err, js = run_tool(self.params, extra=["--derive-only"])
        self.assertNotEqual(rc, 0)
        # 1/2_600_000 lovelace per base unit at 0 decimals is 3.8e-13 ADA.
        self.assertIn("0.000000000000384", js["error"])

    def test_the_honest_ceremony_still_passes_the_same_anchor(self):
        rc, out, err, js = run_tool(GOLDEN_PARAMS, extra=golden_expectations())
        self.assertEqual(rc, 0, f"{out}\n{err}")
        self.assertEqual(js["band"]["bid_ceiling_ada_per_display_unit"], "2.6")
        self.assertEqual(js["band"]["ask_floor_ada_per_display_unit"], "2.7")
        self.assertEqual(js["band"]["anchor_ada_per_display_unit"], ["2.5", "2.8"])
        self.assertTrue(js["band"]["level_anchored"])

    def test_a_wrong_decimals_moves_the_band_by_a_million_and_is_refused(self):
        """The same floors read as a 6-decimal token are 2.6 MILLION ADA per
        token. The keeper's own branded-unit footgun, seen from the client side."""
        rc, out, err, js = run_tool(GOLDEN_PARAMS, extra=golden_expectations(),
                                    decimals=6)
        self.assertNotEqual(rc, 0)
        self.assertIn("2600000", js["error"].replace(",", ""))
        self.assertNotIn("derived", js)

    def test_derive_only_without_a_band_says_the_level_is_unchecked(self):
        rc, out, err, js = run_tool(self.params, extra=["--derive-only"], band=None)
        self.assertEqual(rc, 0, f"{out}\n{err}")
        self.assertFalse(js["band"]["level_anchored"])
        self.assertIn("NOT CHECKED: that this is the level you agreed to", out)
        self.assertNotIn("VERIFIED", out)


class VerdictInputsAreMandatory(unittest.TestCase):
    """The inputs only the client can supply are not optional for a verdict. Each
    one was a verdict-bearing hole: without a signature a bot/client swap passes,
    without the band a floor transposition passes, and without the decimals the
    band cannot be converted at all."""

    def test_decimals_is_required_even_to_derive(self):
        rc, out, err, js = run_tool(GOLDEN_PARAMS, extra=["--derive-only"],
                                    decimals=None)
        self.assertNotEqual(rc, 0)
        self.assertIn("--decimals", err)

    def test_a_nonsense_decimals_is_refused(self):
        rc, out, err, js = run_tool(GOLDEN_PARAMS, extra=["--derive-only"],
                                    decimals=-1)
        self.assertNotEqual(rc, 0)
        self.assertIn("--decimals", err)

    def test_the_band_is_required_for_a_verdict(self):
        rc, out, err, js = run_tool(GOLDEN_PARAMS, extra=golden_expectations(),
                                    band=None)
        self.assertNotEqual(rc, 0)
        self.assertIn("--expect-band-ada-per-display-unit", err)
        self.assertNotIn("VERIFIED", out)

    def test_a_detached_proof_without_the_public_half_is_refused(self):
        """A detached signature does not carry the key it was made with, so it
        cannot be checked against client_owner_vkh on its own."""
        rc, out, err, js = run_tool(GOLDEN_PARAMS, extra=golden_expectations(),
                                    vkey=None)
        self.assertNotEqual(rc, 0)
        self.assertIn("--my-vkey-file", out + err)
        self.assertNotIn("VERIFIED", out)

    def test_the_possession_proof_is_required_for_a_verdict(self):
        rc, out, err, js = run_tool(GOLDEN_PARAMS, extra=golden_expectations(),
                                    proof=None)
        self.assertNotEqual(rc, 0)
        self.assertNotIn("VERIFIED", out)
        self.assertFalse(js["checks"]["key_possession_proved"])
        self.assertEqual(js["verdict"], "refused")

    def test_derive_only_needs_none_of_them_and_asserts_nothing(self):
        rc, out, err, js = run_tool(GOLDEN_PARAMS, extra=["--derive-only"],
                                    band=None, vkey=None, proof=None)
        self.assertEqual(rc, 0, f"{out}\n{err}")
        self.assertNotIn("VERIFIED", out)
        self.assertIn("DERIVED ONLY", out)

    def test_a_malformed_band_is_refused_not_guessed(self):
        for bad in ("2.5", "2.5:", "high:low", "2.8:2.5", "0:2.8", "-1:2"):
            rc, out, err, js = run_tool(GOLDEN_PARAMS, extra=["--derive-only"],
                                        band=bad)
            self.assertNotEqual(rc, 0, f"band {bad!r} was accepted")


class ToolchainPin(unittest.TestCase):
    """The conclusion is 'these bytes are what this source compiles to', which is
    only true for one compiler and one stdlib. Both are pinned in files a client
    fetches, so both are checkable."""

    def _project_copy(self, tmp):
        proj = os.path.join(tmp, "maker_stake")
        shutil.copytree(HERE, proj, ignore=shutil.ignore_patterns("rehearsal",
                                                                 "__pycache__"))
        return proj

    def test_pinned_versions_are_reported(self):
        rc, out, err, js = run_tool(GOLDEN_PARAMS, extra=golden_expectations())
        self.assertEqual(rc, 0, f"{out}\n{err}")
        self.assertEqual(js["toolchain"]["aiken_pinned"], "v1.1.22")
        self.assertTrue(any("aiken-lang/stdlib" in p
                            for p in js["toolchain"]["locked_packages"]))
        self.assertIn("aiken.lock", out)

    def test_a_wrong_aiken_version_is_refused_not_reported(self):
        tmp = tempfile.mkdtemp(prefix="mmaas-aiken-")
        try:
            stub = os.path.join(tmp, "fake-aiken")
            with open(stub, "w") as fh:
                fh.write("#!/bin/sh\n"
                         'if [ "$1" = "--version" ]; then echo "aiken v9.9.9"; exit 0; fi\n'
                         f'exec {AIKEN} "$@"\n')
            os.chmod(stub, 0o755)
            params = write_params(GOLDEN_PARAMS, os.path.join(tmp, "p.json"))
            proc = subprocess.run(
                [sys.executable, TOOL, "--params", params, "--project", HERE,
                 "--aiken", stub, "--network", "testnet", "--derive-only",
                 "--decimals", str(DEFAULT_DECIMALS)],
                capture_output=True, text=True)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("v9.9.9", proc.stdout + proc.stderr)
            self.assertIn("v1.1.22", proc.stdout + proc.stderr)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_a_missing_aiken_lock_is_refused(self):
        tmp = tempfile.mkdtemp(prefix="mmaas-nolock-")
        try:
            proj = self._project_copy(tmp)
            os.remove(os.path.join(proj, "aiken.lock"))
            rc, out, err, js = run_tool(GOLDEN_PARAMS, project=proj,
                                        extra=["--derive-only"])
            self.assertNotEqual(rc, 0)
            self.assertIn("aiken.lock", js["error"])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_a_lock_that_does_not_pin_a_declared_dependency_is_refused(self):
        tmp = tempfile.mkdtemp(prefix="mmaas-badlock-")
        try:
            proj = self._project_copy(tmp)
            lock = os.path.join(proj, "aiken.lock")
            with open(lock) as fh:
                text = fh.read()
            with open(lock, "w") as fh:
                fh.write(text.replace("v3.1.0", "v3.0.0"))
            rc, out, err, js = run_tool(GOLDEN_PARAMS, project=proj,
                                        extra=["--derive-only"])
            self.assertNotEqual(rc, 0)
            self.assertIn("aiken.lock", js["error"])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class NetworkFlag(unittest.TestCase):

    def test_network_flag_is_required(self):
        rc, out, err, js = run_tool(GOLDEN_PARAMS, network=None, extra=["--derive-only"])
        self.assertNotEqual(rc, 0)
        self.assertIn("--network", err)

    def test_mainnet_addresses_differ_and_carry_mainnet_headers(self):
        from verify_ceremony import bech32_decode
        rc, out, err, js = run_tool(mainnet_params(), network="mainnet",
                                    extra=["--derive-only"])
        self.assertEqual(rc, 0, f"{out}\n{err}")
        order = js["derived"]["order_address"]
        reward = js["derived"]["reward_address"]
        applied = js["derived"]["applied_script_hash"]
        self.assertNotEqual(order, GOLDEN_ORDER_ADDR)
        self.assertNotEqual(reward, GOLDEN_REWARD_ADDR)
        hrp, raw = bech32_decode(order)
        self.assertEqual(hrp, "addr")
        self.assertEqual(raw, bytes([0x31]) + bytes.fromhex(GOLDEN_PARAMS["dapp_hash"])
                         + bytes.fromhex(applied))
        hrp, raw = bech32_decode(reward)
        self.assertEqual(hrp, "stake")
        self.assertEqual(raw, bytes([0xf1]) + bytes.fromhex(applied))

    def test_testnet_headers_match_cip19(self):
        from verify_ceremony import bech32_decode
        hrp, raw = bech32_decode(GOLDEN_ORDER_ADDR)
        self.assertEqual(hrp, "addr_test")
        self.assertEqual(raw, bytes([0x30]) + bytes.fromhex(GOLDEN_PARAMS["dapp_hash"])
                         + bytes.fromhex(GOLDEN_APPLIED_HASH))
        hrp, raw = bech32_decode(GOLDEN_REWARD_ADDR)
        self.assertEqual(hrp, "stake_test")
        self.assertEqual(raw, bytes([0xf0]) + bytes.fromhex(GOLDEN_APPLIED_HASH))

    def test_wrong_network_expected_address_is_a_mismatch(self):
        rc, out, err, js = run_tool(mainnet_params(), network="mainnet",
                                    extra=["--expect-order-address", GOLDEN_ORDER_ADDR])
        self.assertNotEqual(rc, 0)


class ParamsFileDiscipline(unittest.TestCase):

    def test_every_missing_param_is_refused_not_defaulted(self):
        for key in GOLDEN_PARAMS:
            p = {k: v for k, v in GOLDEN_PARAMS.items() if k != key}
            rc, out, err, js = run_tool(p, extra=["--derive-only"])
            self.assertNotEqual(rc, 0, f"missing {key} was accepted")
            self.assertIn(key, out + err)

    def test_unknown_param_is_refused(self):
        p = dict(GOLDEN_PARAMS, min_asset3_price={"numerator": 1, "denominator": 1})
        rc, out, err, js = run_tool(p, extra=["--derive-only"])
        self.assertNotEqual(rc, 0)
        self.assertIn("min_asset3_price", out + err)

    def test_malformed_hash_is_refused(self):
        p = dict(GOLDEN_PARAMS, dapp_hash="11928a3a")
        rc, out, err, js = run_tool(p, extra=["--derive-only"])
        self.assertNotEqual(rc, 0)
        self.assertIn("dapp_hash", out + err)

    def test_malformed_rational_is_refused(self):
        p = dict(GOLDEN_PARAMS, min_asset1_price="1/3000000")
        rc, out, err, js = run_tool(p, extra=["--derive-only"])
        self.assertNotEqual(rc, 0)
        self.assertIn("min_asset1_price", out + err)

    def test_verdict_requires_an_expectation_or_derive_only(self):
        rc, out, err, js = run_tool(GOLDEN_PARAMS)
        self.assertNotEqual(rc, 0)
        self.assertIn("--derive-only", err)

    def test_derive_only_cannot_masquerade_as_a_verdict(self):
        rc, out, err, js = run_tool(
            GOLDEN_PARAMS, extra=["--derive-only"] + golden_expectations())
        self.assertNotEqual(rc, 0)
        self.assertIn("asserts nothing", err)


class SourceIntegrity(unittest.TestCase):

    def _tampered_project(self, tmp, mutate):
        proj = os.path.join(tmp, "maker_stake")
        shutil.copytree(HERE, proj, ignore=shutil.ignore_patterns("rehearsal", ".git"))
        bp = os.path.join(proj, "plutus.json")
        with open(bp) as fh:
            doc = json.load(fh)
        mutate(doc)
        with open(bp, "w") as fh:
            json.dump(doc, fh, indent=2)
        return proj

    def test_tampered_compiled_code_is_caught(self):
        def mutate(doc):
            for v in doc["validators"]:
                if "bound" in v["title"]:
                    v["compiledCode"] = v["compiledCode"][:-4] + "beef"
        tmp = tempfile.mkdtemp(prefix="mmaas-tamper-")
        try:
            proj = self._tampered_project(tmp, mutate)
            rc, out, err, js = run_tool(GOLDEN_PARAMS, project=proj,
                                        extra=["--derive-only"])
            self.assertNotEqual(rc, 0)
            self.assertIn("compiledCode", out + err)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_tampered_hash_field_is_caught(self):
        def mutate(doc):
            for v in doc["validators"]:
                if "bound" in v["title"]:
                    v["hash"] = "00" * 28
        tmp = tempfile.mkdtemp(prefix="mmaas-tamper-")
        try:
            proj = self._tampered_project(tmp, mutate)
            rc, out, err, js = run_tool(GOLDEN_PARAMS, project=proj,
                                        extra=["--derive-only"])
            self.assertNotEqual(rc, 0)
            self.assertIn("hash", out + err)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_uncommitted_validator_edits_are_refused(self):
        """A commit hash only means something if the script files are AT that commit."""
        tmp = tempfile.mkdtemp(prefix="mmaas-dirty-")
        try:
            proj = os.path.join(tmp, "maker_stake")
            shutil.copytree(HERE, proj, ignore=shutil.ignore_patterns("rehearsal", ".git"))
            for args in (["init", "-q"], ["add", "-A"],
                         ["-c", "user.email=t@t", "-c", "user.name=t",
                          "commit", "-q", "-m", "baseline"]):
                subprocess.run(["git", "-C", proj] + args, check=True,
                               capture_output=True)
            rc, out, err, js = run_tool(GOLDEN_PARAMS, project=proj,
                                        extra=["--derive-only"])
            self.assertEqual(rc, 0, f"clean clone should verify:\n{out}\n{err}")
            self.assertTrue(js["provenance"]["clean"])

            with open(os.path.join(proj, "validators", "maker_stake_bound.ak"), "a") as fh:
                fh.write("\n// local edit\n")
            rc, out, err, js = run_tool(GOLDEN_PARAMS, project=proj,
                                        extra=["--derive-only"])
            self.assertNotEqual(rc, 0)
            self.assertFalse(js["provenance"]["clean"])
            self.assertIn("validators/maker_stake_bound.ak", js["provenance"]["uncommitted"])
            self.assertNotIn("derived", js)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_reordered_validator_parameters_are_caught(self):
        def mutate(doc):
            for v in doc["validators"]:
                if "bound" in v["title"]:
                    ps = v["parameters"]
                    ps[0], ps[1] = ps[1], ps[0]
        tmp = tempfile.mkdtemp(prefix="mmaas-tamper-")
        try:
            proj = self._tampered_project(tmp, mutate)
            rc, out, err, js = run_tool(GOLDEN_PARAMS, project=proj,
                                        extra=["--derive-only"])
            self.assertNotEqual(rc, 0)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


STUB_CLI = """#!/usr/bin/env python3
import json, sys
argv = sys.argv[1:]
if "utxo" in argv:
    print(json.dumps(json.loads(%(utxo)r)))
elif "stake-address-info" in argv:
    print(json.dumps(json.loads(%(stake)r)))
else:
    sys.stderr.write("unexpected query: %%s\\n" %% argv)
    sys.exit(3)
"""

# Every field below is copied from a REAL live preprod two-way order — UTxO
# 164796d5…#1 at addr_test1zqge9z3…, read back with `cardano-cli query utxo
# --output-json` on cardano-cli 11.0.0.0. A fixture that merely had "a datum"
# let --require-live call an undecodable UTxO a live order.
PAIR_BEACON = "2c973472600b564e14ae330f49bbacf6865006fc316263b1bc5329b5973828cd"
ASSET1_BEACON = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
ASSET2_BEACON = "430c6a076c362473c648fd1b7c77c9d8cfc51a10be64f5d78fa34323cd80e573"
TOKEN_POLICY = "0ff71ae2bdba25bb5e1805983c8e7924edfc77f808f4f8f6cc421ce4"
TOKEN_NAME = "4144414d4d4b54"


def swap_datum(beacon_id=GOLDEN_PARAMS["beacon_id"], pair_beacon=PAIR_BEACON,
               asset1_price=(1, 2600000), asset2_price=(2700000, 1)):
    """A two-way cardano-swaps SwapDatum in the detailed-JSON form cardano-cli
    emits for an inline datum: eight byte strings, two Rationals, two Options."""
    def rational(pair):
        return {"constructor": 0,
                "fields": [{"int": pair[0]}, {"int": pair[1]}]}
    return {"constructor": 0, "fields": [
        {"bytes": beacon_id}, {"bytes": pair_beacon},
        {"bytes": ""}, {"bytes": ""}, {"bytes": ASSET1_BEACON},
        {"bytes": TOKEN_POLICY}, {"bytes": TOKEN_NAME}, {"bytes": ASSET2_BEACON},
        rational(asset1_price), rational(asset2_price),
        {"constructor": 1, "fields": []},   # prev_input: None
        {"constructor": 1, "fields": []},   # expiration: None
    ]}


def order_utxo(txin, datum, beacons=(PAIR_BEACON, ASSET1_BEACON, ASSET2_BEACON),
               lovelace=4000000):
    value = {"lovelace": lovelace, TOKEN_POLICY: {TOKEN_NAME: 250}}
    if beacons:
        value[GOLDEN_PARAMS["beacon_id"]] = {name: 1 for name in beacons}
    return json.dumps({txin: {
        "inlineDatum": datum, "inlineDatumhash": "cc" * 32, "datum": None,
        "referenceScript": None, "value": value}})


LIVE_ORDER_UTXO = order_utxo("aa" * 32 + "#0", swap_datum())
FUNDED_UTXO = LIVE_ORDER_UTXO

# The auditor's case: an inline datum that is the bare integer 1. It exists, so a
# presence check called it a live order and exited 0.
BARE_INT_DATUM_UTXO = order_utxo("a1" * 32 + "#0", {"int": 1})

# Decodable, beacon-bearing, but the datum names a DIFFERENT beacon policy, so
# the dApp does not read it as an order for this pair.
WRONG_BEACON_DATUM_UTXO = order_utxo("a2" * 32 + "#0", swap_datum(beacon_id="ab" * 28))

# The datum names a pair beacon the UTxO does not hold.
MISSING_PAIR_BEACON_UTXO = order_utxo(
    "a3" * 32 + "#0", swap_datum(pair_beacon="cd" * 32))

# Negative numerator AND denominator: the ratio is positive, but the sign flip
# inverts every cross-multiplied floor comparison the validator makes.
NEGATIVE_PRICE_DATUM_UTXO = order_utxo(
    "a4" * 32 + "#0", swap_datum(asset2_price=(-2700000, -1)))

# What a client produces by taking "fund this address" literally: a plain wallet
# payment to a script address. No datum, so no script input can ever be built
# from it — the deposit is gone, and --require-live used to call it healthy.
DATUMLESS_UTXO = json.dumps({
    "bb" * 32 + "#1": {"datum": None, "inlineDatum": None, "inlineDatumRaw": None,
                       "referenceScript": None, "value": {"lovelace": 2000000}},
})

# Datum-bearing, beacon-bearing — but the datum is a HASH, which the
# cardano-swaps order form does not read.
DATUM_HASH_UTXO = json.dumps({
    "cc" * 32 + "#2": {
        "datum": None, "inlineDatum": None, "datumhash": "dd" * 32,
        "referenceScript": None,
        "value": {"lovelace": 4000000,
                  GOLDEN_PARAMS["beacon_id"]: {PAIR_BEACON: 1, ASSET1_BEACON: 1}}},
})

# An inline datum but no beacons: a leftover, not a quotable order.
NO_BEACON_UTXO = order_utxo("ee" * 32 + "#0", swap_datum(), beacons=())
REGISTERED = json.dumps([{"stakeRegistrationDeposit": 2000000, "stakeDelegation": None,
                          "voteDelegation": None, "rewardAccountBalance": 0}])
DELEGATED = json.dumps([{"stakeRegistrationDeposit": 2000000,
                         "stakeDelegation": "pool1operatorownspool000000000000000000000000000000000000",
                         "voteDelegation": None, "rewardAccountBalance": 431_000}])
VOTE_DELEGATED = json.dumps([{"stakeRegistrationDeposit": 2000000,
                              "stakeDelegation": None,
                              "voteDelegation": {"keyHash": "ab" * 28},
                              "rewardAccountBalance": 0}])


class ChainConfirmation(unittest.TestCase):
    """--check-chain is optional; the tool is complete without it, loud with it."""

    def _stub(self, tmp, utxo, stake):
        path = os.path.join(tmp, "stub-cardano-cli")
        with open(path, "w") as fh:
            fh.write(STUB_CLI % {"utxo": utxo, "stake": stake})
        os.chmod(path, 0o755)
        return path

    def test_tool_is_complete_offline_even_with_no_usable_cardano_cli(self):
        rc, out, err, js = run_tool(
            GOLDEN_PARAMS,
            extra=golden_expectations() + ["--cardano-cli", "/nonexistent/cardano-cli"])
        self.assertEqual(rc, 0, f"{out}\n{err}")
        self.assertNotIn("chain", js)

    def test_check_chain_reports_holdings_and_registration(self):
        tmp = tempfile.mkdtemp(prefix="mmaas-stub-")
        try:
            cli = self._stub(tmp, FUNDED_UTXO, REGISTERED)
            rc, out, err, js = run_tool(
                GOLDEN_PARAMS,
                extra=golden_expectations() + ["--check-chain", "--require-live",
                                               "--cardano-cli", cli])
            self.assertEqual(rc, 0, f"{out}\n{err}")
            self.assertTrue(js["chain"]["stake_credential_registered"])
            self.assertEqual(js["chain"]["order_address_utxo_count"], 1)
            self.assertEqual(js["chain"]["order_address_holdings"]["lovelace"], 4000000)
            self.assertEqual(
                js["chain"]["order_address_holdings"][
                    "0ff71ae2bdba25bb5e1805983c8e7924edfc77f808f4f8f6cc421ce4.4144414d4d4b54"],
                250)
            self.assertEqual(len(js["chain"]["live_order_utxos"]), 1)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_require_live_fails_on_an_unregistered_credential(self):
        tmp = tempfile.mkdtemp(prefix="mmaas-stub-")
        try:
            cli = self._stub(tmp, FUNDED_UTXO, "[]")
            rc, out, err, js = run_tool(
                GOLDEN_PARAMS,
                extra=golden_expectations() + ["--check-chain", "--require-live",
                                               "--cardano-cli", cli])
            self.assertNotEqual(rc, 0)
            self.assertIn("not registered", " ".join(js["chain_failures"]))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_require_live_fails_on_an_empty_order_address(self):
        tmp = tempfile.mkdtemp(prefix="mmaas-stub-")
        try:
            cli = self._stub(tmp, "{}", REGISTERED)
            rc, out, err, js = run_tool(
                GOLDEN_PARAMS,
                extra=golden_expectations() + ["--check-chain", "--require-live",
                                               "--cardano-cli", cli])
            self.assertNotEqual(rc, 0)
            self.assertIn("holds nothing", " ".join(js["chain_failures"]))
            # A matching address that is merely unfunded is not a wrong script,
            # and the report must not say it is.
            self.assertEqual(js["mismatches"], [])
            self.assertNotIn("DO NOT FUND THIS ADDRESS", out)
            self.assertIn("The ceremony itself checks out", out)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_a_wrong_address_still_says_do_not_fund_it(self):
        tmp = tempfile.mkdtemp(prefix="mmaas-stub-")
        try:
            cli = self._stub(tmp, LIVE_ORDER_UTXO, REGISTERED)
            rc, out, err, js = run_tool(
                GOLDEN_PARAMS,
                extra=["--expect-script-hash", "00" * 28, "--check-chain",
                       "--require-live", "--cardano-cli", cli])
            self.assertNotEqual(rc, 0)
            self.assertIn("DO NOT FUND THIS ADDRESS", out)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_require_live_fails_on_a_datumless_deposit(self):
        """The tool tells the client to fund a SCRIPT address. A plain payment
        there carries no datum, so no script input can ever be built from it and
        the deposit is unrecoverable — by SaturnSwap, by the escape-hatch key, by
        anyone. --require-live used to report exactly this as live."""
        tmp = tempfile.mkdtemp(prefix="mmaas-stub-")
        try:
            cli = self._stub(tmp, DATUMLESS_UTXO, REGISTERED)
            rc, out, err, js = run_tool(
                GOLDEN_PARAMS,
                extra=golden_expectations() + ["--check-chain", "--require-live",
                                               "--cardano-cli", cli])
            self.assertNotEqual(rc, 0)
            self.assertNotIn("VERIFIED", out)
            failures = " ".join(js["chain_failures"])
            self.assertIn("carries NO datum", failures)
            self.assertIn("unrecoverable", failures)
            self.assertEqual(js["chain"]["unspendable_utxos"], ["bb" * 32 + "#1"])
            self.assertEqual(js["chain"]["live_order_utxos"], [])
            self.assertIn("UNSPENDABLE", out)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_require_live_fails_on_a_datum_hash_utxo(self):
        tmp = tempfile.mkdtemp(prefix="mmaas-stub-")
        try:
            cli = self._stub(tmp, DATUM_HASH_UTXO, REGISTERED)
            rc, out, err, js = run_tool(
                GOLDEN_PARAMS,
                extra=golden_expectations() + ["--check-chain", "--require-live",
                                               "--cardano-cli", cli])
            self.assertNotEqual(rc, 0)
            self.assertIn("datum HASH", " ".join(js["chain_failures"]))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_require_live_fails_when_nothing_carries_the_pair_beacon(self):
        tmp = tempfile.mkdtemp(prefix="mmaas-stub-")
        try:
            cli = self._stub(tmp, NO_BEACON_UTXO, REGISTERED)
            rc, out, err, js = run_tool(
                GOLDEN_PARAMS,
                extra=golden_expectations() + ["--check-chain", "--require-live",
                                               "--cardano-cli", cli])
            self.assertNotEqual(rc, 0)
            self.assertIn("is a live order", " ".join(js["chain_failures"]))
            self.assertIn(GOLDEN_PARAMS["beacon_id"], " ".join(js["chain_failures"]))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def _refuses(self, utxo, expected):
        tmp = tempfile.mkdtemp(prefix="mmaas-stub-")
        try:
            cli = self._stub(tmp, utxo, REGISTERED)
            rc, out, err, js = run_tool(
                GOLDEN_PARAMS,
                extra=golden_expectations() + ["--check-chain", "--require-live",
                                               "--cardano-cli", cli])
            self.assertNotEqual(rc, 0, f"{out}\n{err}")
            self.assertEqual(js["chain"]["live_order_utxos"], [])
            self.assertIn(expected, " ".join(js["chain_failures"]))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_require_live_fails_on_a_datum_that_is_not_a_swap_datum(self):
        """A datum that merely EXISTS is not an order. Checking presence alone let
        --require-live exit 0 calling the bare integer 1 a live order — which a
        client reads as 'my inventory is resting and quotable'."""
        self._refuses(BARE_INT_DATUM_UTXO, "not a constructor-0 value")

    def test_require_live_fails_when_the_datum_names_another_beacon_policy(self):
        self._refuses(WRONG_BEACON_DATUM_UTXO, "names beacon policy")

    def test_require_live_fails_when_the_pair_beacon_named_is_not_held(self):
        self._refuses(MISSING_PAIR_BEACON_UTXO, "does not hold the pair beacon")

    def test_require_live_fails_on_a_negatively_signed_price(self):
        """Both parts negative, so the ratio still reads positive — but the
        validator cross-multiplies, and that only preserves the direction of a
        comparison for positive rationals."""
        self._refuses(NEGATIVE_PRICE_DATUM_UTXO, "refuses a non-positive price")

    def test_a_real_two_way_swap_datum_is_accepted(self):
        """The counterpart: the fixture above is a real live preprod order, so the
        tightened check must not have made every order unrecognisable."""
        tmp = tempfile.mkdtemp(prefix="mmaas-stub-")
        try:
            cli = self._stub(tmp, LIVE_ORDER_UTXO, REGISTERED)
            rc, out, err, js = run_tool(
                GOLDEN_PARAMS,
                extra=golden_expectations() + ["--check-chain", "--require-live",
                                               "--cardano-cli", cli])
            self.assertEqual(rc, 0, f"{out}\n{err}")
            self.assertEqual(js["chain"]["live_order_utxos"], ["aa" * 32 + "#0"])
            self.assertEqual(js["chain"]["malformed_datum_utxos"], [])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_the_report_says_how_the_address_must_be_funded(self):
        """'Fund this and nothing else' is not an instruction a client can follow
        with a wallet, and the report must not read like one."""
        rc, out, err, js = run_tool(GOLDEN_PARAMS, extra=golden_expectations())
        self.assertEqual(rc, 0, f"{out}\n{err}")
        self.assertIn("PERMANENTLY UNSPENDABLE", out)
        self.assertIn("CREATE transaction", out)
        self.assertIn("INLINE SwapDatum", out)
        self.assertIn(GOLDEN_PARAMS["beacon_id"], out)

    def test_delegation_is_printed_not_silently_collected(self):
        """B8: only the escape-hatch key may publish a delegation certificate, so a
        delegation the client did not sign means the on-chain script is not this
        source — and it is the trigger for every `+0` withdrawal breaking."""
        tmp = tempfile.mkdtemp(prefix="mmaas-stub-")
        try:
            cli = self._stub(tmp, FUNDED_UTXO, DELEGATED)
            rc, out, err, js = run_tool(
                GOLDEN_PARAMS,
                extra=golden_expectations() + ["--check-chain", "--cardano-cli", cli])
            self.assertIn("stake delegation", out)
            self.assertIn("pool1operatorownspool", out)
            self.assertIn("vote delegation", out)
            self.assertEqual(js["chain"]["reward_account_balance"], 431_000)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_require_live_fails_on_an_unexpected_stake_delegation(self):
        tmp = tempfile.mkdtemp(prefix="mmaas-stub-")
        try:
            cli = self._stub(tmp, FUNDED_UTXO, DELEGATED)
            rc, out, err, js = run_tool(
                GOLDEN_PARAMS,
                extra=golden_expectations() + ["--check-chain", "--require-live",
                                               "--cardano-cli", cli])
            self.assertNotEqual(rc, 0)
            self.assertIn("delegated to pool", " ".join(js["chain_failures"]))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_require_live_fails_on_an_unexpected_vote_delegation(self):
        tmp = tempfile.mkdtemp(prefix="mmaas-stub-")
        try:
            cli = self._stub(tmp, FUNDED_UTXO, VOTE_DELEGATED)
            rc, out, err, js = run_tool(
                GOLDEN_PARAMS,
                extra=golden_expectations() + ["--check-chain", "--require-live",
                                               "--cardano-cli", cli])
            self.assertNotEqual(rc, 0)
            self.assertIn("governance vote", " ".join(js["chain_failures"]))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_require_live_without_check_chain_is_refused(self):
        rc, out, err, js = run_tool(
            GOLDEN_PARAMS, extra=golden_expectations() + ["--require-live"])
        self.assertNotEqual(rc, 0)
        self.assertIn("--check-chain", err)

    def test_a_broken_chain_query_refuses_instead_of_passing_silently(self):
        rc, out, err, js = run_tool(
            GOLDEN_PARAMS,
            extra=golden_expectations() + ["--check-chain",
                                           "--cardano-cli", "/bin/false"])
        self.assertNotEqual(rc, 0)
        self.assertIn("cardano-cli", js["error"])


class MachineReadableOutput(unittest.TestCase):

    def test_json_to_stdout_is_a_single_parseable_line(self):
        tmp = tempfile.mkdtemp(prefix="mmaas-json-")
        try:
            params_path = write_params(GOLDEN_PARAMS, os.path.join(tmp, "params.json"))
            vk = write_vkey(CLIENT_VKEY_ENVELOPE, os.path.join(tmp, "client.vkey"))
            pf = os.path.join(tmp, "possession.proof")
            with open(pf, "w") as fh:
                fh.write(committed_proof(GOLDEN_PARAMS).hex())
            proc = subprocess.run(
                [sys.executable, TOOL, "--params", params_path, "--project", HERE,
                 "--aiken", AIKEN, "--network", "testnet", "--json-out", "-",
                 "--decimals", str(DEFAULT_DECIMALS),
                 "--expect-band-ada-per-display-unit", DEFAULT_BAND,
                 "--my-vkey-file", vk, "--possession-proof", pf]
                + golden_expectations(), capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(len(proc.stdout.strip().splitlines()), 1)
            js = json.loads(proc.stdout)
            self.assertTrue(js["ok"])
            self.assertEqual(js["derived"]["order_address"], GOLDEN_ORDER_ADDR)
            self.assertIn("STEP 1", proc.stderr)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_json_is_emitted_even_on_refusal(self):
        p = {k: v for k, v in GOLDEN_PARAMS.items() if k != "beacon_id"}
        rc, out, err, js = run_tool(p, extra=["--derive-only"])
        self.assertNotEqual(rc, 0)
        self.assertFalse(js["ok"])
        self.assertIn("beacon_id", js["error"])

    def test_json_carries_the_fields_the_verification_panel_shows(self):
        rc, out, err, js = run_tool(GOLDEN_PARAMS, extra=golden_expectations())
        self.assertEqual(rc, 0)
        for key in ("ok", "network", "derived", "other_network", "applied_parameters",
                    "source_integrity", "comparisons", "mismatches", "provenance",
                    "repo_commit", "payout_address_detail", "applied_script_size_bytes",
                    "band", "toolchain", "decimals", "my_vkh"):
            self.assertIn(key, js)
        self.assertEqual(js["payout_address_detail"]["payment_kind"], "key")
        self.assertEqual(js["other_network"]["network"], "mainnet")


class DataEncoder(unittest.TestCase):
    """The Plutus Data encodings must match the schema the blueprint declares."""

    def test_enterprise_payout_matches_rehearsal_hex(self):
        from verify_ceremony import address_to_plutus_data
        data, _ = address_to_plutus_data(GOLDEN_PARAMS["client_payout_address"], "testnet")
        self.assertEqual(data.hex(), GOLDEN_PAYOUT_CBOR)

    def test_base_payout_encodes_inline_stake_credential(self):
        from verify_ceremony import address_to_plutus_data
        # Base address: same payment key hash, delegated to a stake KEY hash.
        pay = GOLDEN_PARAMS["client_owner_vkh"]
        stake = "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f"
        from verify_ceremony import bech32_encode
        addr = bech32_encode("addr_test",
                             bytes([0x00]) + bytes.fromhex(pay) + bytes.fromhex(stake))
        data, info = address_to_plutus_data(addr, "testnet")
        # Constr(0,[Constr(0,[pay]), Constr(0,[Constr(0,[Constr(0,[stake])])])])
        expected = ("d8799f" "d8799f" f"581c{pay}" "ff"
                    "d8799f" "d8799f" "d8799f" f"581c{stake}" "ff" "ff" "ff" "ff")
        self.assertEqual(data.hex(), expected)
        self.assertEqual(info["stake_kind"], "key")

    def test_rational_encoding_matches_aiken_serialise(self):
        from verify_ceremony import rational_to_plutus_data
        # cbor.serialise(LegacyRational{1, 2_500_000}) == d8799f011a002625a0ff,
        # pinned by the validator's golden two-way datum.
        self.assertEqual(rational_to_plutus_data(1, 2_500_000).hex(), "d8799f011a002625a0ff")
        self.assertEqual(rational_to_plutus_data(2_500_000, 1).hex(), "d8799f1a002625a001ff")

    def test_integer_encoding_covers_both_cbor_signs_and_widths(self):
        from verify_ceremony import data_int, CeremonyError
        for value, expected in [(0, "00"), (23, "17"), (24, "1818"), (255, "18ff"),
                                (256, "190100"), (-1, "20"), (-25, "3818"),
                                (2_000_000, "1a001e8480"),
                                # past 64 bits CBOR tags a byte string; aiken accepts
                                # these, so refusing them was refusing to derive an
                                # address the validator can be parameterised with
                                (2 ** 64, "c249010000000000000000"),
                                (-2 ** 64 - 1, "c349010000000000000000")]:
            self.assertEqual(data_int(value).hex(), expected, f"for {value}")
        with self.assertRaises(CeremonyError):
            data_int("7")

    def test_a_pointer_address_is_encoded_not_refused(self):
        """fee_address is operator-chosen and a pointer address is a legal Plutus
        Address, so a refusal here was a client recovery an operator could brick
        by picking an exotic address form."""
        from verify_ceremony import address_to_plutus_data, bech32_encode
        addr = bech32_encode("addr_test", bytes([0x40]) + b"\x01" * 28 + b"\x02\x03\x04")
        data, info = address_to_plutus_data(addr, "testnet")
        self.assertEqual(info["stake_kind"], "pointer")
        self.assertEqual(info["pointer"], [2, 3, 4])
        self.assertTrue(data)

    def test_bech32_roundtrip(self):
        from verify_ceremony import bech32_encode, bech32_decode
        raw = bytes([0x30]) + bytes.fromhex(GOLDEN_PARAMS["dapp_hash"]) \
            + bytes.fromhex(GOLDEN_APPLIED_HASH)
        self.assertEqual(bech32_encode("addr_test", raw), GOLDEN_ORDER_ADDR)
        self.assertEqual(bech32_decode(GOLDEN_ORDER_ADDR), ("addr_test", raw))

    def test_bech32_rejects_a_corrupted_checksum(self):
        from verify_ceremony import bech32_decode, CeremonyError
        bad = GOLDEN_REWARD_ADDR[:-1] + ("q" if GOLDEN_REWARD_ADDR[-1] != "q" else "p")
        with self.assertRaises(CeremonyError):
            bech32_decode(bad)


class EscapeKeyPossession(unittest.TestCase):
    """A verification key is PUBLIC. Hashing the file the operator sent proves that
    the file hashes to client_owner_vkh and nothing else — least of all who holds the
    signing half.

    This is that ceremony: the OPERATOR generated the keypair, kept the .skey and
    handed the client the .vkey. Every coherence rule passes, the payout address is
    the key's own, the applied hash is exactly what the operator published — and the
    operator keeps the escape hatch. A verdict here is a lie, so there must not be
    one without a signature."""

    @classmethod
    def setUpClass(cls):
        cls.params = dict(
            GOLDEN_PARAMS,
            client_owner_vkh=OPERATOR_KEYPAIR_VKH,
            client_payout_address=enterprise_addr(OPERATOR_KEYPAIR_VKH))
        cls.hash = applied_hash_for(cls.params)

    def test_the_ceremony_is_coherent_and_its_address_matches(self):
        """The premise: nothing short of a signature objects to it."""
        rc, out, err, js = run_tool(self.params, extra=["--derive-only"],
                                    vkey=OPERATOR_VKEY_ENVELOPE, proof=None)
        self.assertEqual(rc, 0, f"{out}\n{err}")
        self.assertEqual(js["derived"]["applied_script_hash"], self.hash)
        self.assertFalse(js["band"]["band_is_crossed"])

    def test_a_vkey_file_alone_earns_no_verdict(self):
        """The defect: this exact invocation printed VERIFIED and exited 0 for a key
        whose signing half the client has never held."""
        rc, out, err, js = run_tool(
            self.params, vkey=OPERATOR_VKEY_ENVELOPE, proof=None,
            extra=["--expect-script-hash", self.hash])
        self.assertNotEqual(rc, 0, f"{out}\n{err}")
        self.assertNotIn("VERIFIED", out)
        self.assertNotEqual(js.get("verdict"), "verified")
        self.assertFalse(js["checks"]["key_possession_proved"])

    def test_the_refusal_prints_the_challenge_and_how_to_sign_it(self):
        """A refusal a client cannot act on is a refusal they will route around."""
        rc, out, err, js = run_tool(
            self.params, vkey=OPERATOR_VKEY_ENVELOPE, proof=None,
            extra=["--expect-script-hash", self.hash])
        self.assertIn(js["possession_challenge"], out)
        self.assertIn("cardano-cli conway transaction witness", out)
        self.assertIn("--possession-proof", out)

    def test_a_signature_by_the_named_key_earns_the_verdict(self):
        """Whoever holds the signing half can pass — that is the whole property. The
        operator's key here is a PUBLISHED RFC 8032 vector, so this test can hold both
        halves and demonstrate the check accepts a genuine proof."""
        proof = sign_possession(self.params, RFC8032_VEC1_SEED)
        rc, out, err, js = run_tool(
            self.params, vkey=OPERATOR_VKEY_ENVELOPE, proof=proof,
            extra=["--expect-script-hash", self.hash])
        self.assertEqual(rc, 0, f"{out}\n{err}")
        self.assertEqual(js["verdict"], "verified")
        self.assertTrue(js["checks"]["key_possession_proved"])

    def test_a_signature_over_another_ceremony_is_refused(self):
        """The challenge is bound to THIS ceremony, so a proof minted for a different
        one — a stale file, or one the operator kept from an earlier round — cannot be
        replayed into it."""
        other = dict(self.params, min_asset2_price={"numerator": 2800000,
                                                    "denominator": 1})
        proof = sign_possession(other, RFC8032_VEC1_SEED)
        rc, out, err, js = run_tool(
            self.params, vkey=OPERATOR_VKEY_ENVELOPE, proof=proof,
            extra=["--expect-script-hash", self.hash])
        self.assertNotEqual(rc, 0, f"{out}\n{err}")
        self.assertNotIn("VERIFIED", out)
        self.assertIn("does not sign this ceremony", js["error"])

    def test_a_tampered_signature_is_refused(self):
        proof = bytearray(sign_possession(self.params, RFC8032_VEC1_SEED))
        proof[-1] ^= 0x01
        rc, out, err, js = run_tool(
            self.params, vkey=OPERATOR_VKEY_ENVELOPE, proof=bytes(proof),
            extra=["--expect-script-hash", self.hash])
        self.assertNotEqual(rc, 0, f"{out}\n{err}")
        self.assertNotIn("VERIFIED", out)

    def test_a_signature_by_a_different_key_is_refused(self):
        """Signing the right challenge with the wrong key proves possession of the
        wrong key."""
        proof = sign_possession(self.params, RFC8032_VEC2_SEED)
        rc, out, err, js = run_tool(
            self.params, vkey=OPERATOR_VKEY_ENVELOPE, proof=proof,
            extra=["--expect-script-hash", self.hash])
        self.assertNotEqual(rc, 0, f"{out}\n{err}")
        self.assertNotIn("VERIFIED", out)


class Ed25519Verifier(unittest.TestCase):
    """The possession check is only worth its verifier. Pinned against RFC 8032's
    own published vectors — an oracle written by the standard, not by this repo —
    and against a witness a real `cardano-cli conway transaction witness` produced,
    so the wire format is pinned too."""

    def test_the_rfc_8032_vectors_verify(self):
        from verify_ceremony import ed25519_verify
        for i, (_, public, message, signature) in enumerate(RFC8032_VECTORS, 1):
            self.assertTrue(
                ed25519_verify(bytes.fromhex(public), bytes.fromhex(message),
                               bytes.fromhex(signature)), f"vector {i}")

    def test_a_tampered_rfc_8032_signature_is_rejected(self):
        from verify_ceremony import ed25519_verify
        for i, (_, public, message, signature) in enumerate(RFC8032_VECTORS, 1):
            for bit in (0, 255, 256, 511):
                raw = bytearray(bytes.fromhex(signature))
                raw[bit // 8] ^= 1 << (bit % 8)
                self.assertFalse(
                    ed25519_verify(bytes.fromhex(public), bytes.fromhex(message),
                                   bytes(raw)), f"vector {i} bit {bit}")

    def test_a_signature_over_a_different_message_is_rejected(self):
        from verify_ceremony import ed25519_verify
        for _, public, message, signature in RFC8032_VECTORS:
            self.assertFalse(ed25519_verify(bytes.fromhex(public),
                                            bytes.fromhex(message) + b"\x00",
                                            bytes.fromhex(signature)))

    def test_a_signature_by_a_different_key_is_rejected(self):
        from verify_ceremony import ed25519_verify
        _, _, message, signature = RFC8032_VECTORS[0]
        other = RFC8032_VECTORS[1][1]
        self.assertFalse(ed25519_verify(bytes.fromhex(other), bytes.fromhex(message),
                                        bytes.fromhex(signature)))

    def test_malformed_keys_and_signatures_are_rejected_not_crashed(self):
        from verify_ceremony import ed25519_verify
        _, public, message, signature = RFC8032_VECTORS[0]
        for bad_key in (b"", b"\x00" * 31, b"\xff" * 32):
            self.assertFalse(ed25519_verify(bad_key, bytes.fromhex(message),
                                            bytes.fromhex(signature)))
        for bad_sig in (b"", b"\x00" * 63, b"\xff" * 64):
            self.assertFalse(ed25519_verify(bytes.fromhex(public),
                                            bytes.fromhex(message), bad_sig))

    def test_the_test_suites_own_signer_reproduces_the_rfc_vectors(self):
        """The signer above mints every proof these tests offer. If it drifted from
        the standard, the possession tests would only agree with themselves."""
        for i, (seed, public, message, signature) in enumerate(RFC8032_VECTORS, 1):
            self.assertEqual(ed25519_public(bytes.fromhex(seed)).hex(), public,
                             f"vector {i} public key")
            self.assertEqual(
                ed25519_sign(bytes.fromhex(seed), bytes.fromhex(message)).hex(),
                signature, f"vector {i} signature")


# The eight small-order (torsion) ed25519 point encodings libsodium's
# ge25519_has_small_order refuses. RFC 8032's own vectors never touch this
# subgroup, so a hand-rolled happy-path verifier passes every published vector
# while accepting a universal forgery: for the identity point A, 0*B == identity
# == R + k*identity, so the fixed 64-byte constant below "signs" any message.
ED25519_SMALL_ORDER_POINTS = [
    "0100000000000000000000000000000000000000000000000000000000000000",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000080",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
]
ED25519_IDENTITY_VKEY = "01" + "00" * 31
ED25519_IDENTITY_FORGERY = "01" + "00" * 31 + "00" * 32


class Ed25519Soundness(unittest.TestCase):
    """cardano-node verifies witnesses with libsodium, which refuses small-order
    points and non-canonical scalars. A possession verifier that accepts what the
    ledger would reject endorses a key whose private half nobody holds — and whose
    payout address is therefore permanently unspendable. These are the cases RFC
    8032's happy-path vectors miss."""

    def _verify(self, vkey_hex, msg, sig_hex):
        from verify_ceremony import ed25519_verify
        return ed25519_verify(bytes.fromhex(vkey_hex), msg, bytes.fromhex(sig_hex))

    def test_the_universal_small_order_forgery_is_rejected(self):
        for msg in (b"", b"\x00" * 32, b"whatever bytes the operator likes"):
            self.assertFalse(
                self._verify(ED25519_IDENTITY_VKEY, msg, ED25519_IDENTITY_FORGERY),
                f"identity-point forgery accepted over {msg!r}")

    def test_libsodium_is_the_verifier_when_present(self):
        """The vetted primitive must be the one taken where it exists. A client
        with nothing but python3 has no PyNaCl and is covered by the fallback
        test below, so this asserts the preference rather than the presence."""
        import verify_ceremony as vc
        try:
            import nacl.signing
        except ImportError:
            self.skipTest("PyNaCl absent; the pure fallback carries the check")
        self.assertIs(vc._NACL_SIGNING, nacl.signing)

    def test_the_pure_fallback_rejects_the_forgery_on_its_own(self):
        """A client running the tool with nothing but python3 uses the in-repo
        verifier; it must reject the forgery without libsodium present."""
        from verify_ceremony import _ed25519_verify_pure
        self.assertFalse(_ed25519_verify_pure(
            bytes.fromhex(ED25519_IDENTITY_VKEY), b"\x00" * 32,
            bytes.fromhex(ED25519_IDENTITY_FORGERY)))

    def test_a_small_order_key_with_a_wellformed_r_is_rejected(self):
        """Isolates the small-order rejection on the KEY: A = identity, R = B (a
        normal, non-torsion point), S = 1. Then s*B == B == R + k*identity for any
        message, so only refusing the small-order key stops it — the R check does
        not fire here."""
        from verify_ceremony import _ed25519_verify_pure, ed25519_verify
        base_point = "5866666666666666666666666666666666666666666666666666666666666666"
        forgery = base_point + ("01" + "00" * 31)  # R = B, S = 1
        for msg in (b"", b"a chosen message"):
            self.assertFalse(ed25519_verify(
                bytes.fromhex(ED25519_IDENTITY_VKEY), msg, bytes.fromhex(forgery)))
            self.assertFalse(_ed25519_verify_pure(
                bytes.fromhex(ED25519_IDENTITY_VKEY), msg, bytes.fromhex(forgery)))

    def test_a_genuine_signature_verifies_on_both_the_vetted_and_pure_paths(self):
        from verify_ceremony import _ed25519_verify_pure
        _, public, message, signature = RFC8032_VECTORS[1]
        self.assertTrue(self._verify(public, bytes.fromhex(message), signature))
        self.assertTrue(_ed25519_verify_pure(
            bytes.fromhex(public), bytes.fromhex(message), bytes.fromhex(signature)))

    def test_a_high_s_malleability_variant_is_rejected_on_both_paths(self):
        """(R, S) mauled to (R, S+L): S must be canonical (< L)."""
        from verify_ceremony import _ED_L, _ed25519_verify_pure
        _, public, message, signature = RFC8032_VECTORS[1]
        raw = bytes.fromhex(signature)
        mauled = raw[:32] + int.to_bytes(
            int.from_bytes(raw[32:], "little") + _ED_L, 32, "little")
        self.assertFalse(self._verify(public, bytes.fromhex(message), mauled.hex()))
        self.assertFalse(_ed25519_verify_pure(
            bytes.fromhex(public), bytes.fromhex(message), mauled))

    def test_a_non_canonical_point_encoding_is_refused_by_the_decoder(self):
        from verify_ceremony import _ED_P, _ed_decompress
        self.assertIsNone(_ed_decompress(int.to_bytes(_ED_P, 32, "little")))

    def test_every_small_order_owner_key_earns_no_verdict_and_names_the_problem(self):
        """Each torsion point offered as the escape-hatch key with the published
        forgery must be refused as unusable — not accepted (identity), and not
        refused for the wrong reason (the others)."""
        from verify_ceremony import check_possession, vkh, CeremonyError
        for enc in ED25519_SMALL_ORDER_POINTS:
            owner = vkh(bytes.fromhex(enc))
            tmp = tempfile.mkdtemp(prefix="mmaas-smallorder-")
            try:
                vkey_path = write_vkey(
                    {"type": "PaymentVerificationKeyShelley_ed25519",
                     "description": "", "cborHex": "5820" + enc},
                    os.path.join(tmp, "k.vkey"))
                proof_path = os.path.join(tmp, "p.proof")
                with open(proof_path, "w") as fh:
                    fh.write(ED25519_IDENTITY_FORGERY + "\n")
                with self.assertRaises(CeremonyError) as caught:
                    check_possession(owner, b"\x00" * 32, proof_path, None,
                                     vkey_path, ["false"])
                self.assertRegex(str(caught.exception),
                                 "small-order|not a usable Cardano key")
            finally:
                shutil.rmtree(tmp, ignore_errors=True)

    def test_the_tool_refuses_the_identity_point_forgery_end_to_end(self):
        """The leads' executed attack: a ceremony naming the identity point as the
        escape key, coherent in every other respect, with the published forgery as
        its possession proof. The pristine tool printed VERIFIED; it must not."""
        from verify_ceremony import vkh
        owner = vkh(bytes.fromhex(ED25519_IDENTITY_VKEY))
        params = dict(GOLDEN_PARAMS, client_owner_vkh=owner,
                      client_payout_address=enterprise_addr(owner))
        rc, out, err, js = run_tool(
            params,
            vkey={"type": "PaymentVerificationKeyShelley_ed25519",
                  "description": "", "cborHex": "5820" + ED25519_IDENTITY_VKEY},
            proof=bytes.fromhex(ED25519_IDENTITY_FORGERY),
            extra=["--expect-script-hash", applied_hash_for(params)])
        self.assertNotEqual(rc, 0, f"{out}\n{err}")
        self.assertNotIn("VERIFIED", out)
        self.assertNotEqual(js.get("verdict"), "verified")
        self.assertFalse(js["checks"]["key_possession_proved"])


class EmitAppliedScript(unittest.TestCase):
    """The escape hatch withdraws the bound credential's reward account, and that
    withdraw-0 must be witnessed by the EXACT applied script this ceremony verified.
    Emitting it here is what lets the client build the escape without taking a
    .plutus from the operator."""

    def test_the_emitted_script_hashes_to_the_verified_credential(self):
        tmp = tempfile.mkdtemp(prefix="mmaas-emit-script-")
        try:
            out = os.path.join(tmp, "bound.plutus")
            rc, _, err, js = run_tool(
                GOLDEN_PARAMS, extra=["--derive-only", "--emit-applied-script", out],
                vkey=None, proof=None)
            self.assertEqual(rc, 0, err)
            env = json.load(open(out))
            self.assertEqual(env["type"], "PlutusScriptV3")
            raw = bytes.fromhex(env["cborHex"])
            self.assertEqual(raw[0], 0x59, "one CBOR bytestring wrapping the compiled code")
            inner = raw[3:]
            self.assertEqual(len(inner), int.from_bytes(raw[1:3], "big"))
            got = hashlib.blake2b(b"\x03" + inner, digest_size=28).hexdigest()
            self.assertEqual(got, js["derived"]["applied_script_hash"])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class PossessionChallenge(unittest.TestCase):
    """The challenge is delivered AS a transaction body, because stock cardano-cli
    has no other way to sign 32 chosen bytes."""

    def test_the_challenge_wire_format_is_pinned(self):
        """The committed possession fixtures answer these exact bytes.

        This catches more than a change to the challenge RULE, and that breadth is
        the point: the digest is taken over the ceremony's applied validator, so
        ANY change to the validator moves it and invalidates every committed
        signature. That is what happened when `fee_ok` was fixed — a deliberate
        change to the on-chain predicate, which re-hashed the script, which
        re-keyed the challenge, which orphaned the proofs.

        The wire FORMAT is pinned separately, by
        test_the_challenge_transaction_is_what_build_raw_emits, over a synthetic
        challenge. So: this test moving alone means the inputs changed and the
        proofs must be re-minted; BOTH moving means the encoding rule changed and
        nothing may be re-minted until that is understood."""
        self.assertEqual(
            challenge_for(GOLDEN_PARAMS).hex(),
            "993774bf630ed50443e1168ecd18558a1bfed0ac27cc1d786008ce5964ecaba4")

    def test_the_challenge_transaction_is_what_build_raw_emits(self):
        """Pinned against a real `cardano-cli conway transaction build-raw --tx-in
        <challenge>#0 --fee 0` on cardano-cli 11.0.0.0, so a client may use the
        emitted file or rebuild it themselves and get the same bytes."""
        from verify_ceremony import challenge_tx_envelope
        challenge = bytes.fromhex("00112233445566778899aabbccddeeff"
                                  "00112233445566778899aabbccddeeff")
        self.assertEqual(
            challenge_tx_envelope(challenge)["cborHex"],
            "84a300d901028182582000112233445566778899aabbccddeeff00112233445566778899"
            "aabbccddeeff0001800200a0f5f6")

    def test_the_digest_is_the_body_hash_cardano_cli_signs(self):
        from verify_ceremony import possession_digest, ed25519_verify
        challenge = bytes.fromhex("00112233445566778899aabbccddeeff"
                                  "00112233445566778899aabbccddeeff")
        self.assertEqual(
            possession_digest(challenge).hex(),
            "0b9106612e989c93757160ab4ca2e139db43b880e79902234329304da8d12100")
        # a witness cardano-cli 11.0.0.0 actually produced over that body
        self.assertTrue(ed25519_verify(
            bytes.fromhex("c3c379a6a02ac27ee6e1bd903324cd438331b5ecf7ce62b6a911a184"
                          "9b8d4bb2"),
            possession_digest(challenge),
            bytes.fromhex("62a1bdb8bb8554a8a9ba8ce7360638e13ff301475a3e05e582e8ded1"
                          "feb4c346655880e566f16895470d24225fca7bc9210b97da16260517"
                          "2ba372c6fc9f4b09")))

    def test_the_challenge_moves_with_every_parameter(self):
        """A challenge that did not move would let a proof for one ceremony endorse
        another."""
        base = challenge_for(GOLDEN_PARAMS)
        for key, value in (
                ("adam_bot_pkh", "b1" * 28),
                ("client_owner_vkh", OPERATOR_KEYPAIR_VKH),
                ("dapp_hash", "b2" * 28),
                ("beacon_id", "b3" * 28),
                ("min_asset1_price", {"numerator": 1, "denominator": 2600001}),
                ("min_asset2_price", {"numerator": 2700001, "denominator": 1}),
                ("fee_address", enterprise_addr("b4" * 28)),
                ("fee_bps", 21)):
            p = dict(GOLDEN_PARAMS, **{key: value})
            if key == "client_owner_vkh":
                p["client_payout_address"] = enterprise_addr(value)
            self.assertNotEqual(challenge_for(p), base, f"{key} did not move it")

    def test_the_network_moves_the_challenge(self):
        self.assertNotEqual(challenge_for(mainnet_params(), "mainnet"),
                            challenge_for(GOLDEN_PARAMS))

    def test_a_verification_key_file_is_not_accepted_as_a_proof(self):
        from verify_ceremony import load_possession_proof, CeremonyError
        tmp = tempfile.mkdtemp(prefix="mmaas-proof-")
        try:
            path = write_vkey(CLIENT_VKEY_ENVELOPE, os.path.join(tmp, "client.vkey"))
            with self.assertRaises(CeremonyError) as caught:
                load_possession_proof(path)
            self.assertIn("not a proof of possession", str(caught.exception))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_the_emitted_challenge_file_is_the_one_being_demanded(self):
        from verify_ceremony import challenge_tx_envelope
        tmp = tempfile.mkdtemp(prefix="mmaas-emit-")
        try:
            out = os.path.join(tmp, "possession-challenge.tx")
            rc, _, err, js = run_tool(
                GOLDEN_PARAMS, extra=["--derive-only", "--emit-possession-challenge",
                                      out], vkey=None, proof=None)
            self.assertEqual(rc, 0, err)
            with open(out) as fh:
                emitted = json.load(fh)
            self.assertEqual(
                emitted,
                challenge_tx_envelope(bytes.fromhex(js["possession_challenge"])))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class SigningKeyFilePath(unittest.TestCase):
    """--my-skey-file: the alternative for a client whose key is already on the
    verifying machine. cardano-cli derives the verification key from the private
    half, which nobody holding only the public half can do."""

    def _stub_cli(self, tmp, vkey_envelope):
        """A cardano-cli that answers `conway key verification-key` with a fixed
        key, so the wiring is exercised without a cardano-cli in the test path."""
        path = os.path.join(tmp, "stub-cardano-cli")
        with open(path, "w") as fh:
            fh.write("#!/bin/sh\n"
                     "for a in \"$@\"; do\n"
                     "  if [ \"$prev\" = --verification-key-file ]; then out=$a; fi\n"
                     "  prev=$a\n"
                     "done\n"
                     f"cat > \"$out\" <<'ENVELOPE'\n{json.dumps(vkey_envelope)}\n"
                     "ENVELOPE\n")
        os.chmod(path, 0o755)
        return path

    def _skey(self, tmp):
        path = os.path.join(tmp, "escape.skey")
        with open(path, "w") as fh:
            json.dump({"type": "PaymentSigningKeyShelley_ed25519",
                       "description": "Payment Signing Key",
                       "cborHex": "5820" + "00" * 32}, fh)
        return path

    def test_a_signing_key_for_the_named_key_earns_the_verdict(self):
        tmp = tempfile.mkdtemp(prefix="mmaas-skey-")
        try:
            rc, out, err, js = run_tool(
                GOLDEN_PARAMS, vkey=None, proof=None,
                extra=golden_expectations() + [
                    "--my-skey-file", self._skey(tmp),
                    "--cardano-cli", self._stub_cli(tmp, CLIENT_VKEY_ENVELOPE)])
            self.assertEqual(rc, 0, f"{out}\n{err}")
            self.assertEqual(js["verdict"], "verified")
            self.assertEqual(js["checks"]["possession_proof_form"], "signing-key-file")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_a_signing_key_for_a_different_key_is_refused(self):
        tmp = tempfile.mkdtemp(prefix="mmaas-skey-")
        try:
            other = dict(CLIENT_VKEY_ENVELOPE,
                         cborHex="5820" + RFC8032_VECTORS[0][1])
            rc, out, err, js = run_tool(
                GOLDEN_PARAMS, vkey=None, proof=None,
                extra=golden_expectations() + [
                    "--my-skey-file", self._skey(tmp),
                    "--cardano-cli", self._stub_cli(tmp, other)])
            self.assertNotEqual(rc, 0, f"{out}\n{err}")
            self.assertNotIn("VERIFIED", out)
            self.assertIn("is not the one you hold", js["error"])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class RationalSpellings(unittest.TestCase):
    """The params file demanded {"numerator","denominator"}, but the spelling the tool
    itself EMITS for a floor is "N/D", and the spelling the adam-oc keeper config
    carries is {"num","den"}. A client copying a floor out of either — the obvious
    thing to do — was refused on their first run."""

    def test_the_floor_spelling_the_artefact_emits_is_accepted_back(self):
        rc, out, err, js = run_tool(GOLDEN_PARAMS, extra=["--derive-only"],
                                    vkey=None, proof=None)
        self.assertEqual(rc, 0, f"{out}\n{err}")
        emitted = {p["params_file_key"]: p["value"] for p in js["applied_parameters"]}
        p = dict(GOLDEN_PARAMS,
                 min_asset1_price=emitted["min_asset1_price"],
                 min_asset2_price=emitted["min_asset2_price"])
        rc, out, err, js = run_tool(p, extra=["--derive-only"], vkey=None, proof=None)
        self.assertEqual(rc, 0, f"{out}\n{err}")
        self.assertEqual(js["derived"]["applied_script_hash"], GOLDEN_APPLIED_HASH)

    def test_the_keeper_configs_num_den_spelling_is_accepted(self):
        p = dict(GOLDEN_PARAMS,
                 min_asset1_price={"num": 1, "den": 2600000},
                 min_asset2_price={"num": 2700000, "den": 1})
        rc, out, err, js = run_tool(p, extra=["--derive-only"], vkey=None, proof=None)
        self.assertEqual(rc, 0, f"{out}\n{err}")
        self.assertEqual(js["derived"]["applied_script_hash"], GOLDEN_APPLIED_HASH)

    def test_a_floor_that_mixes_two_spellings_is_refused_naming_all_three(self):
        """Accepting more spellings must not become accepting anything: a floor that
        is half one spelling and half another is a typo, not a dialect."""
        p = dict(GOLDEN_PARAMS, min_asset1_price={"num": 1, "denominator": 2600000})
        rc, out, err, js = run_tool(p, extra=["--derive-only"], vkey=None, proof=None)
        self.assertNotEqual(rc, 0)
        for spelling in ('"numerator"', '"num"', "N/D"):
            self.assertIn(spelling, js["error"])

    def test_a_floor_string_that_is_not_two_integers_is_refused(self):
        for text in ("2.6", "1/0", "1/2/3", "1 / 2600000e3", "0x1/2"):
            p = dict(GOLDEN_PARAMS, min_asset1_price=text)
            rc, out, err, js = run_tool(p, extra=["--derive-only"],
                                        vkey=None, proof=None)
            self.assertNotEqual(rc, 0, f"{text!r} was accepted")


#: Ceremonies this tool refuses to endorse and the validator's escape branch
#: nonetheless honours — `withdraw` returns True on the client's signature before
#: `payout_bound` is reached, so none of these parameters is even read. Each has a
#: paired aiken test naming it: zero_floor_ceremony_client_escape_passes,
#: crossed_ceremony_client_escape_passes,
#: negatively_signed_ceremony_client_escape_passes,
#: payout_to_foreign_key_client_escape_passes.
INCOHERENT_CEREMONIES = {
    "crossed band": dict(CROSSED_FLOORS),
    "zero floors": {"min_asset1_price": {"numerator": 0, "denominator": 1},
                    "min_asset2_price": {"numerator": 0, "denominator": 1}},
    "negatively signed floors": {
        "min_asset1_price": {"numerator": -1, "denominator": -2},
        "min_asset2_price": {"numerator": -1, "denominator": -2}},
    "payout to a foreign key": {"client_payout_address": enterprise_addr("ab" * 28)},
    "bot key == client key": {"adam_bot_pkh": GOLDEN_PARAMS["client_owner_vkh"]},
}


class ContractedFeeCeiling(unittest.TestCase):
    """A rate above the validator's ceiling makes the instance refuse EVERY bot
    action — the same "your position can only be moved by your escape key" outcome
    the tool already refuses a zero floor and a crossed band for. It endorsed this
    one, because the coherence gate never looked at fee_bps."""

    def test_the_ceiling_is_read_from_the_validator_not_restated(self):
        """A second copy of the number could drift from the one consensus
        enforces, and the drift would be a ceremony the tool blesses and the
        chain refuses."""
        from verify_ceremony import contracted_fee_ceiling_bps
        source = os.path.join(HERE, "validators", "maker_stake_bound.ak")
        declared = re.search(r"^const\s+max_fee_bps\s*:\s*Int\s*=\s*(\d+)\s*$",
                             open(source).read(), re.MULTILINE)
        self.assertIsNotNone(declared, "the validator no longer declares max_fee_bps")
        self.assertEqual(contracted_fee_ceiling_bps(HERE), int(declared.group(1)))

    def test_a_rate_over_the_ceiling_is_refused(self):
        from verify_ceremony import contracted_fee_ceiling_bps
        over = contracted_fee_ceiling_bps() + 1
        rc, out, err, js = run_tool(dict(GOLDEN_PARAMS, fee_bps=over),
                                    extra=["--derive-only"], vkey=None, proof=None)
        self.assertNotEqual(rc, 0)
        self.assertEqual(js["verdict"], "refused")
        self.assertIn(str(over), js["error"])

    def test_the_ceiling_itself_is_accepted(self):
        """The validator admits fee_bps == max_fee_bps, so refusing it here would
        be the tool inventing a stricter rule than the chain's."""
        from verify_ceremony import contracted_fee_ceiling_bps
        rc, out, err, js = run_tool(
            dict(GOLDEN_PARAMS, fee_bps=contracted_fee_ceiling_bps()),
            extra=["--derive-only"], vkey=None, proof=None)
        self.assertEqual(rc, 0, f"{out}\n{err}")

    def test_a_negative_rate_is_refused(self):
        rc, out, err, js = run_tool(dict(GOLDEN_PARAMS, fee_bps=-1),
                                    extra=["--derive-only"], vkey=None, proof=None)
        self.assertNotEqual(rc, 0)

    def test_an_inert_instance_is_still_recoverable(self):
        """Bricked by the rate is exactly when the escape hatch is the only way
        out, so the derivation has to survive the refusal."""
        from verify_ceremony import contracted_fee_ceiling_bps
        params = dict(GOLDEN_PARAMS, fee_bps=contracted_fee_ceiling_bps() + 1)
        rc, out, err, js = run_tool(params, extra=["--for-escape"], vkey=None, proof=None)
        self.assertEqual(rc, 0, f"{out}\n{err}")
        self.assertEqual(js["verdict"], "escape-derivation")
        self.assertEqual(js["derived"]["applied_script_hash"], applied_hash_for(params))

    def test_the_verified_report_names_the_fee_leg(self):
        """The VERIFIED block is the tool's enumeration of what the client is
        bound to. Phase 1 A added a third permitted destination and left the
        sentence saying there were two."""
        rc, out, err, js = run_tool(GOLDEN_PARAMS, extra=golden_expectations())
        self.assertEqual(rc, 0, f"{out}\n{err}")
        self.assertEqual(js["verdict"], "verified")
        self.assertIn(GOLDEN_PARAMS["fee_address"], out)
        self.assertIn(f"{GOLDEN_PARAMS['fee_bps']} basis points", out)
        # the two things a client cannot read off the parameters: a closing
        # transaction pays no fee at all, and the fee address is matched by SHAPE
        # so the operator must use it for nothing else
        self.assertIn("closes an order", out)
        self.assertIn("recognised by SHAPE", out)


class BigIntegerParameters(unittest.TestCase):
    """Anything the validator can be parameterised with has to be encodable, or
    the client holding that ceremony cannot derive their own address — and the
    refusal fired in the ENCODER, upstream of --for-escape, so it took the escape
    hatch with it."""

    HUGE = 2 ** 64

    def test_an_integer_past_64_bits_encodes_as_a_cbor_bignum(self):
        from verify_ceremony import data_int
        self.assertEqual(data_int(self.HUGE).hex(), "c249010000000000000000")
        self.assertEqual(data_int(-self.HUGE - 1).hex(), "c349010000000000000000")

    def test_the_64_bit_forms_are_unchanged(self):
        from verify_ceremony import data_int
        for value, expected in ((0, "00"), (23, "17"), (24, "1818"), (-1, "20"),
                                (500, "1901f4"), (2 ** 64 - 1, "1bffffffffffffffff")):
            self.assertEqual(data_int(value).hex(), expected, f"for {value}")

    def test_such_a_ceremony_can_still_be_escaped(self):
        params = dict(GOLDEN_PARAMS, fee_bps=self.HUGE)
        rc, out, err, js = run_tool(params, extra=["--for-escape"], vkey=None, proof=None)
        self.assertEqual(rc, 0, f"{out}\n{err}")
        self.assertEqual(js["derived"]["applied_script_hash"], applied_hash_for(params))


class EscapeDerivation(unittest.TestCase):
    """A client whose operator handed them a broken ceremony is exactly the client
    the escape hatch is for, and the tool used to refuse them hardest: every
    coherence check raised before an address was derived, so escape.sh — which
    derives through this tool — could not build the recovery at all. Endorsing a
    ceremony and telling a client where their inventory sits are different acts."""

    def test_every_ceremony_the_escape_branch_honours_is_derivable(self):
        for name, overrides in INCOHERENT_CEREMONIES.items():
            with self.subTest(name):
                rc, out, err, js = run_tool(dict(GOLDEN_PARAMS, **overrides),
                                            extra=["--for-escape"], vkey=None, proof=None)
                self.assertEqual(rc, 0, f"{name}: {out}\n{err}")
                self.assertEqual(js["verdict"], "escape-derivation")
                self.assertTrue(js["derived"]["order_address"])
                self.assertTrue(js["derived"]["reward_address"])
                self.assertIn("coherence_refusal", js)

    def test_the_same_ceremonies_are_still_refused_without_the_flag(self):
        """The discriminating control. If these passed too, the flag would be
        measuring nothing and the endorsement gate would be gone."""
        for name, overrides in INCOHERENT_CEREMONIES.items():
            with self.subTest(name):
                rc, out, err, js = run_tool(dict(GOLDEN_PARAMS, **overrides),
                                            extra=["--derive-only"], vkey=None, proof=None)
                self.assertNotEqual(rc, 0, f"{name} was endorsed")
                self.assertEqual(js["verdict"], "refused")

    def test_the_escape_derivation_is_the_address_the_parameters_really_produce(self):
        """Deriving anyway is only useful if it derives the RIGHT address — a
        recovery aimed at the wrong script is worse than no recovery. Checked
        against the apply chain driven independently of the tool's own gates."""
        for name, overrides in INCOHERENT_CEREMONIES.items():
            with self.subTest(name):
                params = dict(GOLDEN_PARAMS, **overrides)
                rc, out, err, js = run_tool(params, extra=["--for-escape"],
                                            vkey=None, proof=None)
                self.assertEqual(rc, 0, f"{name}: {out}\n{err}")
                self.assertEqual(js["derived"]["applied_script_hash"],
                                 applied_hash_for(params))

    def test_it_never_reads_as_a_verdict(self):
        for name, overrides in INCOHERENT_CEREMONIES.items():
            with self.subTest(name):
                rc, out, err, js = run_tool(dict(GOLDEN_PARAMS, **overrides),
                                            extra=["--for-escape"], vkey=None, proof=None)
                self.assertFalse(js["ok"])
                self.assertFalse(js["checks"]["expectations_matched"])
                self.assertEqual(js["checks"]["expectations_compared"], [])
                self.assertIn("FOR ESCAPE ONLY", out)

    def test_the_refusal_it_bypassed_is_stated_not_buried(self):
        """A client must be told what was wrong with the ceremony they are
        walking away from, in the report and in the document."""
        rc, out, err, js = run_tool(dict(GOLDEN_PARAMS, **CROSSED_FLOORS),
                                    extra=["--for-escape"], vkey=None, proof=None)
        self.assertIn("CROSSED", js["coherence_refusal"])
        self.assertIn("CROSSED", out)
        self.assertIn("INCOHERENT", out)

    def test_an_honest_ceremony_is_not_labelled_an_escape(self):
        """The verdict tracks the refusal, not the flag — otherwise every
        escape-derivation document would look alarming and none would be read."""
        rc, out, err, js = run_tool(GOLDEN_PARAMS, extra=["--for-escape"],
                                    vkey=None, proof=None)
        self.assertEqual(rc, 0, f"{out}\n{err}")
        self.assertEqual(js["verdict"], "derive-only")
        self.assertNotIn("coherence_refusal", js)

    def test_it_can_be_checked_against_the_address_the_client_funded(self):
        """The only mode that derives for an incoherent ceremony must also be
        able to compare — otherwise a client escaping a bad ceremony is handed an
        address with no way to tell whether it is the one holding their money."""
        params = dict(GOLDEN_PARAMS, **CROSSED_FLOORS)
        derived = applied_hash_for(params)
        rc, out, err, js = run_tool(params, vkey=None, proof=None,
                                    extra=["--for-escape", "--expect-script-hash", derived])
        self.assertEqual(rc, 0, f"{out}\n{err}")
        self.assertEqual(js["verdict"], "escape-derivation")
        self.assertEqual(js["mismatches"], [])
        self.assertFalse(js["ok"], "a comparison must not promote it to a verdict")

    def test_a_comparison_that_fails_is_reported_and_still_recovers(self):
        params = dict(GOLDEN_PARAMS, **CROSSED_FLOORS)
        rc, out, err, js = run_tool(params, vkey=None, proof=None,
                                    extra=["--for-escape", "--expect-script-hash", "ab" * 28])
        self.assertEqual(js["verdict"], "escape-derivation")
        self.assertTrue(js["mismatches"])
        self.assertIn("DOES NOT MATCH", out)
        self.assertEqual(js["derived"]["applied_script_hash"], applied_hash_for(params))

    def test_it_never_becomes_a_verdict_even_when_everything_matches(self):
        """Comparing is not endorsing. Nothing proved possession of the escape
        key here, so "verified" would be a claim this run cannot make."""
        rc, out, err, js = run_tool(GOLDEN_PARAMS, vkey=None, proof=None,
                                    extra=["--for-escape"] + golden_expectations())
        self.assertEqual(rc, 0, f"{out}\n{err}")
        self.assertEqual(js["verdict"], "derive-only")
        self.assertFalse(js["ok"])
        self.assertEqual(js["mismatches"], [])


class PointerAddressParameters(unittest.TestCase):
    """fee_address is chosen by the OPERATOR. A pointer address is a legal Plutus
    Address whose constructor the blueprint schema names, so refusing to encode
    one was a recovery an operator could brick by picking an exotic address
    form — the one thing this tool exists to make impossible."""

    #: type-4 header (key payment, pointer stake) on testnet, pointer 1/2/3.
    def _pointer_addr(self, slot=1, tx=2, cert=3):
        from verify_ceremony import bech32_encode
        def nat(n):
            out = [n & 0x7F]
            n >>= 7
            while n:
                out.append(n & 0x7F | 0x80)
                n >>= 7
            return bytes(reversed(out))
        return bech32_encode("addr_test", bytes([0x40]) + bytes.fromhex("cd" * 28)
                             + nat(slot) + nat(tx) + nat(cert))

    def test_a_pointer_address_encodes_rather_than_refusing(self):
        from verify_ceremony import address_to_plutus_data
        data, info = address_to_plutus_data(self._pointer_addr(), "testnet")
        self.assertEqual(info["stake_kind"], "pointer")
        self.assertEqual(info["pointer"], [1, 2, 3])
        self.assertEqual(info["payment_hash"], "cd" * 28)

    def test_multibyte_pointer_numbers_round_trip(self):
        from verify_ceremony import address_to_plutus_data
        _, info = address_to_plutus_data(
            self._pointer_addr(slot=123456789, tx=300, cert=0), "testnet")
        self.assertEqual(info["pointer"], [123456789, 300, 0])

    def test_a_truncated_pointer_is_refused_not_guessed(self):
        from verify_ceremony import address_to_plutus_data, bech32_encode, CeremonyError
        truncated = bech32_encode("addr_test", bytes([0x40]) + bytes.fromhex("cd" * 28)
                                  + bytes([0x01, 0x02]))
        with self.assertRaises(CeremonyError) as caught:
            address_to_plutus_data(truncated, "testnet")
        self.assertIn("ends mid-number", str(caught.exception))

    def test_such_a_ceremony_derives_and_can_be_escaped(self):
        params = dict(GOLDEN_PARAMS, fee_address=self._pointer_addr())
        rc, out, err, js = run_tool(params, extra=["--for-escape"], vkey=None, proof=None)
        self.assertEqual(rc, 0, f"{out}\n{err}")
        self.assertEqual(js["derived"]["applied_script_hash"], applied_hash_for(params))


class DeriveOnlyIsNotAVerdict(unittest.TestCase):
    """--derive-only skips every expectation check by design, yet it emitted ok:true
    and a full `derived` block — the same two fields the adam-oc keeper reads to
    authenticate a client's price band. Nothing in the document said which checks had
    actually run, so a derive-only artefact was indistinguishable from a verified one."""

    def test_the_document_says_it_is_not_a_verdict(self):
        rc, out, err, js = run_tool(GOLDEN_PARAMS, extra=["--derive-only"],
                                    vkey=None, proof=None)
        self.assertEqual(rc, 0, f"{out}\n{err}")
        self.assertIn("derived", js)
        self.assertEqual(js["verdict"], "derive-only")
        self.assertNotEqual(js.get("ok"), True)

    def test_it_records_which_checks_did_not_run(self):
        rc, out, err, js = run_tool(GOLDEN_PARAMS, extra=["--derive-only"],
                                    vkey=None, proof=None, band=None)
        checks = js["checks"]
        self.assertFalse(checks["band_level_anchored"])
        self.assertFalse(checks["key_possession_proved"])
        self.assertFalse(checks["expectations_matched"])
        self.assertEqual(checks["expectations_compared"], [])

    def test_a_verified_document_records_every_check_as_run(self):
        rc, out, err, js = run_tool(GOLDEN_PARAMS, extra=golden_expectations())
        self.assertEqual(rc, 0, f"{out}\n{err}")
        self.assertEqual(js["verdict"], "verified")
        self.assertTrue(js["ok"])
        checks = js["checks"]
        self.assertTrue(checks["band_level_anchored"])
        self.assertTrue(checks["key_possession_proved"])
        self.assertTrue(checks["expectations_matched"])
        self.assertEqual(sorted(checks["expectations_compared"]),
                         ["order address", "reward address", "staking script hash"])

    def test_a_refused_document_is_labelled_refused(self):
        p = dict(GOLDEN_PARAMS, **CROSSED_FLOORS)
        rc, out, err, js = run_tool(p, extra=["--derive-only"], vkey=None, proof=None)
        self.assertNotEqual(rc, 0)
        self.assertEqual(js["verdict"], "refused")
        self.assertFalse(js["ok"])



V2_VECTORS = json.load(open(os.path.join(HERE, "testdata", "cip30-consent-v2-vectors.json")))

# Terms for the golden rehearsal ceremony (0 decimals, limits 2.6 and 2.7 ADA), naming its
# token ADAMMKT under an illustrative policy id: the statement renders any 28 bytes alike.
GOLDEN_CONSENT = {
    "token": {"policyId": "ad" * 28, "assetNameHex": "4144414d4d4b54"},
    "decimals": 0,
    "terms": {"spreadBps": 800, "maxDepthAda": 120, "dailyLossBps": 500, "minRepriceBps": 150},
    "signedAt": "2026-09-24T09:00:00Z",
}


class ConsentV2Statement(unittest.TestCase):
    """possession_payload is the v2 statement a client signs, built from the terms they name,
    and nothing at all without them: the v1 statement is never offered for signing again."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mmaas-consent-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def terms_file(self, consent):
        path = os.path.join(self.tmp, "consent-terms.json")
        with open(path, "w") as fh:
            json.dump(consent, fh)
        return path

    def test_possession_payload_is_the_v2_statement_built_from_consent_terms(self):
        import verify_ceremony as vc
        rc, out, err, js = run_tool(GOLDEN_PARAMS, extra=[
            "--derive-only", "--consent-terms", self.terms_file(GOLDEN_CONSENT)])
        self.assertEqual(rc, 0, out + err)
        payload = js["possession_payload"]
        self.assertTrue(payload.startswith("SaturnSwap MMaaS consent, version 2\n"), payload)
        self.assertIn("I consent", payload)
        self.assertEqual(payload, vc.canonical_consent_payload_v2(
            bytes.fromhex(js["possession_challenge"]), "testnet", GOLDEN_PARAMS, GOLDEN_CONSENT))

    def test_without_consent_terms_nothing_is_offered_for_signing(self):
        rc, out, err, js = run_tool(GOLDEN_PARAMS, extra=["--derive-only"])
        self.assertEqual(rc, 0, out + err)
        self.assertIsNone(js["possession_payload"])

    def test_terms_at_other_decimals_than_the_ones_verified_are_refused(self):
        """The price limits in the statement are read at its own decimals, so they would not
        be the band this run just checked."""
        rc, out, _, js = run_tool(GOLDEN_PARAMS, extra=[
            "--derive-only", "--consent-terms", self.terms_file(dict(GOLDEN_CONSENT, decimals=6))])
        self.assertEqual(rc, 1)
        self.assertRegex(out, "decimals 6.*--decimals 0")
        self.assertIsNone(js.get("possession_payload"))

    def test_a_statement_the_keeper_would_refuse_is_never_offered(self):
        oversize = dict(GOLDEN_CONSENT, terms=dict(GOLDEN_CONSENT["terms"], maxDepthAda=int("9" * 1100)))
        rc, out, _, js = run_tool(GOLDEN_PARAMS, extra=[
            "--derive-only", "--consent-terms", self.terms_file(oversize)])
        self.assertEqual(rc, 1)
        self.assertIn("at most 2,048", out)
        self.assertIsNone(js.get("possession_payload"))

    def test_consent_terms_are_refused_while_escaping(self):
        """--for-escape derives a ceremony the tool may refuse to endorse; a statement
        consenting to be market-made under it is the one thing it must not produce."""
        rc, _, err, _ = run_tool(GOLDEN_PARAMS, extra=[
            "--for-escape", "--consent-terms", self.terms_file(GOLDEN_CONSENT)])
        self.assertEqual(rc, 2)
        self.assertIn("never builds a statement consenting to be market-made", err)


class ConsentV2ProofEndToEnd(unittest.TestCase):
    """A real wallet signature over the v2 statement, through the whole tool: rebuild, apply,
    derive, and a verdict that says what the client consented to."""

    VECTOR = next(v for v in V2_VECTORS["vectors"] if v["name"] == "mainnet-base")
    ANCHOR = "0.09:0.11"

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="mmaas-consent-e2e-")
        v = cls.VECTOR
        cls.proof = os.path.join(cls.tmp, "possession-proof.json")
        with open(cls.proof, "w") as fh:
            json.dump({"type": "CIP30PossessionProof", "address": v["address"],
                       "coseSign1": v["cose_sign1_hex"], "coseKey": v["cose_key_hex"]}, fh)
        _, _, _, derived = run_tool(v["params"], network="mainnet", decimals=6, band=cls.ANCHOR,
                                    vkey=None, proof=None, extra=["--derive-only"])
        cls.order_address = derived["derived"]["order_address"]

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def run_with_proof(self, decimals, anchor):
        return run_tool(self.VECTOR["params"], network="mainnet", decimals=decimals, band=anchor,
                        vkey=None, proof=None,
                        extra=["--possession-proof", self.proof, "--my-address",
                               self.VECTOR["address"], "--expect-order-address", self.order_address])

    def test_a_real_v2_proof_earns_a_verdict_and_reports_what_was_consented_to(self):
        rc, out, err, js = self.run_with_proof(6, self.ANCHOR)
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(js["verdict"], "verified")
        self.assertEqual(js["possession"]["statement"], "v2")
        self.assertEqual(js["consent_terms"], self.VECTOR["consent_terms"])
        self.assertIn("You consented to:", out)
        for line in self.VECTOR["payload_text"].split("\n")[7:14]:
            self.assertIn(line, out)

    def test_decimals_7_against_a_statement_signed_at_6_is_refused(self):
        """The anchor moves with the decimals, so the band check passes and the refusal is the
        statement's own decimals line."""
        rc, out, _, js = self.run_with_proof(7, "0.9:1.1")
        self.assertEqual(rc, 1)
        self.assertRegex(out, "token decimals 6.*--decimals 7")
        self.assertIsNone(js["consent_terms"])


NIGHT_V1_RECORD = json.load(open(os.path.join(HERE, "testdata", "mainnet-night-v1-consent.json")))
NIGHT_PARAMS = json.load(open(os.path.join(HERE, "testdata", "consent-v2.golden.json")))["ceremony"]["params"]
# The credential the live NIGHT order sits under (D2 spec section 7, read from Kupo).
NIGHT_LIVE_CREDENTIAL = "ae354eef546c4b1052534470e0d0d989d343b7d963bc85243b335f0b"


class ConsentV1ProofEndToEnd(unittest.TestCase):
    """The live NIGHT book's own on-chain consent, which its client's wallet signed over the v1
    statement. It still proves the escape-hatch key, and the tool says it consents to nothing."""

    def test_the_live_night_v1_record_proves_the_key_and_is_reported_audit_only(self):
        record = NIGHT_V1_RECORD["metadata"]
        address, cose_sign1, cose_key = ("".join(record[key]) for key in ("addr", "sig", "key"))
        self.assertEqual(record["n"], [len(address), len(cose_sign1), len(cose_key)])
        self.assertEqual(address, NIGHT_PARAMS["client_payout_address"])
        tmp = tempfile.mkdtemp(prefix="mmaas-consent-v1-")
        self.addCleanup(shutil.rmtree, tmp, True)
        proof = os.path.join(tmp, "possession-proof.json")
        with open(proof, "w") as fh:
            json.dump({"type": "CIP30PossessionProof", "address": address,
                       "coseSign1": cose_sign1, "coseKey": cose_key}, fh)
        ceremony = dict(network="mainnet", decimals=6, band="0.09:0.11", vkey=None, proof=None)
        _, _, _, derived = run_tool(NIGHT_PARAMS, extra=["--derive-only"], **ceremony)
        self.assertEqual(derived["derived"]["applied_script_hash"], NIGHT_LIVE_CREDENTIAL)

        rc, out, err, js = run_tool(NIGHT_PARAMS, **ceremony, extra=[
            "--possession-proof", proof, "--my-address", address,
            "--expect-order-address", derived["derived"]["order_address"]])
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(js["verdict"], "verified")
        self.assertEqual(js["possession"]["statement"], "v1, audit only, not accepted by the keeper")
        self.assertIsNone(js["consent_terms"])
        self.assertIn("v1, audit only, not accepted by the keeper", out)
        self.assertIn("consents to nothing", out)
        self.assertNotIn("You consented to:", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
