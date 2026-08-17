#!/usr/bin/env python3
"""Verify a SaturnSwap MMaaS payout-constrained staking ceremony, client-side.

Your market-making inventory sits at an address whose protections — your price
floors, your payout address, your own escape-hatch key — are compiled INTO a
staking script. SaturnSwap compiles that script and tells you an address. This
tool re-derives the script and the address from the validator source in this
repository and your own parameters, and refuses if the result is not exactly
what you were told. It needs nothing from SaturnSwap but the address itself.

WHAT THIS CHECK IS ANCHORED ON, and what you must obtain yourself
-----------------------------------------------------------------
The anchor is AUDITABLE SOURCE, not bytes anyone hands you. An operator can
publish a manifest that matches a backdoored blob; it cannot publish source that
compiles to one. So the conclusion is only worth what these six inputs are
worth, and every one of them must reach you independently of the operator:

  1. This repository, from its published URL — specifically
     `maker_stake/validators/maker_stake_bound.ak`, `maker_stake/aiken.toml`,
     `maker_stake/aiken.lock` and `maker_stake/plutus.json`. Nothing else in it
     determines the script.
  2. The `aiken` build pinned in `aiken.toml` (`compiler = ...`), from
     aiken-lang's own releases. Aiken bytecode is NOT reproducible across
     different builds of one version string, so this tool refuses on a mismatch
     rather than reporting a difference you might read past.
  3. Your own escape-hatch key and payout address, generated on YOUR machine.
     The operator must never generate or hold either. A SIGNATURE by that key
     over this ceremony's challenge is REQUIRED for a verdict
     (`--possession-proof`, or `--my-skey-file`): it is the only check that can
     see a swapped bot/client parameter pair, because on chain both are 28
     opaque bytes and no predicate over them can tell which one a human can
     sign for. Hashing a `.vkey` file cannot do it — a verification key is
     PUBLIC, so the operator can generate the pair, keep the signing half and
     send you a file that hashes correctly.
  4. The cardano-swaps order script hash and beacon policy id of the book being
     made — from the audited cardano-swaps deployment, not from the operator's
     message. This tool cannot tell a correct one from a plausible one.
  5. The token's `decimals` and the price band you agreed to, in ADA per whole
     token, from a source that is not the operator (`--decimals`,
     `--expect-band-ada-per-display-unit`). Both floors are raw base units and
     the on-chain band relation is SYMMETRIC — it bounds the spread, never the
     level — so without an external price anchor a transposed pair of floors is
     a perfectly valid, non-crossed, on-chain-accepted ceremony whose ask floor
     is sub-lovelace dust. Both flags are REQUIRED for a verdict.
  6. The address the operator told you to fund, and the stake credential
     actually registered on chain (`--check-chain`).

The nine parameters are POSITIONAL and same-typed in pairs, so a swap produces
a valid script that means something else. Any swap changes the applied hash, so
the address comparison catches it — as long as the parameters you feed this tool
are the ones YOU chose. That is why (3), (4) and (5) are yours to obtain.

Requires: python3 and the pinned aiken. `--check-chain` additionally uses
cardano-cli; everything else works offline.
"""

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import tomllib
from decimal import Decimal, localcontext
from fractions import Fraction

# The possession proof is judged against the SAME primitive cardano-node signs and
# verifies with: libsodium, via PyNaCl. Its ge25519_has_small_order rejection is
# exactly what stops a torsion-point forgery, and matching it means a key this tool
# endorses is a key the ledger will too. When PyNaCl is absent the pure-python
# fallback below carries the identical checks, so a client with nothing but python3
# is never told a forged proof is genuine.
try:
    import nacl.signing as _NACL_SIGNING
    from nacl.exceptions import BadSignatureError as _NACL_BAD_SIGNATURE
except ImportError:  # pragma: no cover - portability fallback exercised in tests
    _NACL_SIGNING = None
    _NACL_BAD_SIGNATURE = Exception

VALIDATOR_MODULE = "maker_stake_bound"
VALIDATOR_NAME = "maker_stake_bound"
VALIDATOR_TITLE_PREFIX = f"{VALIDATOR_MODULE}.{VALIDATOR_NAME}."


class CeremonyError(Exception):
    """A refusal: something could not be verified, so nothing is asserted."""


# ---------------------------------------------------------------------------
# The nine parameters, in the order the validator declares them. `aiken
# blueprint apply` is POSITIONAL, so this order is the whole ballgame: two
# parameters of the same shape swapped over produce a valid script with
# inverted meaning. Every entry is pinned against the blueprint before use.
# ---------------------------------------------------------------------------

PARAMS = [
    {
        "name": "adam_bot_pkh",
        "key": "adam_bot_pkh",
        "kind": "hash28",
        "ref": "aiken~1crypto~1VerificationKeyHash",
        "label": "SaturnSwap bot key",
        "protects": (
            "The bot key allowed to reprice and cancel your orders. It can never\n"
            "     move your value anywhere except back into your own order address or\n"
            "     to your payout address below, and it can never tear down your stake\n"
            "     credential to pocket the 2 ADA deposit."
        ),
    },
    {
        "name": "client_owner_vkh",
        "key": "client_owner_vkh",
        "kind": "hash28",
        "ref": "aiken~1crypto~1VerificationKeyHash",
        "label": "YOUR escape-hatch key",
        "protects": (
            "Your self-custody escape hatch. A signature from this key alone moves,\n"
            "     reprices or cancels anything under this script with no cooperation\n"
            "     from SaturnSwap. Confirm this is a key YOU hold — if it is wrong,\n"
            "     you cannot recover your inventory without the bot."
        ),
    },
    {
        "name": "client_payout",
        "key": "client_payout_address",
        "kind": "address",
        "ref": "cardano~1address~1Address",
        "label": "YOUR payout address",
        "protects": (
            "The only non-order address the bot may pay to, matched exactly and with\n"
            "     no datum attached. Its payment credential MUST be the escape-hatch key\n"
            "     above — the validator requires it — so a hot escape key with a separate\n"
            "     cold payout address is not expressible. Confirm you control it."
        ),
    },
    {
        "name": "dapp_hash",
        "key": "dapp_hash",
        "kind": "hash28",
        "ref": "aiken~1crypto~1ScriptHash",
        "label": "order script",
        "protects": (
            "The cardano-swaps order validator your inventory rests in — the payment\n"
            "     half of your order address."
        ),
    },
    {
        "name": "beacon_id",
        "key": "beacon_id",
        "kind": "hash28",
        "ref": "aiken~1crypto~1ScriptHash",
        "label": "beacon policy",
        "protects": (
            "The beacon minting policy of the book you are making. A repriced order\n"
            "     must name this policy or it does not count as still being yours."
        ),
    },
    {
        "name": "min_asset1_price",
        "key": "min_asset1_price",
        "kind": "rational",
        "ref": "maker_stake_bound~1LegacyRational",
        "label": "your BID CEILING",
        "protects": (
            "asset1_price = token base units per lovelace. Because it is quoted that way\n"
            "     round, flooring it CAPS what you pay: the most the bot can ever bid is\n"
            "     denominator/numerator lovelace per token base unit."
        ),
    },
    {
        "name": "min_asset2_price",
        "key": "min_asset2_price",
        "kind": "rational",
        "ref": "maker_stake_bound~1LegacyRational",
        "label": "your ASK FLOOR",
        "protects": (
            "asset2_price = lovelace per token base unit. The least the bot can ever ask\n"
            "     for your token is numerator/denominator lovelace per base unit."
        ),
    },
    {
        "name": "fee_address",
        "key": "fee_address",
        "kind": "address",
        "ref": "cardano~1address~1Address",
        "label": "the OPERATOR FEE address",
        "protects": (
            "Where the operator fee may land, and nowhere else. This is the SAME TYPE as\n"
            "     your payout address above and sits next to it positionally, so a swap\n"
            "     between the two is silent and type-compatible — check both values, not\n"
            "     just one. A fee leg must be ADA-only and datum-free; anything else at\n"
            "     this address is not a fee and the validator refuses the transaction."
        ),
    },
    {
        "name": "fee_bps",
        "key": "fee_bps",
        "kind": "int",
        "ref": "Int",
        "label": "the operator FEE RATE, in basis points",
        "protects": (
            "The ceiling on the operator fee, enforced on chain: the fee may never exceed\n"
            "     fee_bps/10000 of what the transaction REALIZES (your payout plus the\n"
            "     fee), so taking more requires paying you more. A rate above 500 bps\n"
            "     makes the whole instance inert, so a mis-parameterised rate cannot\n"
            "     over-charge you — it stops the bot entirely."
        ),
    },
]

# Both floors are in RAW base units — lovelace and 10^-decimals of one token.
# Nothing on chain knows the decimals, so they are a required client-supplied
# input rather than a guess: the conversion below is the whole reason the band's
# LEVEL is checkable at all.
FLOOR_UNITS_CAVEAT = (
    "lovelace per token BASE UNIT (10^-decimals of one token), not per whole token"
)

LOVELACE_PER_ADA = 1_000_000
MAX_DECIMALS = 30

# Constructor indices this tool encodes with. Checked against the blueprint's own
# declared schema on every run, so a stdlib change that renumbers a constructor
# is a loud refusal rather than a wrong address.
EXPECTED_SCHEMA = {
    "cardano/address/Address": {"Address": 0},
    "cardano/address/PaymentCredential": {"VerificationKey": 0, "Script": 1},
    "cardano/address/Credential": {"VerificationKey": 0, "Script": 1},
    "cardano/address/StakeCredential": {"Inline": 0, "Pointer": 1},
    "Option<cardano/address/StakeCredential>": {"Some": 0, "None": 1},
    "maker_stake_bound/LegacyRational": {"LegacyRational": 0},
}

NETWORKS = {
    # name: (network id nibble, payment hrp, reward hrp)
    "mainnet": (1, "addr", "stake"),
    "testnet": (0, "addr_test", "stake_test"),
}

# CIP-19 Shelley address types this tool understands, as
# (payment credential kind, stake credential kind).
ADDRESS_TYPES = {
    0: ("key", "key"),
    1: ("script", "key"),
    2: ("key", "script"),
    3: ("script", "script"),
    6: ("key", None),
    7: ("script", None),
}
ORDER_ADDRESS_TYPE = 3
REWARD_SCRIPT_ADDRESS_TYPE = 15


# ---------------------------------------------------------------------------
# bech32 (BIP-173), without the 90-character limit Cardano addresses exceed
# ---------------------------------------------------------------------------

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values):
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if (top >> i) & 1 else 0
    return chk


def _bech32_hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _convertbits(data, frombits, tobits, pad):
    acc = 0
    bits = 0
    out = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            out.append((acc >> bits) & maxv)
    if pad:
        if bits:
            out.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise CeremonyError("bech32 payload has invalid padding")
    return out


def bech32_encode(hrp, payload):
    data = _convertbits(payload, 8, 5, True)
    checksum_input = _bech32_hrp_expand(hrp) + data + [0, 0, 0, 0, 0, 0]
    polymod = _bech32_polymod(checksum_input) ^ 1
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(BECH32_CHARSET[d] for d in data + checksum)


def bech32_decode(address):
    if address != address.lower() and address != address.upper():
        raise CeremonyError(f"bech32 string mixes upper and lower case: {address}")
    address = address.lower()
    pos = address.rfind("1")
    if pos < 1 or pos + 7 > len(address):
        raise CeremonyError(f"not a bech32 string: {address}")
    hrp, body = address[:pos], address[pos + 1:]
    try:
        data = [BECH32_CHARSET.index(c) for c in body]
    except ValueError:
        raise CeremonyError(f"bech32 string has a character outside the charset: {address}")
    if _bech32_polymod(_bech32_hrp_expand(hrp) + data) != 1:
        raise CeremonyError(
            f"bech32 checksum is invalid — the string is corrupted or mistyped: {address}")
    return hrp, bytes(_convertbits(data[:-6], 5, 8, False))


# ---------------------------------------------------------------------------
# Plutus Data (CBOR) encoding, in the canonical form aiken's `cbor.serialise`
# emits: definite-length heads, indefinite-length constructor field lists,
# definite empty list for a field-less constructor.
# ---------------------------------------------------------------------------

def _cbor_head(major, n):
    if n < 24:
        return bytes([major << 5 | n])
    if n < 0x100:
        return bytes([major << 5 | 24, n])
    if n < 0x10000:
        return bytes([major << 5 | 25]) + n.to_bytes(2, "big")
    if n < 0x100000000:
        return bytes([major << 5 | 26]) + n.to_bytes(4, "big")
    if n < 0x10000000000000000:
        return bytes([major << 5 | 27]) + n.to_bytes(8, "big")
    raise CeremonyError(f"length {n} exceeds the 64-bit CBOR forms this tool encodes")


def data_int(value):
    """Plutus Data's integer encoding, including the bignum forms.

    Anything the VALIDATOR can be parameterised with, this has to encode, or a
    client holding that ceremony cannot derive their own address — and a fee rate
    of 2^64 is exactly the kind of thing an operator would bake to make an
    instance inert. Beyond 64 bits CBOR switches to a tagged byte string (tag 2
    positive, tag 3 negative), which is what aiken emits for the same value."""
    if not isinstance(value, int) or isinstance(value, bool):
        raise CeremonyError(f"expected an integer, got {value!r}")
    magnitude = value if value >= 0 else -1 - value
    if magnitude < 0x10000000000000000:
        return _cbor_head(0 if value >= 0 else 1, magnitude)
    raw = magnitude.to_bytes((magnitude.bit_length() + 7) // 8, "big")
    return bytes([0xC2 if value >= 0 else 0xC3]) + _cbor_head(2, len(raw)) + raw


def data_bytes(raw):
    if len(raw) > 64:
        raise CeremonyError(
            f"byte string of {len(raw)} bytes needs Plutus chunking this tool does not encode")
    return _cbor_head(2, len(raw)) + raw


def data_constr(index, fields):
    if not 0 <= index <= 6:
        raise CeremonyError(f"constructor index {index} is outside the compact tag range")
    head = _cbor_head(6, 121 + index)
    if not fields:
        return head + b"\x80"
    return head + b"\x9f" + b"".join(fields) + b"\xff"


def rational_to_plutus_data(numerator, denominator):
    return data_constr(EXPECTED_SCHEMA["maker_stake_bound/LegacyRational"]["LegacyRational"],
                       [data_int(numerator), data_int(denominator)])


def _credential_data(kind, hash_bytes):
    index = EXPECTED_SCHEMA["cardano/address/Credential"][
        "VerificationKey" if kind == "key" else "Script"]
    return data_constr(index, [data_bytes(hash_bytes)])


def _decode_pointer(address, raw):
    """CIP-19 pointer payload: the payment hash, then slot, tx index and cert
    index as base-128 naturals whose high bit means "another byte follows"."""
    payment_hash, rest, parts = raw[1:29], raw[29:], []
    if len(raw) < 29:
        raise CeremonyError(f"pointer address {address} is truncated before its payment hash")
    i = 0
    for _ in range(3):
        value = 0
        while True:
            if i >= len(rest):
                raise CeremonyError(
                    f"pointer address {address} ends mid-number; its slot, transaction "
                    f"index and certificate index are not all present")
            byte = rest[i]; i += 1
            value = value << 7 | byte & 0x7F
            if not byte & 0x80:
                break
        parts.append(value)
    if i != len(rest):
        raise CeremonyError(
            f"pointer address {address} carries {len(rest) - i} trailing byte(s) after its "
            f"certificate index; a Shelley pointer address has exactly three numbers")
    return payment_hash, tuple(parts)


def address_to_plutus_data(address, network):
    """Decode a bech32 Shelley address into the Plutus `Address` Data the
    validator was parameterised with, refusing anything ambiguous."""
    expected_id, payment_hrp, _ = NETWORKS[network]
    hrp, raw = bech32_decode(address)
    if hrp != payment_hrp:
        other = next((n for n, (_, p, _) in NETWORKS.items() if p == hrp), None)
        if other:
            raise CeremonyError(
                f"payout address {address} is a {other} address but --network {network} "
                f"was requested; a wrong-network address is a different address")
        raise CeremonyError(
            f"payout address {address} has prefix '{hrp}', expected '{payment_hrp}' "
            f"(Byron/base58 addresses cannot appear in a Plutus context at all)")
    header = raw[0]
    addr_type, network_id = header >> 4, header & 0x0F
    if network_id != expected_id:
        raise CeremonyError(
            f"payout address {address} carries network id {network_id}, "
            f"but --network {network} means network id {expected_id}")
    if addr_type in (4, 5):
        # A pointer address is a legal Plutus Address and the blueprint's own
        # schema names the constructor, so refusing to encode one was refusing to
        # derive an address the validator can be parameterised with. fee_address
        # is chosen by the OPERATOR: a refusal here is a recovery they can brick
        # by picking an exotic address form, which is the one thing this tool
        # exists to make impossible.
        payment_kind = "key" if addr_type == 4 else "script"
        payment_hash, pointer = _decode_pointer(address, raw)
        data = data_constr(
            EXPECTED_SCHEMA["cardano/address/Address"]["Address"],
            [_credential_data(payment_kind, payment_hash),
             data_constr(
                 EXPECTED_SCHEMA["Option<cardano/address/StakeCredential>"]["Some"],
                 [data_constr(
                     EXPECTED_SCHEMA["cardano/address/StakeCredential"]["Pointer"],
                     [data_int(n) for n in pointer])])])
        return data, {
            "bech32": address, "address_type": addr_type, "payment_kind": payment_kind,
            "payment_hash": payment_hash.hex(), "stake_kind": "pointer",
            "stake_hash": None, "pointer": list(pointer),
        }
    if addr_type not in ADDRESS_TYPES:
        raise CeremonyError(f"payout address {address} has unsupported type {addr_type}")
    payment_kind, stake_kind = ADDRESS_TYPES[addr_type]
    expected_len = 1 + 28 + (28 if stake_kind else 0)
    if len(raw) != expected_len:
        raise CeremonyError(
            f"payout address {address} is {len(raw)} bytes, expected {expected_len} "
            f"for address type {addr_type}")
    payment_hash = raw[1:29]
    stake_hash = raw[29:57] if stake_kind else None

    if stake_kind is None:
        stake_data = data_constr(
            EXPECTED_SCHEMA["Option<cardano/address/StakeCredential>"]["None"], [])
    else:
        inline = data_constr(
            EXPECTED_SCHEMA["cardano/address/StakeCredential"]["Inline"],
            [_credential_data(stake_kind, stake_hash)])
        stake_data = data_constr(
            EXPECTED_SCHEMA["Option<cardano/address/StakeCredential>"]["Some"], [inline])

    data = data_constr(EXPECTED_SCHEMA["cardano/address/Address"]["Address"],
                       [_credential_data(payment_kind, payment_hash), stake_data])
    info = {
        "bech32": address,
        "address_type": addr_type,
        "payment_kind": payment_kind,
        "payment_hash": payment_hash.hex(),
        "stake_kind": stake_kind,
        "stake_hash": stake_hash.hex() if stake_hash else None,
    }
    return data, info


def order_address(network, dapp_hash, applied_hash):
    network_id, hrp, _ = NETWORKS[network]
    header = ORDER_ADDRESS_TYPE << 4 | network_id
    return bech32_encode(hrp, bytes([header]) + dapp_hash + applied_hash)


def reward_address(network, applied_hash):
    network_id, _, hrp = NETWORKS[network]
    header = REWARD_SCRIPT_ADDRESS_TYPE << 4 | network_id
    return bech32_encode(hrp, bytes([header]) + applied_hash)


# ---------------------------------------------------------------------------
# Params file
# ---------------------------------------------------------------------------

def _hash28(key, value):
    if not isinstance(value, str):
        raise CeremonyError(f"{key}: expected a 28-byte hex string, got {value!r}")
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        raise CeremonyError(f"{key}: '{value}' is not hexadecimal")
    if len(raw) != 28:
        raise CeremonyError(
            f"{key}: '{value}' is {len(raw)} bytes; a Cardano key or script hash is 28")
    return raw


# The three spellings a floor reaches this tool in. The params file has always
# wanted the first; the second is what the keeper config carries; the third is
# what this tool PRINTS for an applied floor, so it is the one a client copying
# out of a --json-out artefact will paste back. Refusing the last two turned the
# obvious move into a confusing refusal on a client's very first run.
_RATIONAL_KEY_PAIRS = (("numerator", "denominator"), ("num", "den"))


def _int_or_none(text):
    body = text[1:] if text[:1] == "-" else text
    return int(text) if body.isascii() and body.isdigit() else None


def _rational_pair(value):
    if isinstance(value, dict):
        for num_key, den_key in _RATIONAL_KEY_PAIRS:
            if set(value) == {num_key, den_key}:
                return value[num_key], value[den_key]
        return None
    if isinstance(value, str):
        parts = value.split("/")
        if len(parts) != 2:
            return None
        num, den = (_int_or_none(part.strip()) for part in parts)
        return None if num is None or den is None else (num, den)
    return None


def _rational(key, value):
    pair = _rational_pair(value)
    if pair is None:
        raise CeremonyError(
            f'{key}: expected a price floor as {{"numerator": <int>, "denominator": '
            f'<int>}}, as {{"num": <int>, "den": <int>}}, or as the "N/D" string this '
            f'tool prints for an applied floor. Got {value!r}')
    num, den = pair
    for label, n in (("numerator", num), ("denominator", den)):
        if not isinstance(n, int) or isinstance(n, bool):
            raise CeremonyError(f"{key}.{label}: expected an integer, got {n!r}")
    return num, den


def _reject_non_positive_floor(key, num, den):
    """A floor of zero or less is a broken ceremony, and this is where we say so.

    It lives beside the other coherence refusals rather than in the encoder,
    because encoding such a floor is perfectly well defined and deriving the
    address is exactly what a client escaping this ceremony needs. The old
    message said in one breath that only the escape-hatch key could move the
    inventory and that it would not derive the address that key must spend
    from."""
    if num <= 0 or den <= 0:
        raise CeremonyError(
            f"{key}: {num}/{den} is not a strictly positive price floor. A zero or "
            f"negative floor disables the dust-reprice protection, so the validator "
            f"refuses every bot action under it and only your escape-hatch key can "
            f"move the inventory. Refusing to endorse it")


def _key_envelope(path, what):
    try:
        with open(path) as fh:
            doc = json.load(fh)
    except FileNotFoundError:
        raise CeremonyError(f"{what} file not found: {path}")
    except json.JSONDecodeError as exc:
        raise CeremonyError(f"{path} is not a cardano-cli key envelope: {exc}")
    cbor_hex = doc.get("cborHex")
    if not isinstance(cbor_hex, str):
        raise CeremonyError(f"{path} has no cborHex field")
    try:
        return doc, bytes.fromhex(cbor_hex)
    except ValueError:
        raise CeremonyError(f"{path} has a cborHex field that is not hexadecimal")


def vkey_from_file(path):
    """The 32 raw ed25519 bytes inside a cardano-cli verification-key envelope."""
    doc, raw = _key_envelope(path, "verification key")
    # A verification key envelope is a CBOR byte string: 0x58 0x20 || 32 bytes.
    if len(raw) != 34 or raw[0] != 0x58 or raw[1] != 0x20:
        raise CeremonyError(
            f"{path} holds {len(raw)} CBOR bytes; expected a 32-byte ed25519 "
            f"verification key (type {doc.get('type')!r}). Extended keys must be "
            f"converted with `cardano-cli key non-extended-key` first")
    return raw[2:]


def vkh(vkey):
    return hashlib.blake2b(vkey, digest_size=28).hexdigest()


def vkh_from_vkey_file(path):
    """The key hash of a cardano-cli VERIFICATION-key envelope.

    This says the file hashes to the parameter, and it says nothing else. A
    verification key is public: the operator can generate the pair, keep the
    signing half and send you this file, and it will hash correctly. Who holds
    the SIGNING half is settled by `check_possession` below, not here."""
    return vkh(vkey_from_file(path))


def vkh_from_skey_file(path, cli):
    """The key hash of a cardano-cli SIGNING-key envelope, derived by asking
    cardano-cli for its verification key. Unlike the hash of a .vkey file this
    cannot be produced without the private half."""
    _key_envelope(path, "signing key")
    workdir = tempfile.mkdtemp(prefix="mmaas-skey-")
    try:
        out = os.path.join(workdir, "derived.vkey")
        _run(cli + ["conway", "key", "verification-key",
                    "--signing-key-file", path, "--verification-key-file", out],
             "cardano-cli conway key verification-key")
        return vkh(vkey_from_file(out))
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# ed25519 verification. ed25519_verify prefers libsodium (PyNaCl), the primitive
# cardano-node uses, and falls back to this RFC 8032 implementation so a proof can
# be judged with nothing but python3. RFC 8032's published vectors are a happy-path
# oracle only: they never touch the torsion subgroup, so both paths additionally
# reject small-order points and non-canonical scalars exactly as libsodium does —
# without that, one fixed constant forges a signature for a key nobody holds.
# ---------------------------------------------------------------------------

_ED_P = 2 ** 255 - 19
_ED_L = 2 ** 252 + 27742317777372353535851937790883648493
_ED_D = -121665 * pow(121666, _ED_P - 2, _ED_P) % _ED_P
_ED_SQRT_M1 = pow(2, (_ED_P - 1) // 4, _ED_P)


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


def _ed_equal(pt, other):
    x1, y1, z1, _ = pt
    x2, y2, z2, _ = other
    return (x1 * z2 - x2 * z1) % _ED_P == 0 and (y1 * z2 - y2 * z1) % _ED_P == 0


def _ed_decompress(raw):
    """The curve point a 32-byte encoding names, or None if it names none."""
    y = int.from_bytes(raw, "little")
    sign, y = y >> 255, y & ((1 << 255) - 1)
    if y >= _ED_P:
        return None
    num = (y * y - 1) % _ED_P
    den = (_ED_D * y * y + 1) % _ED_P
    x2 = num * pow(den, _ED_P - 2, _ED_P) % _ED_P
    if x2 == 0:
        return None if sign else (0, y, 1, 0)
    x = pow(x2, (_ED_P + 3) // 8, _ED_P)
    if (x * x - x2) % _ED_P != 0:
        x = x * _ED_SQRT_M1 % _ED_P
    if (x * x - x2) % _ED_P != 0:
        return None
    if x & 1 != sign:
        x = _ED_P - x
    return (x, y, 1, x * y % _ED_P)


_ED_B = _ed_decompress(
    bytes.fromhex("5866666666666666666666666666666666666666666666666666666666666666"))


_ED_NEUTRAL = (0, 1, 1, 0)


def _ed_is_small_order(point):
    """A point has small (torsion) order iff 8*point is the neutral element — the
    whole 8-point subgroup libsodium refuses. Accepting one lets a fixed 64-byte
    constant verify against a fixed key for EVERY message (for the identity point,
    0*B == neutral == R + k*neutral), a universal forgery for a key nobody holds."""
    return _ed_equal(_ed_mul(8, point), _ED_NEUTRAL)


def _ed25519_verify_pure(public, message, signature):
    """RFC 8032 verification in pure python, hardened to libsodium's rejections:
    small-order A and R, non-canonical point encodings (y >= p, in _ed_decompress)
    and non-canonical scalars (s >= L). The fallback for a client with no PyNaCl."""
    if len(public) != 32 or len(signature) != 64:
        return False
    point_a = _ed_decompress(public)
    if point_a is None or _ed_is_small_order(point_a):
        return False
    encoded_r = signature[:32]
    point_r = _ed_decompress(encoded_r)
    if point_r is None or _ed_is_small_order(point_r):
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _ED_L:
        return False
    k = int.from_bytes(
        hashlib.sha512(encoded_r + public + message).digest(), "little") % _ED_L
    return _ed_equal(_ed_mul(s, _ED_B), _ed_add(point_r, _ed_mul(k, point_a)))


def ed25519_verify(public, message, signature):
    if len(public) != 32 or len(signature) != 64:
        return False
    if _NACL_SIGNING is not None:
        try:
            _NACL_SIGNING.VerifyKey(bytes(public)).verify(bytes(message),
                                                          bytes(signature))
            return True
        except (_NACL_BAD_SIGNATURE, ValueError):
            return False
    return _ed25519_verify_pure(public, message, signature)


# ---------------------------------------------------------------------------
# Proof of possession
#
# The escape-hatch parameter is 28 bytes, and the file that hashes to it is
# PUBLIC. So the question "is this a key you hold?" is not answerable by hashing
# anything; it is answerable only by a signature. The challenge below is a
# function of the whole ceremony — the compiler's unapplied script plus all
# nine applied parameters plus the network — so a proof minted for one ceremony
# cannot be replayed into another.
#
# Stock cardano-cli has no raw-message signing command. Its only ed25519 signing
# surfaces are `transaction sign` and `transaction witness`, which sign a
# transaction body hash. So the challenge is delivered AS a transaction body:
# one input whose txid is the challenge, no outputs, zero fee — a transaction
# that can never be submitted, built and signed entirely offline.
# ---------------------------------------------------------------------------

POSSESSION_DOMAIN = b"SaturnSwap-MMaaS-bound-ceremony-possession-v1"


def possession_challenge(network, unapplied_hash, encoded):
    digest = hashlib.blake2b(digest_size=32)
    digest.update(POSSESSION_DOMAIN)
    digest.update(b"\n" + network.encode())
    digest.update(b"\n" + bytes.fromhex(unapplied_hash))
    for param in encoded:
        digest.update(b"\n" + bytes.fromhex(param["plutus_data_cbor_hex"]))
    return digest.digest()


def challenge_tx_body(challenge):
    """`{0: set[[challenge, 0]], 1: [], 2: 0}` — byte for byte what `cardano-cli
    conway transaction build-raw --tx-in <challenge>#0 --fee 0` emits."""
    return (b"\xa3\x00\xd9\x01\x02\x81\x82\x58\x20" + challenge
            + b"\x00\x01\x80\x02\x00")


def challenge_tx_envelope(challenge):
    body = challenge_tx_body(challenge)
    return {
        "type": "Tx ConwayEra",
        "description": "SaturnSwap MMaaS ceremony possession challenge — "
                       "zero fee, no outputs, unsubmittable",
        "cborHex": (b"\x84" + body + b"\xa0\xf5\xf6").hex(),
    }


def possession_digest(challenge):
    """The 32 bytes a signer signs: the challenge transaction's body hash, which
    is exactly what `cardano-cli conway transaction witness` puts its signature
    over."""
    return hashlib.blake2b(challenge_tx_body(challenge), digest_size=32).digest()


def load_possession_proof(path):
    """A signature over the challenge digest, as `(form, vkey_or_None, signature)`.

    Two forms, because two kinds of signer exist: a `TxWitness` envelope from
    stock cardano-cli, which carries its own verification key, and 128 hex
    characters from anything else (a hardware signer, cardano-signer), which
    does not and is checked against --my-vkey-file."""
    try:
        with open(path) as fh:
            text = fh.read().strip()
    except FileNotFoundError:
        raise CeremonyError(f"possession proof file not found: {path}")
    if text.startswith("{"):
        try:
            doc = json.loads(text)
        except json.JSONDecodeError as exc:
            raise CeremonyError(f"{path} is not a readable JSON envelope: {exc}")
        kind = doc.get("type", "")
        if "TxWitness" not in kind:
            raise CeremonyError(
                f"{path} is a {kind!r} envelope, not a proof of possession. A "
                f"verification key is not a proof — it is the thing being proved "
                f"about. Sign the challenge with "
                f"`cardano-cli conway transaction witness`")
        raw = bytes.fromhex(doc.get("cborHex", ""))
        # A shelley key witness is the CBOR pair [vkey, signature]:
        # 0x82 || 0x5820 || 32 bytes || 0x5840 || 64 bytes.
        if (len(raw) != 101 or raw[0] != 0x82 or raw[1:3] != b"\x58\x20"
                or raw[35:37] != b"\x58\x40"):
            raise CeremonyError(
                f"{path} does not hold a single ed25519 key witness "
                f"([vkey, signature]); got {len(raw)} CBOR bytes")
        return "cardano-cli-tx-witness", raw[3:35], raw[37:]
    cleaned = "".join(text.split())
    try:
        signature = bytes.fromhex(cleaned)
    except ValueError:
        raise CeremonyError(
            f"{path} is neither a cardano-cli TxWitness envelope nor a hex "
            f"ed25519 signature")
    if len(signature) != 64:
        raise CeremonyError(
            f"{path} holds {len(signature)} bytes; a detached ed25519 signature "
            f"is 64 (128 hex characters)")
    return "detached-signature", None, signature


def check_possession(owner_vkh, digest, proof_path, skey_path, vkey_path, cli):
    """Did the PRIVATE half of client_owner_vkh sign this ceremony's challenge?

    Returns a record of what was actually established. Raises only when a proof
    was offered and does not hold — a proof that was never offered is a missing
    verdict input, not a lie, and is reported as such."""
    record = {"proved": False, "form": None, "digest": digest.hex()}
    if skey_path:
        derived = vkh_from_skey_file(skey_path, cli)
        if derived != owner_vkh:
            raise CeremonyError(
                f"{skey_path} is the signing key for {derived}, but the ceremony "
                f"names {owner_vkh} as the escape-hatch key. The key that can move "
                f"your inventory without SaturnSwap is not the one you hold")
        record.update(proved=True, form="signing-key-file")
        return record
    if not proof_path:
        return record
    form, vkey, signature = load_possession_proof(proof_path)
    if vkey is None:
        if not vkey_path:
            raise CeremonyError(
                f"{proof_path} is a detached signature, which does not carry the "
                f"verification key it was made with. Pass --my-vkey-file as well, "
                f"or use the `cardano-cli conway transaction witness` form, which "
                f"carries its own")
        vkey = vkey_from_file(vkey_path)
    signer = vkh(vkey)
    if signer != owner_vkh:
        raise CeremonyError(
            f"the possession proof in {proof_path} was made by key {signer}, but "
            f"the ceremony names {owner_vkh} as the escape-hatch key. Proving you "
            f"hold a different key proves nothing about this one")
    point = _ed_decompress(vkey)
    if point is None or _ed_is_small_order(point):
        raise CeremonyError(
            f"the verification key in {proof_path} is a small-order ed25519 point, "
            f"not a usable Cardano key: it has no private half, so any 'proof' by it "
            f"is a published forgery, and a payout address built from {owner_vkh} "
            f"would be permanently unspendable. Regenerate the escape-hatch keypair "
            f"with `cardano-cli address key-gen`")
    if not ed25519_verify(vkey, digest, signature):
        raise CeremonyError(
            f"the signature in {proof_path} does not sign this ceremony. It is "
            f"either not a signature by {signer}, or it was made over a different "
            f"challenge — a proof minted for another ceremony, or before a "
            f"parameter changed. The challenge is a function of every parameter, "
            f"so re-sign the one printed above and try again")
    record.update(proved=True, form=form)
    return record


def load_params(path):
    try:
        with open(path) as fh:
            doc = json.load(fh)
    except FileNotFoundError:
        raise CeremonyError(f"params file not found: {path}")
    except json.JSONDecodeError as exc:
        raise CeremonyError(f"params file {path} is not valid JSON: {exc}")
    if not isinstance(doc, dict):
        raise CeremonyError(f"params file {path} must be a JSON object")

    expected_keys = {p["key"] for p in PARAMS}
    missing = sorted(expected_keys - set(doc))
    unknown = sorted(set(doc) - expected_keys)
    if missing:
        raise CeremonyError(
            "params file is missing required field(s): " + ", ".join(missing) +
            "\nAll nine ceremony parameters must be stated explicitly; this tool "
            "will not guess or default any of them.")
    if unknown:
        raise CeremonyError(
            "params file has unrecognised field(s): " + ", ".join(unknown) +
            "\nRefusing to run rather than silently ignore them. Expected exactly: " +
            ", ".join(p["key"] for p in PARAMS))
    return doc


def _decimal_str(value):
    """A Fraction as an exact decimal string where it has one, otherwise six
    significant digits marked with '≈'. Display only — every comparison in this
    file is done on the exact Fractions."""
    den = value.denominator
    while den % 2 == 0:
        den //= 2
    while den % 5 == 0:
        den //= 5
    exact = den == 1
    with localcontext() as ctx:
        ctx.prec = 40 if exact else 6
        text = format(
            (Decimal(value.numerator) / Decimal(value.denominator)).normalize(), "f")
    return text if exact else "≈" + text


def parse_band_anchor(text):
    """`LOW:HIGH` in ADA per whole token — the price band you agreed to, sourced
    from somewhere that is not the operator. Parsed exactly, never as a float."""
    parts = text.split(":")
    if len(parts) != 2:
        raise CeremonyError(
            f"--expect-band-ada-per-display-unit takes LOW:HIGH in ADA per whole "
            f"token, e.g. 2.5:2.8. Got {text!r}")
    try:
        low, high = (Fraction(p.strip()) for p in parts)
    except (ValueError, ZeroDivisionError):
        raise CeremonyError(
            f"--expect-band-ada-per-display-unit: {text!r} is not two decimal "
            f"numbers separated by a colon")
    if low <= 0 or high <= 0:
        raise CeremonyError(
            f"--expect-band-ada-per-display-unit: {text!r} contains a non-positive "
            f"price; a band anchored at or below zero anchors nothing")
    if low > high:
        raise CeremonyError(
            f"--expect-band-ada-per-display-unit: LOW ({low}) is above HIGH ({high})")
    return low, high


def contracted_fee_ceiling_bps(project=None):
    """`max_fee_bps` as the validator declares it.

    Read out of the very source this run rebuilds — not the script's own
    neighbour and not a second copy of the number — because a copy could drift
    from the one consensus enforces, and the drift would show up as a ceremony
    the tool blesses and the chain refuses."""
    path = os.path.join(project or os.path.dirname(os.path.abspath(__file__)),
                        "validators", "maker_stake_bound.ak")
    with open(path) as fh:
        found = re.search(r"^const\s+max_fee_bps\s*:\s*Int\s*=\s*(\d+)\s*$",
                          fh.read(), re.MULTILINE)
    if not found:
        raise CeremonyError(
            f"{path} declares no `const max_fee_bps: Int`; this tool will not guess the "
            f"ceiling the validator enforces")
    return int(found.group(1))


def check_ceremony_coherence(doc, payout_info, decimals, anchor, project=None):
    """Refuse ceremonies that are internally incoherent.

    These are cheap and they are exactly where a positional-parameter swap
    shows up when the operator hands you a parameter list that *looks* honest.
    Nothing here needs chain access or a rebuild."""
    bot, owner = doc["adam_bot_pkh"], doc["client_owner_vkh"]
    if bot == owner:
        raise CeremonyError(
            f"adam_bot_pkh and client_owner_vkh are the same key ({bot}). Then the "
            f"'escape hatch' disjunct IS the bot, so the bot has unconditional "
            f"authority over your inventory with no conservation check at all. "
            f"Refusing to endorse it")

    if payout_info["payment_kind"] != "key":
        raise CeremonyError(
            f"your payout address {payout_info['bech32']} is a SCRIPT address. The "
            f"validator only credits payouts to your escape-hatch key's own address, "
            f"so under this ceremony no bot action can ever validate and only your "
            f"escape-hatch key could move the inventory. Refusing to endorse it")
    if payout_info["payment_hash"] == doc["dapp_hash"]:
        raise CeremonyError(
            "your payout address is the order script itself; the validator "
            "explicitly rejects that ceremony")
    if payout_info["payment_hash"] != owner:
        raise CeremonyError(
            f"your payout address pays to key {payout_info['payment_hash']} but your "
            f"escape-hatch key is {owner}. The validator requires them to be the SAME "
            f"key, so no bot action could ever validate under this ceremony. If the "
            f"payout address is genuinely yours, then client_owner_vkh is not your key "
            f"— which is what a swapped adam_bot_pkh/client_owner_vkh pair looks like, "
            f"and it would hand the bot unconditional authority. Refusing to endorse it")

    fee_bps = doc["fee_bps"]
    if not isinstance(fee_bps, int) or isinstance(fee_bps, bool):
        raise CeremonyError(f"fee_bps must be an integer number of basis points, got {fee_bps!r}")
    ceiling = contracted_fee_ceiling_bps(project)
    if not 0 <= fee_bps <= ceiling:
        raise CeremonyError(
            f"fee_bps is {fee_bps}, outside the 0..{ceiling} the validator accepts. An "
            f"instance naming a rate above the ceiling refuses EVERY bot action, so your "
            f"position could never be repriced or cancelled by the operator and only your "
            f"escape-hatch key could move it. Refusing to endorse it")

    if doc["fee_address"] == doc["client_payout_address"]:
        raise CeremonyError(
            f"fee_address and client_payout_address are the same address "
            f"({doc['fee_address']}). Every ADA-only payout to it would then count BOTH "
            f"as your realized payout and as the operator's fee, so the fee bound could "
            f"never hold and the instance would refuse every bot action. Refusing to "
            f"endorse it")

    if doc["dapp_hash"] == doc["beacon_id"]:
        raise CeremonyError(
            f"dapp_hash and beacon_id are the same hash ({doc['dapp_hash']}). One is a "
            f"spending script and one is a minting policy; they are never equal in a "
            f"real cardano-swaps deployment. Refusing to endorse it")

    a1, a2 = doc["min_asset1_price"], doc["min_asset2_price"]
    a1n, a1d = _rational("min_asset1_price", a1)
    a2n, a2d = _rational("min_asset2_price", a2)
    _reject_non_positive_floor("min_asset1_price", a1n, a1d)
    _reject_non_positive_floor("min_asset2_price", a2n, a2d)
    # min_asset1_price is token-per-lovelace, so it caps the bid at a1d/a1n
    # lovelace per base unit. min_asset2_price is lovelace-per-base-unit, so it
    # floors the ask at a2n/a2d. A band is crossed when the ceiling is ABOVE the
    # floor, i.e. a1d/a1n > a2n/a2d, i.e. a1n*a2n < a1d*a2d.
    if a1n * a2n < a1d * a2d:
        raise CeremonyError(
            f"these two floors describe a CROSSED band. Your bid ceiling is "
            f"{a1d}/{a1n} lovelace per token base unit, ABOVE your ask floor of "
            f"{a2n}/{a2d}. A quote resting on both floors is bought at the ask and "
            f"sold straight back at the bid for the difference, risk-free and "
            f"repeatable — so 'neither side can be repriced to dust' would be a lie. "
            f"The validator refuses every bot action under a crossed band, so this "
            f"ceremony would also be inert. Refusing to derive an address for it")

    # LEVEL, which the relation above cannot see. `min_a1 * min_a2 >= 1` is
    # SYMMETRIC in the two floors: it bounds the SPREAD and says nothing about
    # where the band SITS. Transposing the two parameters therefore yields a
    # band that is still non-crossed, still passes `floors_ok` on chain, and
    # whose ask floor is sub-lovelace dust — a permissionless TakeAsset lifts
    # the whole token leg for ~1 lovelace. Nothing inside the ceremony can
    # anchor the level: the floors are raw base units and the token's decimals
    # are not on chain. So the anchor is a client input, and without it this
    # tool asserts nothing about either floor's magnitude.
    scale = Fraction(10) ** decimals / LOVELACE_PER_ADA
    bid_ceiling = Fraction(a1d, a1n) * scale
    ask_floor = Fraction(a2n, a2d) * scale
    band = {
        "bid_ceiling_lovelace_per_base_unit": f"{a1d}/{a1n}",
        "ask_floor_lovelace_per_base_unit": f"{a2n}/{a2d}",
        "band_is_crossed": False,
        "decimals": decimals,
        "bid_ceiling_ada_per_display_unit": _decimal_str(bid_ceiling),
        "ask_floor_ada_per_display_unit": _decimal_str(ask_floor),
        "anchor_ada_per_display_unit": None if anchor is None
        else [_decimal_str(anchor[0]), _decimal_str(anchor[1])],
        "level_anchored": anchor is not None,
    }
    if anchor is not None:
        low, high = anchor
        if not (low <= bid_ceiling and ask_floor <= high):
            raise CeremonyError(
                f"these floors are NOT the band you said you agreed to. Converted "
                f"with --decimals {decimals}, they cap the bot's bid at "
                f"{_decimal_str(bid_ceiling)} ADA and floor its ask at "
                f"{_decimal_str(ask_floor)} ADA per whole token, but you sourced "
                f"{_decimal_str(low)}–{_decimal_str(high)} ADA independently, and "
                f"both floors have to sit inside that.\n"
                f"The relation the chain enforces (min_asset1_price x "
                f"min_asset2_price >= 1) is SYMMETRIC: it bounds the SPREAD and "
                f"never the LEVEL. A min_asset1_price/min_asset2_price "
                f"TRANSPOSITION, or the wrong decimals, produces a band that is "
                f"not crossed, is accepted on chain, matches the address you were "
                f"given — and still lets your whole token leg be taken for dust. "
                f"This anchor is the only check that sees it. Refusing to derive "
                f"an address for it")
    return band


def check_toolchain_pin(project, aiken):
    """Pin the exact aiken build and the exact stdlib the bytecode depends on.

    The whole check reduces to 'the bytes SaturnSwap deployed are what this
    source compiles to', and that sentence is only true for one compiler build
    and one stdlib. Both live in files in this repository, so both are checkable
    rather than assumed.

    Runs BEFORE any build: `aiken build` regenerates `aiken.lock`, so a missing
    or edited lock file would be silently repaired if this ran afterwards."""
    toml_path = os.path.join(project, "aiken.toml")
    lock_path = os.path.join(project, "aiken.lock")
    blueprint_path = os.path.join(project, "plutus.json")
    for path in (toml_path, lock_path):
        if not os.path.exists(path):
            raise CeremonyError(
                f"{path} is missing. Without it the compiler and stdlib the bytecode "
                f"depends on are unpinned, so a rebuild proves nothing")
    with open(toml_path, "rb") as fh:
        toml = tomllib.load(fh)
    with open(lock_path, "rb") as fh:
        lock = tomllib.load(fh)

    pinned = toml.get("compiler")
    if not pinned:
        raise CeremonyError(f"{toml_path} declares no `compiler` version to pin against")
    reported = _run([aiken, "--version"], "aiken --version").strip()
    # `aiken --version` prints e.g. "aiken v1.1.22+39d6b04": the version string,
    # then a build-specific commit suffix.
    running = reported.split()[-1].split("+")[0] if reported else ""
    if running != pinned:
        raise CeremonyError(
            f"your aiken is {reported!r}, but this project pins {pinned} in "
            f"aiken.toml. Aiken bytecode is not reproducible across versions, so a "
            f"rebuild with the wrong one cannot confirm or deny anything. Install "
            f"{pinned} from aiken-lang's releases and re-run")

    # The committed blueprint records the full build string (version + commit
    # suffix). Only the version has to match the pin — whether the client's
    # specific BUILD produces the same bytecode is settled by the byte comparison
    # in check_source_integrity, which is the stronger test.
    blueprint_build = None
    if os.path.exists(blueprint_path):
        with open(blueprint_path) as fh:
            blueprint_build = json.load(fh).get(
                "preamble", {}).get("compiler", {}).get("version")
    if blueprint_build and blueprint_build.split("+")[0] != pinned:
        raise CeremonyError(
            f"maker_stake/plutus.json was generated by aiken {blueprint_build} but "
            f"aiken.toml pins {pinned}; the committed blueprint and the pin disagree")

    wanted = {(d["name"], d["version"], d.get("source"))
              for d in toml.get("dependencies", [])}
    locked = {(p["name"], p["version"], p.get("source"))
              for p in lock.get("packages", [])}
    if wanted - locked:
        raise CeremonyError(
            f"aiken.lock does not pin every dependency aiken.toml declares; "
            f"unpinned: {sorted(wanted - locked)}")
    return {"aiken_pinned": pinned, "aiken_running": reported,
            "locked_packages": sorted(f"{n} {v} ({s})" for n, v, s in locked)}


def encode_params(doc, network):
    """Encode each parameter to Plutus Data in the validator's declared order."""
    encoded = []
    payout_info = None
    for spec in PARAMS:
        value = doc[spec["key"]]
        if spec["kind"] == "hash28":
            data = data_bytes(_hash28(spec["key"], value))
            shown = value
        elif spec["kind"] == "rational":
            num, den = _rational(spec["key"], value)
            data = rational_to_plutus_data(num, den)
            shown = f"{num}/{den}"
        elif spec["kind"] == "int":
            if not isinstance(value, int) or isinstance(value, bool):
                raise CeremonyError(
                    f"{spec['key']} must be a plain integer, got {value!r}"
                )
            data = data_int(value)
            shown = str(value)
        elif spec["kind"] == "address":
            info: dict
            data, info = address_to_plutus_data(value, network)
            # Only the CLIENT payout drives the coherence checks below. Capturing
            # it unconditionally would let the fee address — the same type, and
            # declared after it — silently replace the address every later check
            # reasons about.
            if spec["name"] == "client_payout":
                payout_info = info
            shown = value
        else:
            raise CeremonyError(
                f"internal: parameter {spec['name']} has unknown kind {spec['kind']!r}"
            )
        encoded.append({
            "name": spec["name"],
            "params_file_key": spec["key"],
            "value": shown,
            "plutus_data_cbor_hex": data.hex(),
        })
    return encoded, payout_info


# ---------------------------------------------------------------------------
# Blueprint: rebuild from source, pin against the committed copy, apply
# ---------------------------------------------------------------------------

def _run(cmd, what):
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise CeremonyError(
            f"{what} failed (exit {proc.returncode}):\n"
            f"  $ {' '.join(shlex.quote(c) for c in cmd)}\n"
            f"{proc.stdout}{proc.stderr}")
    return proc.stdout


def _bound_validator(blueprint, source):
    hits = [v for v in blueprint["validators"] if v["title"].startswith(VALIDATOR_TITLE_PREFIX)]
    if not hits:
        raise CeremonyError(f"{source} contains no {VALIDATOR_TITLE_PREFIX}* validator")
    codes = {v["compiledCode"] for v in hits}
    hashes = {v["hash"] for v in hits}
    if len(codes) != 1 or len(hashes) != 1:
        raise CeremonyError(
            f"{source} lists diverging bytecode for the three "
            f"{VALIDATOR_TITLE_PREFIX}* endpoints, which must share one script")
    return hits[0]


def check_source_integrity(project, aiken, workdir):
    """Rebuild the blueprint from the .ak source and pin it to the committed one."""
    committed_path = os.path.join(project, "plutus.json")
    if not os.path.exists(committed_path):
        raise CeremonyError(f"no committed blueprint at {committed_path}")
    rebuilt_path = os.path.join(workdir, "rebuilt.plutus.json")
    _run([aiken, "build", "-S", project, "-o", rebuilt_path],
         f"aiken build of {project}")
    with open(committed_path) as fh:
        committed = json.load(fh)
    with open(rebuilt_path) as fh:
        rebuilt = json.load(fh)

    problems = []
    committed_by_title = {v["title"]: v for v in committed["validators"]}
    for v in rebuilt["validators"]:
        other = committed_by_title.get(v["title"])
        if other is None:
            problems.append(f"{v['title']}: present in the rebuild, absent from plutus.json")
            continue
        if v["compiledCode"] != other["compiledCode"]:
            problems.append(
                f"{v['title']}: compiledCode in plutus.json does not match the "
                f"bytecode the source compiles to")
        if v["hash"] != other["hash"]:
            problems.append(
                f"{v['title']}: hash in plutus.json is {other['hash']}, "
                f"source compiles to {v['hash']}")
        if v.get("parameters", []) != other.get("parameters", []):
            problems.append(
                f"{v['title']}: the parameter list in plutus.json does not match "
                f"the source's declared parameters")
    for title in set(committed_by_title) - {v["title"] for v in rebuilt["validators"]}:
        problems.append(f"{title}: present in plutus.json, absent from the rebuild")

    rebuilt_compiler = rebuilt.get("preamble", {}).get("compiler", {})
    committed_compiler = committed.get("preamble", {}).get("compiler", {})
    result = {
        "ok": not problems,
        "problems": problems,
        "your_aiken": f"{rebuilt_compiler.get('name')} {rebuilt_compiler.get('version')}",
        "blueprint_aiken": f"{committed_compiler.get('name')} {committed_compiler.get('version')}",
        "unapplied_script_hash": _bound_validator(rebuilt, rebuilt_path)["hash"],
        "committed_unapplied_script_hash": _bound_validator(committed, committed_path)["hash"],
    }
    return result, rebuilt_path, rebuilt


def check_blueprint_schema(blueprint):
    """Pin the parameter order and the constructor indices this tool encodes with
    against the blueprint's own declared schema."""
    problems = []
    validator = _bound_validator(blueprint, "the rebuilt blueprint")
    declared = validator.get("parameters", [])
    expected = [(p["name"], f"#/definitions/{p['ref']}") for p in PARAMS]
    actual = [(p.get("title"), p.get("schema", {}).get("$ref")) for p in declared]
    if actual != expected:
        problems.append(
            "the validator's declared parameters are not the nine this tool knows "
            "how to encode, in order.\n    expected: " + ", ".join(n for n, _ in expected) +
            "\n    found:    " + ", ".join(str(n) for n, _ in actual))
    definitions = blueprint.get("definitions", {})
    for name, indices in EXPECTED_SCHEMA.items():
        schema = definitions.get(name)
        if schema is None:
            problems.append(f"blueprint declares no schema for {name}")
            continue
        found = {c.get("title"): c.get("index") for c in schema.get("anyOf", [])}
        if found != indices:
            problems.append(
                f"{name}: blueprint declares constructors {found}, "
                f"this tool encodes {indices}")
    return problems


def apply_params(aiken, blueprint_path, encoded, workdir):
    current = blueprint_path
    for i, param in enumerate(encoded, start=1):
        nxt = os.path.join(workdir, f"applied.{i}.json")
        _run([aiken, "blueprint", "apply", "-i", current, "-o", nxt,
              "-m", VALIDATOR_MODULE, "-v", VALIDATOR_NAME, param["plutus_data_cbor_hex"]],
             f"aiken blueprint apply of {param['name']}")
        current = nxt
    with open(current) as fh:
        applied = json.load(fh)
    validator = _bound_validator(applied, current)
    if validator.get("parameters"):
        raise CeremonyError(
            f"after applying nine parameters the validator still declares "
            f"{len(validator['parameters'])} unapplied parameter(s)")
    return validator["hash"], validator["compiledCode"], current


# ---------------------------------------------------------------------------
# Optional read-only chain confirmation
# ---------------------------------------------------------------------------

# A two-way cardano-swaps SwapDatum, in the detailed-JSON form
# `cardano-cli query utxo --output-json` emits for an inline datum. Pinned
# against preprod UTxO 164796d5…#1 at the live two-way dApp address.
SWAP_DATUM_FIELDS = 12


def _pd_bytes(node):
    if isinstance(node, dict) and isinstance(node.get("bytes"), str):
        return node["bytes"]
    return None


def _pd_rational(node):
    if not isinstance(node, dict) or node.get("constructor") != 0:
        return None
    fields = node.get("fields")
    if not isinstance(fields, list) or len(fields) != 2:
        return None
    values = []
    for field in fields:
        if not isinstance(field, dict) or not isinstance(field.get("int"), int) \
                or isinstance(field.get("int"), bool):
            return None
        values.append(field["int"])
    return tuple(values)


def _pd_is_option(node):
    return (isinstance(node, dict) and node.get("constructor") in (0, 1)
            and isinstance(node.get("fields"), list))


def swap_datum_problems(datum, beacon_id, value):
    """Why this inline datum is not a live two-way cardano-swaps order.

    `--require-live` means "your inventory is resting and quotable", and a datum
    that merely EXISTS does not make it so. The dApp decodes a twelve-field
    two-way SwapDatum; against anything else its validator can never succeed, so
    the UTxO is as stuck as a datum-less one. Checking presence alone called a
    bare integer a live order."""
    if datum is None:
        return ["its inline datum was not returned by the chain query, so nothing "
                "here can say it is a decodable order"]
    if not isinstance(datum, dict) or datum.get("constructor") != 0:
        return ["its inline datum is not a constructor-0 value, so it is not a "
                "SwapDatum at all"]
    fields = datum.get("fields")
    if not isinstance(fields, list) or len(fields) != SWAP_DATUM_FIELDS:
        found = len(fields) if isinstance(fields, list) else "no"
        return [f"its inline datum has {found} fields; a two-way cardano-swaps "
                f"SwapDatum has {SWAP_DATUM_FIELDS}"]

    problems = []
    hexes = [_pd_bytes(f) for f in fields[:8]]
    if any(h is None for h in hexes):
        problems.append("its inline datum's first eight fields are not all byte "
                        "strings, so it is not a SwapDatum")
    else:
        if hexes[0] != beacon_id:
            problems.append(
                f"its inline datum names beacon policy {hexes[0]}, not this pair's "
                f"{beacon_id}")
        held = value.get(beacon_id)
        if not isinstance(held, dict) or not held.get(hexes[1]):
            problems.append(
                f"it does not hold the pair beacon {hexes[1]} that its own datum "
                f"names, so the dApp does not see it as an order for this pair")
    for index, label in ((8, "asset1_price"), (9, "asset2_price")):
        pair = _pd_rational(fields[index])
        if pair is None:
            problems.append(
                f"its inline datum's {label} is not a Rational(numerator, denominator)")
        elif pair[0] <= 0 or pair[1] <= 0:
            problems.append(
                f"its inline datum prices {label} at {pair[0]}/{pair[1]}. The "
                f"validator refuses a non-positive price: cross-multiplication only "
                f"preserves the direction of a price comparison for positive "
                f"rationals, so a negative one inverts every floor check")
    for index, label in ((10, "prev_input"), (11, "expiration")):
        if not _pd_is_option(fields[index]):
            problems.append(f"its inline datum's {label} is not an Option")
    return problems


def check_chain(cli, network, testnet_magic, order_addr, reward_addr, beacon_id):
    net = ["--mainnet"] if network == "mainnet" else ["--testnet-magic", str(testnet_magic)]
    out = _run(cli + ["query", "utxo", "--address", order_addr] + net,
               "cardano-cli query utxo")
    utxos = json.loads(out)
    holdings = {}
    detail = {}
    for txin, entry in utxos.items():
        value = entry.get("value", {})
        for unit, qty in value.items():
            if unit == "lovelace":
                holdings["lovelace"] = holdings.get("lovelace", 0) + qty
            else:
                for name, amount in qty.items():
                    key = f"{unit}.{name}"
                    holdings[key] = holdings.get(key, 0) + amount
        # A cardano-swaps order is an INLINE SwapDatum plus this pair's beacons.
        # Anything else at this address is not an order: a script input with no
        # datum at all cannot be spent by anyone, ever.
        inline = entry.get("inlineDatum") is not None or bool(entry.get("inlineDatumRaw"))
        detail[txin] = {
            "has_inline_datum": inline,
            "datum_hash_only": not inline and bool(entry.get("datumhash")),
            "carries_pair_beacon": beacon_id in value,
            "datum_problems": swap_datum_problems(
                entry.get("inlineDatum"), beacon_id, value) if inline else [],
        }
    out = _run(cli + ["conway", "query", "stake-address-info", "--address", reward_addr] + net,
               "cardano-cli query stake-address-info")
    info = json.loads(out)
    return {
        "order_address_utxo_count": len(utxos),
        "order_address_holdings": holdings,
        "order_address_utxos": detail,
        "unspendable_utxos": sorted(
            t for t, d in detail.items()
            if not d["has_inline_datum"] and not d["datum_hash_only"]),
        "non_inline_datum_utxos": sorted(
            t for t, d in detail.items() if d["datum_hash_only"]),
        "malformed_datum_utxos": sorted(
            t for t, d in detail.items()
            if d["has_inline_datum"] and d["datum_problems"]),
        "live_order_utxos": sorted(
            t for t, d in detail.items()
            if d["has_inline_datum"] and d["carries_pair_beacon"]
            and not d["datum_problems"]),
        "stake_credential_registered": bool(info),
        "stake_registration_deposit": info[0].get("stakeRegistrationDeposit") if info else None,
        "stake_delegation": info[0].get("stakeDelegation") if info else None,
        "vote_delegation": info[0].get("voteDelegation") if info else None,
        "reward_account_balance": info[0].get("rewardAccountBalance") if info else None,
    }


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def _git(project, *args):
    try:
        proc = subprocess.run(["git", "-C", project, *args], capture_output=True, text=True)
    except OSError:
        return None
    return proc.stdout if proc.returncode == 0 else None


# Everything that determines the compiled script. Uncommitted edits here mean the
# commit below describes different source than the one just compiled.
SCRIPT_DETERMINING_PATHS = ["validators", "aiken.toml", "aiken.lock", "plutus.json"]


def git_provenance(project):
    """The commit a client compares against the published one, and whether the files
    that determine the bytecode are actually at that commit."""
    head = _git(project, "rev-parse", "HEAD")
    if head is None:
        return {"commit": None, "clean": None, "uncommitted": []}
    dirty = _git(project, "status", "--porcelain", "--", *SCRIPT_DETERMINING_PATHS) or ""
    return {"commit": head.strip(), "clean": not dirty.strip(),
            "uncommitted": sorted(line[3:] for line in dirty.splitlines())}


def compare(expected, derived, what):
    if expected is None:
        return None
    expected = expected.strip()
    return {"what": what, "expected": expected, "derived": derived,
            "match": expected == derived}


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="verify_ceremony.py",
        description="Re-derive and verify a SaturnSwap MMaaS bound staking ceremony.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--params", required=True,
                        help="JSON file holding all nine ceremony parameters")
    parser.add_argument("--network", required=True, choices=sorted(NETWORKS),
                        help="which network the address you were given is on (no default)")
    parser.add_argument("--project", default=os.path.dirname(os.path.abspath(__file__)),
                        help="the maker_stake aiken project directory")
    parser.add_argument("--aiken", default=shutil.which("aiken") or "aiken",
                        help="path to the aiken binary")
    parser.add_argument("--my-vkey-file",
                        help="YOUR escape-hatch verification key file. Its hash must "
                             "equal client_owner_vkh. A verification key is PUBLIC, so "
                             "this states which key the ceremony names and proves "
                             "nothing about who holds it; it is required alongside a "
                             "detached --possession-proof, which needs the public half "
                             "to check the signature against")
    parser.add_argument("--possession-proof", metavar="FILE",
                        help="a signature by YOUR escape-hatch key over this "
                             "ceremony's challenge — the check that catches a swapped "
                             "bot/client parameter pair, because on chain both are 28 "
                             "opaque bytes and no predicate over them can tell which "
                             "one a human can SIGN for. Either a `cardano-cli conway "
                             "transaction witness` envelope or 128 hex characters. "
                             "REQUIRED for a verdict unless --my-skey-file is given; "
                             "run without it once and the tool prints the challenge "
                             "and the exact commands")
    parser.add_argument("--my-skey-file", metavar="FILE",
                        help="the alternative to --possession-proof: YOUR escape-hatch "
                             "SIGNING key, read locally by cardano-cli and never "
                             "transmitted. Simpler, but it puts the private key on this "
                             "machine, which the signature path never needs")
    parser.add_argument("--emit-possession-challenge", metavar="FILE",
                        help="write the challenge transaction to sign here, so an "
                             "air-gapped signer needs nothing from this machine but "
                             "the file")
    parser.add_argument("--emit-applied-script", metavar="FILE",
                        help="write the applied maker_stake_bound script as a cardano-cli "
                             "PlutusScriptV3 envelope here, so the escape hatch can witness "
                             "the withdraw-0 with the exact script this ceremony verified — "
                             "the client never trusts an operator-supplied .plutus")
    parser.add_argument("--decimals", type=int, required=True,
                        help="the token's decimals, from the token registry or its "
                             "CIP-68 metadata — NOT from the operator. Required: the "
                             "two floors are raw base units, so without it neither "
                             "this tool nor the chain can see what they mean")
    parser.add_argument("--expect-band-ada-per-display-unit", metavar="LOW:HIGH",
                        help="the price band you agreed to, in ADA per WHOLE token, "
                             "from your own price source. Both derived floors must "
                             "sit inside it. REQUIRED for a verdict: the on-chain "
                             "band relation is symmetric, so it bounds the spread and "
                             "never the level, and a transposed pair of floors is "
                             "otherwise indistinguishable from an honest one")
    parser.add_argument("--expect-order-address",
                        help="the order address SaturnSwap told you to fund")
    parser.add_argument("--expect-reward-address",
                        help="the reward/stake address of your bound credential")
    parser.add_argument("--expect-script-hash",
                        help="the applied staking script hash you were given")
    parser.add_argument("--derive-only", action="store_true",
                        help="derive and print without comparing (no verdict is asserted)")
    parser.add_argument("--for-escape", action="store_true",
                        help="derive the addresses even for a ceremony this tool would "
                             "refuse to endorse, so recovery is possible from a bad one")
    parser.add_argument("--check-chain", action="store_true",
                        help="also query the chain read-only for your inventory and "
                             "your stake credential's registration")
    parser.add_argument("--require-live", action="store_true",
                        help="with --check-chain, fail unless the stake credential is "
                             "registered AND the order address holds something")
    parser.add_argument("--cardano-cli", default="cardano-cli",
                        help="cardano-cli invocation for --check-chain, e.g. "
                             "'ssh myrelay cardano-cli'")
    parser.add_argument("--testnet-magic", type=int, default=1,
                        help="testnet magic for --check-chain (preprod is 1)")
    parser.add_argument("--json-out",
                        help="write the machine-readable result here; '-' sends the JSON "
                             "to stdout and the human report to stderr")
    args = parser.parse_args(argv)

    json_to_stdout = args.json_out == "-"
    report = sys.stderr if json_to_stdout else sys.stdout

    expectations = (args.expect_order_address, args.expect_reward_address,
                    args.expect_script_hash)
    if args.derive_only and any(expectations) and not args.for_escape:
        parser.error(
            "--derive-only asserts nothing, so it cannot be combined with an "
            "--expect-* flag. Drop it to get a verdict.")
    if args.require_live and not args.check_chain:
        parser.error("--require-live has nothing to judge without --check-chain")
    # Recovery is not endorsement. The coherence gate refuses a crossed band, a
    # zero floor, a foreign payout key and a bot/client collision — and the
    # validator deliberately leaves the escape branch OPEN under every one of
    # them, because those are precisely the ceremonies a client needs to walk
    # away from. A tool that refuses hardest when the operator turned out to be
    # hostile is a tool that helps the operator, so this mode derives anyway and
    # says loudly what it found. It can never produce a verdict.
    # --expect-* stays available here on purpose. It is the ONLY mode that derives
    # an address for an incoherent ceremony, so forbidding the comparison would
    # leave a client escaping a bad ceremony with an address and no way to check
    # it against the one they actually funded. A comparison is not an
    # endorsement: mismatches are reported and the verdict never rises above
    # escape-derivation.
    if args.for_escape:
        args.derive_only = True
    if not (args.derive_only or any(expectations)):
        parser.error(
            "nothing to verify against. Pass at least one of --expect-order-address, "
            "--expect-reward-address, --expect-script-hash, or --derive-only if you "
            "only want to see what your parameters produce.")
    if not 0 <= args.decimals <= MAX_DECIMALS:
        parser.error(f"--decimals must be between 0 and {MAX_DECIMALS}")
    # A verdict is a sentence about YOUR protections, so the two inputs only you
    # can supply are not optional for one. Both gaps were verdict-bearing: a
    # bot/client swap and a floor transposition each earn a matching address, and
    # each is invisible to every other check in this file.
    if not args.derive_only and not (args.my_vkey_file or args.possession_proof
                                     or args.my_skey_file):
        parser.error(
            "no escape-hatch key was named at all. A verdict needs proof that you "
            "can SIGN for client_owner_vkh: pass --possession-proof (with "
            "--my-vkey-file) or --my-skey-file. Run with --derive-only first and "
            "the tool prints the challenge and the commands that produce one.")
    if not args.derive_only and not args.expect_band_ada_per_display_unit:
        parser.error(
            "--expect-band-ada-per-display-unit LOW:HIGH is required for a verdict. "
            "The two floors are raw base units and the band relation the chain "
            "enforces is symmetric, so nothing in the ceremony fixes where the band "
            "SITS — a transposed pair of floors is non-crossed, accepted on chain "
            "and matches the address. Supply the band in ADA per whole token from "
            "your own price source, or pass --derive-only and get no verdict.")

    # A consumer reading this document must be able to tell a verdict from a
    # derivation without reconstructing the tool's flow, so every check it could
    # have run is named here and starts out not-run. --derive-only leaves all of
    # them false, which is exactly what it asserts.
    checks = {
        "source_integrity": False,
        "band_level_anchored": False,
        "key_hash_matches_your_file": False,
        "key_possession_proved": False,
        "possession_proof_form": None,
        "expectations_compared": [],
        "expectations_matched": False,
        "chain_checked": False,
        "chain_require_live": False,
    }
    result = {"ok": False, "verdict": "refused", "checks": checks,
              "network": args.network, "params_file": args.params,
              "decimals": args.decimals}
    workdir = tempfile.mkdtemp(prefix="mmaas-verify-")
    try:
        params = load_params(args.params)
        result["toolchain"] = check_toolchain_pin(args.project, args.aiken)
        integrity, rebuilt_path, rebuilt = check_source_integrity(
            args.project, args.aiken, workdir)
        result["source_integrity"] = integrity
        provenance = git_provenance(args.project)
        result["provenance"] = provenance
        result["repo_commit"] = provenance["commit"]

        print("SaturnSwap MMaaS — client-side ceremony verification", file=report)
        print("=" * 60, file=report)
        print(file=report)
        print("STEP 1  Does the compiled script match the source you can read?", file=report)
        print(f"  source        {os.path.join(args.project, 'validators', 'maker_stake_bound.ak')}",
              file=report)
        print(f"  your aiken    {integrity['your_aiken']}", file=report)
        print(f"  blueprint     {integrity['blueprint_aiken']}", file=report)
        print(f"  pinned aiken  {result['toolchain']['aiken_pinned']} "
              f"(aiken.toml) — running {result['toolchain']['aiken_running']}", file=report)
        for pkg in result["toolchain"]["locked_packages"]:
            print(f"  aiken.lock    {pkg}", file=report)
        print(f"  repo commit   {provenance['commit'] or 'unknown (not a git checkout)'}"
              f"{'' if provenance['clean'] is not False else '  (LOCALLY MODIFIED)'}",
              file=report)
        if provenance["clean"] is False:
            for path in provenance["uncommitted"]:
                print(f"                  - {path}", file=report)
            raise CeremonyError(
                "the files that determine this script have uncommitted local changes, so "
                "the commit above does not describe the source that was just compiled. "
                "Verify against a clean clone of the published repository")
        if not integrity["ok"]:
            print("  RESULT        REFUSED — the committed blueprint is not what this "
                  "source compiles to:", file=report)
            for problem in integrity["problems"]:
                print(f"                  - {problem}", file=report)
            print("                If your aiken build differs from the one above, "
                  "install that exact\n                build before trusting any "
                  "conclusion; aiken bytecode is not\n                reproducible "
                  "across different builds of one version string.", file=report)
            raise CeremonyError("source integrity check failed; nothing was derived")
        checks["source_integrity"] = True
        print(f"  unapplied     {integrity['unapplied_script_hash']}", file=report)
        print("  RESULT        OK — plutus.json is exactly what this source compiles to",
              file=report)
        print(file=report)

        schema_problems = check_blueprint_schema(rebuilt)
        if schema_problems:
            for problem in schema_problems:
                print(f"  - {problem}", file=report)
            raise CeremonyError(
                "the validator's parameters or their data schema are not the ones this "
                "tool encodes; refusing to derive an address")

        encoded, payout_info = encode_params(params, args.network)
        result["applied_parameters"] = encoded
        result["payout_address_detail"] = payout_info

        print("STEP 2  Your nine parameters, applied in the order the validator "
              "declares them", file=report)
        print("        (aiken applies parameters POSITIONALLY — order is part of the "
              "meaning)", file=report)
        for i, (spec, param) in enumerate(zip(PARAMS, encoded), start=1):
            print(f"\n  {i}. {spec['name']}  ({spec['label']})", file=report)
            print(f"     {param['value']}", file=report)
            print(f"     {spec['protects']}", file=report)
        print(file=report)

        anchor = (parse_band_anchor(args.expect_band_ada_per_display_unit)
                  if args.expect_band_ada_per_display_unit else None)
        band = None
        try:
            band = check_ceremony_coherence(params, payout_info, args.decimals, anchor,
                                            args.project)
        except CeremonyError as incoherent:
            if not args.for_escape:
                raise
            result["coherence_refusal"] = str(incoherent)
            print("  THIS CEREMONY IS INCOHERENT, AND YOU ARE RECOVERING FROM IT:\n",
                  file=report)
            print(f"     {incoherent}\n", file=report)
            print("     Derived anyway, because the validator's escape branch does not\n"
                  "     read any of the parameters this refusal is about — it returns\n"
                  "     True on your signature alone. The addresses below are still the\n"
                  "     addresses your inventory sits at, and your key can still empty\n"
                  "     them. Nothing here endorses this ceremony: do not fund it, and\n"
                  "     do not resume trading under it.\n", file=report)
        result["band"] = band
        if band is None:
            print(file=report)
        else:
            checks["band_level_anchored"] = band["level_anchored"]
            print(f"  Your quoting band, {FLOOR_UNITS_CAVEAT}:", file=report)
            print(f"     the bot may never bid ABOVE "
                  f"{band['bid_ceiling_lovelace_per_base_unit']}", file=report)
            print(f"     the bot may never ask BELOW  "
                  f"{band['ask_floor_lovelace_per_base_unit']}", file=report)
            print(f"  The same band at --decimals {args.decimals}, in ADA per WHOLE "
                  f"token:", file=report)
            print(f"     bid ceiling  {band['bid_ceiling_ada_per_display_unit']} ADA",
                  file=report)
            print(f"     ask floor    {band['ask_floor_ada_per_display_unit']} ADA",
                  file=report)
            if anchor:
                print(f"     both inside the {band['anchor_ada_per_display_unit'][0]}–"
                      f"{band['anchor_ada_per_display_unit'][1]} ADA band you sourced "
                      f"yourself", file=report)
            else:
                print("     NOT CHECKED: that this is the level you agreed to. The "
                      "chain's\n"
                      "     band relation is symmetric — it bounds the spread, never "
                      "the\n"
                      "     level — so a transposed pair of floors looks exactly like "
                      "an\n"
                      "     honest one here. Pass --expect-band-ada-per-display-unit.",
                      file=report)
            print("     The ask floor is at or above the bid ceiling, so no sequence "
                  "of\n"
                  "     quotes inside this band can be round-tripped against you for a\n"
                  "     profit. These bounds are ABSOLUTE, not market-relative: if the\n"
                  "     market leaves the band the bot cannot quote at all, and a new\n"
                  "     ceremony (new script, new address, new registration, "
                  "client-signed\n"
                  "     re-funding) is the only way back in.", file=report)
        owner = params["client_owner_vkh"]
        if args.my_vkey_file:
            mine = vkh_from_vkey_file(args.my_vkey_file)
            result["my_vkh"] = mine
            if mine != owner:
                raise CeremonyError(
                    f"{args.my_vkey_file} hashes to {mine}, but the ceremony names "
                    f"{owner} as the escape-hatch key. The key that "
                    f"can move your inventory without SaturnSwap is not yours")

        challenge = possession_challenge(
            args.network, integrity["unapplied_script_hash"], encoded)
        digest = possession_digest(challenge)
        result["possession_challenge"] = challenge.hex()
        result["possession_digest"] = digest.hex()
        if args.emit_possession_challenge:
            with open(args.emit_possession_challenge, "w") as fh:
                json.dump(challenge_tx_envelope(challenge), fh, indent=4)
                fh.write("\n")

        possession = check_possession(
            owner, digest, args.possession_proof, args.my_skey_file,
            args.my_vkey_file, shlex.split(args.cardano_cli))
        result["possession"] = possession
        checks["key_hash_matches_your_file"] = bool(args.my_vkey_file)
        checks["key_possession_proved"] = possession["proved"]
        checks["possession_proof_form"] = possession["form"]

        if possession["proved"]:
            print(f"  Escape-hatch key {owner}\n"
                  f"  PROVED: its private half signed this ceremony's challenge "
                  f"({possession['form']}).", file=report)
        else:
            print(f"  NOT PROVED: that anyone can sign for {owner}.\n"
                  f"  A .vkey file is PUBLIC — hashing one says which key the ceremony\n"
                  f"  names, never who holds it. Sign this ceremony's challenge with the\n"
                  f"  key YOU generated, on the machine that holds it:\n", file=report)
            print(f"    challenge  {challenge.hex()}", file=report)
            print(f"    digest     {digest.hex()}", file=report)
            print(f"\n    cardano-cli conway transaction build-raw \\\n"
                  f"        --tx-in {challenge.hex()}#0 --fee 0 \\\n"
                  f"        --out-file possession-challenge.tx\n"
                  f"    cardano-cli conway transaction witness \\\n"
                  f"        --tx-body-file possession-challenge.tx \\\n"
                  f"        --signing-key-file YOUR-escape-hatch.skey \\\n"
                  f"        --out-file possession.witness\n"
                  f"\n  then re-run with --possession-proof possession.witness. That "
                  f"transaction\n  pays nothing, has no outputs and a zero fee: it "
                  f"cannot be submitted, and it\n  is built and signed with no node and "
                  f"no network. --emit-possession-challenge\n  writes it out for an "
                  f"air-gapped signer; --my-skey-file is the shortcut if the\n  key is "
                  f"already on this machine.", file=report)
        print(file=report)

        applied_hash, applied_code, applied_path = apply_params(
            args.aiken, rebuilt_path, encoded, workdir)
        applied_bytes = bytes.fromhex(applied_hash)
        dapp_bytes = bytes.fromhex(params["dapp_hash"])
        derived = {
            "applied_script_hash": applied_hash,
            "order_address": order_address(args.network, dapp_bytes, applied_bytes),
            "reward_address": reward_address(args.network, applied_bytes),
        }
        other = "mainnet" if args.network == "testnet" else "testnet"
        result["derived"] = derived
        result["other_network"] = {
            "network": other,
            "order_address": order_address(other, dapp_bytes, applied_bytes),
            "reward_address": reward_address(other, applied_bytes),
        }
        result["applied_script_size_bytes"] = len(applied_code) // 2

        if args.emit_applied_script:
            # cardano-cli wants the compiledCode wrapped in one further CBOR bytestring; it
            # decodes that once and hashes blake2b-224(0x03 ‖ compiledCode) to the credential.
            raw = bytes.fromhex(applied_code)
            n = len(raw)
            head = (bytes([0x40 | n]) if n < 24 else bytes([0x58, n]) if n < 256 else
                    bytes([0x59]) + n.to_bytes(2, "big") if n < 65536 else
                    bytes([0x5a]) + n.to_bytes(4, "big"))
            with open(args.emit_applied_script, "w") as fh:
                json.dump({"type": "PlutusScriptV3",
                           "description": "maker_stake_bound applied — escape-hatch withdraw-0 witness",
                           "cborHex": (head + raw).hex()}, fh)

        print(f"STEP 3  What your parameters actually produce on {args.network}", file=report)
        print(f"  staking script hash   {derived['applied_script_hash']}", file=report)
        print(f"  ORDER ADDRESS         {derived['order_address']}", file=report)
        print("                        (payment credential is the order script, stake "
              "credential\n                         is your bound script)", file=report)
        print(f"  reward address        {derived['reward_address']}", file=report)
        # The address is a SCRIPT address, and the only thing that makes value at
        # it spendable is a datum the create transaction attaches. "Fund this
        # address" is therefore not an instruction a client can safely follow
        # with a wallet send.
        print("\n  HOW IT MUST BE FUNDED — do not just send to it. This address is only\n"
              "  fundable by a cardano-swaps CREATE transaction that mints this pair's\n"
              f"  beacons under policy {params['beacon_id']}\n"
              "  and attaches a valid INLINE SwapDatum. A plain wallet payment here is\n"
              "  PERMANENTLY UNSPENDABLE — a Plutus script input with no datum can never\n"
              "  be spent, by SaturnSwap, by your escape-hatch key, or by anyone. Fund it\n"
              "  only through the create transaction, and re-run with --check-chain\n"
              "  --require-live afterwards to confirm what landed is a live order.",
              file=report)
        print(f"\n  For reference, the same script on {other} would be a DIFFERENT address:",
              file=report)
        print(f"    order   {result['other_network']['order_address']}", file=report)
        print(f"    reward  {result['other_network']['reward_address']}", file=report)
        print(file=report)

        chain = None
        if args.check_chain:
            chain = check_chain(shlex.split(args.cardano_cli), args.network,
                                args.testnet_magic, derived["order_address"],
                                derived["reward_address"], params["beacon_id"])
            result["chain"] = chain
            print("STEP 4  Read-only chain confirmation", file=report)
            print(f"  stake credential registered   {chain['stake_credential_registered']}"
                  f"  (deposit {chain['stake_registration_deposit']})", file=report)
            # Only your escape-hatch key may publish a delegation certificate, so
            # anything here that you did not sign means the script on chain is not
            # this source. Both are also the brick trigger: once a reward balance
            # accrues, every `+0` withdrawal in the tooling stops building.
            print(f"  stake delegation              {chain['stake_delegation']}", file=report)
            print(f"  vote delegation               {chain['vote_delegation']}", file=report)
            print(f"  reward account balance        {chain['reward_account_balance']}",
                  file=report)
            print(f"  UTxOs at the order address    {chain['order_address_utxo_count']}",
                  file=report)
            for unit, qty in sorted(chain["order_address_holdings"].items()):
                print(f"    {qty} {unit}", file=report)
            if not chain["order_address_holdings"]:
                print("    (nothing yet — expected if you have not funded the ceremony)",
                      file=report)
            print(f"  live orders (inline datum + a beacon of "
                  f"{params['beacon_id'][:12]}…)  {len(chain['live_order_utxos'])}",
                  file=report)
            for txin in chain["unspendable_utxos"]:
                print(f"    UNSPENDABLE  {txin} — no datum at all. Nobody can ever "
                      f"spend it.", file=report)
            for txin in chain["non_inline_datum_utxos"]:
                print(f"    NOT AN ORDER {txin} — datum hash, not an inline datum.",
                      file=report)
            for txin, d in sorted(chain["order_address_utxos"].items()):
                if d["has_inline_datum"] and not d["carries_pair_beacon"]:
                    print(f"    NOT AN ORDER {txin} — carries no beacon of this pair's "
                          f"policy.", file=report)
                for problem in d["datum_problems"]:
                    print(f"    NOT AN ORDER {txin} — {problem}.", file=report)
            print(file=report)

        comparisons = [c for c in (
            compare(args.expect_script_hash, derived["applied_script_hash"],
                    "staking script hash"),
            compare(args.expect_order_address, derived["order_address"], "order address"),
            compare(args.expect_reward_address, derived["reward_address"], "reward address"),
        ) if c is not None]
        result["comparisons"] = comparisons
        mismatches = [c for c in comparisons if not c["match"]]
        result["mismatches"] = mismatches
        checks["expectations_compared"] = [c["what"] for c in comparisons]
        checks["expectations_matched"] = bool(comparisons) and not mismatches
        checks["chain_checked"] = bool(args.check_chain)
        checks["chain_require_live"] = bool(args.require_live)

        chain_failures = []
        if args.check_chain and args.require_live:
            if not chain["stake_credential_registered"]:
                chain_failures.append("the bound stake credential is not registered on chain")
            if not chain["order_address_holdings"]:
                chain_failures.append("the derived order address holds nothing")
            for txin in chain["unspendable_utxos"]:
                chain_failures.append(
                    f"{txin} at the order address carries NO datum. A Plutus script "
                    f"input without a datum can never be spent — not by SaturnSwap, "
                    f"not by your escape-hatch key, not by anyone. That value is "
                    f"unrecoverable, and it is what a plain wallet payment to this "
                    f"address produces; only a cardano-swaps create transaction, "
                    f"minting this pair's beacons with an inline SwapDatum, funds it")
            for txin in chain["non_inline_datum_utxos"]:
                chain_failures.append(
                    f"{txin} at the order address carries a datum HASH, not an inline "
                    f"datum; the cardano-swaps order form reads inline datums, so this "
                    f"is not a live order")
            for txin in chain["malformed_datum_utxos"]:
                for problem in chain["order_address_utxos"][txin]["datum_problems"]:
                    chain_failures.append(
                        f"{txin} at the order address has an inline datum, but "
                        f"{problem}. The dApp validator decodes this datum before it "
                        f"will admit the input, so the value is as stuck as a "
                        f"datum-less deposit")
            if chain["order_address_holdings"] and not chain["live_order_utxos"]:
                chain_failures.append(
                    f"nothing at the order address is a live order: no UTxO has both an "
                    f"inline datum and a beacon under policy {params['beacon_id']}. "
                    f"--require-live means 'your inventory is resting and quotable', "
                    f"not 'something is sitting at the address'")
            if chain["stake_delegation"] is not None:
                chain_failures.append(
                    f"the credential is delegated to pool {chain['stake_delegation']}. "
                    f"Only your escape-hatch key may publish that certificate, so "
                    f"either you signed it or the script on chain is not this source. "
                    f"It also diverts your staking yield and, once a reward accrues, "
                    f"breaks every +0 withdrawal the tooling builds")
            if chain["vote_delegation"] is not None:
                chain_failures.append(
                    f"the credential's governance vote is delegated to "
                    f"{chain['vote_delegation']}, which only your escape-hatch key may "
                    f"publish")
        result["chain_failures"] = chain_failures

        # Not proving possession is not a broken ceremony and not a broken
        # funding — it is a verdict this run has not earned the right to print.
        key_failures = [] if possession["proved"] or args.derive_only else [
            f"nobody has proved they can sign for the escape-hatch key {owner}. "
            f"Hashing a verification key establishes only that a PUBLIC file "
            f"hashes to that parameter, which the operator can arrange while "
            f"keeping the signing half. See the challenge and the commands "
            f"printed above"]
        result["key_failures"] = key_failures
        blocked = mismatches or chain_failures or key_failures

        print("VERDICT", file=report)
        # An escape derivation can compare, and still never becomes a verdict: the
        # ceremony it came from is one this tool refuses to endorse.
        # A recovery may COMPARE — it is the only mode that derives an address for
        # an incoherent ceremony, so a client escaping one would otherwise be
        # handed an address with no way to check it against the one they funded.
        # It still never becomes a verdict: no possession was proved and the
        # ceremony behind it is one this tool refuses to endorse.
        if args.for_escape:
            escaping = "coherence_refusal" in result
            result["verdict"] = (
                "refused" if chain_failures
                else "escape-derivation" if escaping else "derive-only")
            for failure in chain_failures:
                print(f"  FAIL  {failure}", file=report)
            for c in mismatches:
                print(f"  MISMATCH on the {c['what']}:", file=report)
                print(f"    you were told  {c['expected']}", file=report)
                print(f"    source derives {c['derived']}", file=report)
            if escaping:
                print("  FOR ESCAPE ONLY — the addresses above are derived from a ceremony "
                      "this\n  tool refuses to endorse, stated at STEP 2. It is enough to "
                      "get your\n  inventory out and it is not enough for anything else. "
                      "ok:false and\n  verdict:\"escape-derivation\" say so to anything "
                      "reading this document.", file=report)
            else:
                print("  DERIVED FOR RECOVERY — this ceremony raised no coherence refusal, "
                      "but\n  --for-escape asserts nothing either way. Re-run without it "
                      "for a verdict.", file=report)
            if mismatches:
                print("\n  AND IT DOES NOT MATCH what you were told. Recovering from the "
                      "address\n  your OWN parameters derive is still correct — that is "
                      "where the script\n  put your inventory — but one of the parameters "
                      "you were handed is not\n  the one behind the address you were "
                      "shown.", file=report)
        elif args.derive_only and not comparisons:
            if chain_failures:
                result["verdict"] = "refused"
            elif "coherence_refusal" in result:
                # Its own verdict, not "derive-only": this document derives from a
                # ceremony the tool refuses to endorse, and a consumer must not be
                # able to mistake it for one that merely asserted nothing.
                result["verdict"] = "escape-derivation"
            else:
                result["verdict"] = "derive-only"
            for failure in chain_failures:
                print(f"  FAIL  {failure}", file=report)
            if result["verdict"] == "escape-derivation":
                print("  FOR ESCAPE ONLY — the addresses above are derived from a "
                      "ceremony this\n  tool refuses to endorse, stated at STEP 2. It "
                      "is enough to get your\n  inventory out and it is not enough for "
                      "anything else. ok:false and\n  verdict:\"escape-derivation\" "
                      "say so to anything reading this document.", file=report)
            if result["verdict"] == "derive-only":
                print("  DERIVED ONLY — nothing was compared and nothing is asserted. "
                      "Re-run with\n  --expect-order-address <the address SaturnSwap "
                      "gave you> and a possession\n  proof to get a verdict. This "
                      "document reports ok:false and verdict:\n  \"derive-only\" "
                      "precisely so it cannot be mistaken for one.", file=report)
        elif blocked:
            for c in mismatches:
                print(f"  MISMATCH on the {c['what']}:", file=report)
                print(f"    you were told  {c['expected']}", file=report)
                print(f"    source derives {c['derived']}", file=report)
            for failure in chain_failures + key_failures:
                print(f"  FAIL  {failure}", file=report)
            # Three different verdicts wear the same exit code, and conflating
            # them would either cry wolf about the parameters or wave through a
            # real mismatch: an address that does not match is a broken CEREMONY,
            # an address that matches but is not live is a broken FUNDING, and an
            # unproved escape hatch is neither — it is a missing input.
            if mismatches:
                print("\n  DO NOT FUND THIS ADDRESS. The script SaturnSwap is pointing you "
                      "at\n  is not the script your parameters describe: at least one of "
                      "your\n  price floors, your payout address, or your escape-hatch key "
                      "is not\n  what you agreed to. Ask for the exact parameters they "
                      "applied and\n  re-run this tool until every line matches.",
                      file=report)
            elif chain_failures:
                print("\n  The ceremony itself checks out — every derived value matches "
                      "what\n  you were told. What --require-live judged on chain does not: "
                      "see the\n  FAIL line(s) above. Nothing here says the script is wrong; "
                      "it says the\n  state at that address is not a live, healthy order.",
                      file=report)
            else:
                print("\n  NO VERDICT. Every derived value matches what you were told, so "
                      "the\n  ceremony is the one your parameters describe — but which of "
                      "the two\n  28-byte keys in it is YOURS is precisely what a matching "
                      "address\n  cannot show, and it is the difference between a self-"
                      "custody escape\n  hatch and the operator's. Sign the challenge above "
                      "and re-run.", file=report)
        else:
            for c in comparisons:
                print(f"  MATCH  {c['what']}  {c['derived']}", file=report)
            result["verdict"] = "verified"
            print("\n  VERIFIED. The address you were given is exactly the script that:", file=report)
            print(f"    - lets only {params['client_owner_vkh']} move your inventory\n"
                  f"      unconditionally, with no help from SaturnSwap — and the PRIVATE\n"
                  f"      half of that key signed this ceremony's challenge "
                  f"({possession['form']}),\n"
                  f"      so it is a key that can actually be signed for. Nothing on chain\n"
                  f"      could have told you that: the validator sees two 28-byte strings\n"
                  f"      and cannot know which of them anyone can sign for.\n"
                  f"      What this does NOT establish is that you are the ONLY holder —\n"
                  f"      no off-chain check can. That follows from you having generated\n"
                  f"      the key yourself and produced that signature yourself, on a\n"
                  f"      machine the operator does not control. If the operator handed\n"
                  f"      you either one, this line is worth nothing;", file=report)
            print(f"    - lets the bot {params['adam_bot_pkh']}\n"
                  f"      reprice and cancel, but only into this address, or to\n"
                  f"      {params['client_payout_address']},\n"
                  f"      or — up to {params['fee_bps']} basis points of what your position\n"
                  f"      realizes, and never more, and NOTHING at all on a transaction\n"
                  f"      that closes an order — to the operator's fee address\n"
                  f"      {params['fee_address']}.\n"
                  f"      That address is recognised by SHAPE, so every ADA-only\n"
                  f"      datum-free output at it counts as fee. The operator must use\n"
                  f"      it for nothing else, including change, or no action of theirs\n"
                  f"      can validate at all;", file=report)
            print(f"    - caps the bot's BID at "
                  f"{band['bid_ceiling_ada_per_display_unit']} ADA and floors its ASK\n"
                  f"      at {band['ask_floor_ada_per_display_unit']} ADA per whole token "
                  f"at --decimals {args.decimals}\n"
                  f"      (raw: {band['bid_ceiling_lovelace_per_base_unit']} and "
                  f"{band['ask_floor_lovelace_per_base_unit']} "
                  f"{FLOOR_UNITS_CAVEAT}).\n"
                  f"      Both sit inside the {band['anchor_ada_per_display_unit'][0]}–"
                  f"{band['anchor_ada_per_display_unit'][1]} ADA band you sourced "
                  f"yourself, and the\n"
                  f"      floor is at or above the ceiling — so neither leg can be "
                  f"repriced to\n"
                  f"      dust AND no sequence of in-band quotes can be round-tripped "
                  f"against you.\n"
                  f"      That first half holds only because you supplied the level: the\n"
                  f"      on-chain relation is symmetric and bounds the spread alone;",
                  file=report)
            print(f"    - can only ever be deregistered, delegated or vote-delegated by\n"
                  f"      your escape-hatch key. The bot may only REGISTER it.", file=report)
            print("\n  Still NOT on-chain invariants, and not asserted here: which pairs\n"
                  "  get quoted, order-flow timing, fill quality, and quote staleness.\n"
                  f"  --decimals {args.decimals} and the band above are YOUR inputs — this\n"
                  "  tool checked the ceremony against them, it did not check them.",
                  file=report)
    except CeremonyError as exc:
        result["verdict"] = "refused"
        result["error"] = str(exc)
        print(f"\nREFUSED: {exc}", file=report)
    finally:
        # `ok` means VERIFIED and nothing else. A derive-only run compares
        # nothing and checks nothing, so it is not ok — it is a derivation, and
        # a consumer that reads `ok` or `verdict` cannot mistake it for a verdict.
        result["ok"] = result["verdict"] == "verified"
        shutil.rmtree(workdir, ignore_errors=True)
        if args.json_out:
            line = json.dumps(result, separators=(",", ":"), sort_keys=True)
            if json_to_stdout:
                print(line)
            else:
                with open(args.json_out, "w") as fh:
                    fh.write(line + "\n")

    return 0 if result["verdict"] in ("verified", "derive-only", "escape-derivation") else 1


if __name__ == "__main__":
    sys.exit(main())
