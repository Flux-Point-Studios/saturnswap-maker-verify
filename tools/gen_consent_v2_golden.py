#!/usr/bin/env python3
"""Emits testdata/consent-v2.golden.json, the fixture the keeper (adam-oc) and the page
(SaturnSwapWeb) pin their v2 consent statement to, and with --edges the additive
testdata/consent-v2.edges.golden.json.

Every payload is rendered by verify_ceremony.py, the reference renderer, over the live NIGHT
ceremony; the edges' decimals cases replace only its price band. Each non-canonical variant is
one of those payloads with one defect, named with the rule of spec 3.3 that must refuse it
first. Deterministic, offline, stdlib only:

    python3 tools/gen_consent_v2_golden.py > testdata/consent-v2.golden.json
    python3 tools/gen_consent_v2_golden.py --edges > testdata/consent-v2.edges.golden.json
"""
import argparse
import json
import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import verify_ceremony as vc  # noqa: E402

NETWORK = "mainnet"
# The generation the live NIGHT book was applied to (spec 1.2); its challenge answers this hash
# whatever generation the repository root publishes later.
UNAPPLIED_SCRIPT_HASH = "19cc10abe5dfedee65c53d82548a1e6e2997f52c52a70af4170321fe"
NIGHT_PARAMS = {
    "adam_bot_pkh": "cea98dfce26e0ffbf5ab892edcb8f8ab8b794d5390f80ec0b9aafed3",
    "client_owner_vkh": "59ff9cf52f1a7cfb42be19a39c7dc58910d1e2f237c80f0b8a216b8a",
    "client_payout_address": "addr1v9vll8849ud8e76zhcv688racky3p50z7gmusrct3gskhzsuk43my",
    "dapp_hash": "11928a3ac3b65edbf103ea6bb3362e39b879a36f02897df31c40917b",
    "beacon_id": "8a199a17ef4517215945aaf3c8c5204c60fd94d34c46d341e99c8fcf",
    "min_asset1_price": {"numerator": 1000, "denominator": 97},
    "min_asset2_price": {"numerator": 1, "denominator": 10},
    "fee_address": "addr1v9wr69p2tx8dx2lat8rzznahxh4xhfl075yzm8uxmth4tvcf3lx47",
    "fee_bps": 20,
}
NIGHT_POLICY = "0691b2fecca1ac4f53cb6dfb00b7013e561d1f34403b957cbb5af1fa"
# Spec 2.2's terms with the section 11 daily-loss knob at its default, 500 bps.
DEFAULT_TERMS = {"spreadBps": 800, "maxDepthAda": 120, "dailyLossBps": 500, "minRepriceBps": 150}
SIGNED_AT = "2026-09-23T18:40:26Z"
SIGNED_AT_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
EPOCH = datetime(1970, 1, 1)

# JavaScript's Date.UTC reads years 0 to 99 as 1900 to 1999; each of these is a real instant the
# reference accepts.
EARLY_SIGNED_AT = (
    ("0001-01-01T00:00:00Z", "year 1, where the reference calendar starts (Python's MINYEAR); "
                             "Date.UTC reads it as 1901"),
    ("0050-06-15T00:00:00Z", "Date.UTC reads year 50 as 1950"),
    ("0099-12-31T23:59:59Z", "Date.UTC reads it as 1999-12-31T23:59:59Z"),
    ("0100-01-01T00:00:00Z", "the first year Date.UTC reads as written, one second after the "
                             "case before"),
)
# Token decimals other than 6, each with a band (params 5 and 6, lovelace per base unit) whose
# price limits are not the band read as it is: a quarter lovelace at 0, 125,000 lovelace at 2
# and 3.5 * 10^-13 lovelace at 18. The policy ids are illustrative.
DECIMALS_CASES = (
    ("readable", 0, "89fa7fb0ad88ae98863765041e61b24a33bcf9e88a0f163d0522e348", b"Grain_0.a-Z9",
     {"numerator": 4, "denominator": 1}, {"numerator": 3, "denominator": 10}),
    ("hex", 2, "444e1186d462c7595c714699375af5fe6dc21fac75a36bffab19ccce",
     bytes.fromhex("0014df10") + b"CENT",
     {"numerator": 1, "denominator": 125000}, {"numerator": 130625, "denominator": 1}),
    ("readable", 18, "1f76a03d0402f2508f506a72d3b018183a38ba8242a3e230e8cef837", b"BRIDGED18",
     {"numerator": 20_000_000_000_000, "denominator": 7},
     {"numerator": 29, "denominator": 80_000_000_000_000}),
)


def consent(asset_name, policy=NIGHT_POLICY, decimals=6, signed_at=SIGNED_AT, **terms):
    return {"token": {"policyId": policy, "assetNameHex": asset_name.hex()},
            "decimals": decimals, "terms": dict(DEFAULT_TERMS, **terms), "signedAt": signed_at}


def ceremony(params):
    """The challenge these params give on the NIGHT book's generation, and the ceremony object a
    golden carries for them."""
    encoded, _ = vc.encode_params(params, NETWORK)
    challenge = vc.possession_challenge(NETWORK, UNAPPLIED_SCRIPT_HASH, encoded)
    return challenge, {
        "network": NETWORK,
        "unappliedScriptHash": UNAPPLIED_SCRIPT_HASH,
        "params": params,
        "paramCborHex": [p["plutus_data_cbor_hex"] for p in encoded],
        "challengeHex": challenge.hex(),
    }


def statement(challenge, params, values):
    return vc.canonical_consent_payload_v2(challenge, NETWORK, params, values)


def emit():
    challenge, night_ceremony = ceremony(NIGHT_PARAMS)

    def render(values):
        return statement(challenge, NIGHT_PARAMS, values)

    def edit(text, old, new):
        if text.count(old) != 1:
            raise ValueError(f"{old!r} occurs {text.count(old)} times, not once")
        return text.replace(old, new)

    def shown_as_readable(values, shown):
        """The canonical statement for `values`, with its token line rewritten to show `shown`
        as the readable name of the same policy and name bytes."""
        text = render(values)
        token = values["token"]
        return edit(text, "\n" + text.split("\n")[7] + "\n",
                    f"\nyour token: {shown} (policy {token['policyId']}, "
                    f"asset name hex {token['assetNameHex']})\n")

    cases = (
        ("readable", consent(b"NIGHT")),
        ("hex", consent(bytes.fromhex("0014df10") + b"NIGHT", spreadBps=405, maxDepthAda=60,
                        dailyLossBps=5000, minRepriceBps=200)),
        ("empty", consent(b"", spreadBps=6000, maxDepthAda=61, dailyLossBps=100,
                          minRepriceBps=1000)),
    )
    rendered = [(form, values, render(values)) for form, values in cases]
    night = rendered[0][2]
    spread_line = next(line for line in night.split("\n") if line.startswith("spread: "))
    widest_cap = "9" * (2049 - len(night) + len(str(DEFAULT_TERMS["maxDepthAda"])))

    variants = (
        ("CR", "3.3.1", "CRLF line endings",
         night.replace("\n", "\r\n")),
        ("trailing space", "3.3.2", "a space at the end of the challenge line",
         night[:-1] + " \n"),
        ("leading zero", "3.3.4", "spread written 0800",
         edit(night, "spread: 800 bps", "spread: 0800 bps")),
        ("8.0%", "3.3.5", "the spread percentage written 8.0",
         edit(night, "(8%)", "(8.0%)")),
        ("upper-case hex", "3.3.4", "the policy id in upper case",
         edit(night, NIGHT_POLICY, NIGHT_POLICY.upper())),
        ("em dash", "3.3.1", "U+2014 in the header, where the v1 header carried one",
         edit(night, "SaturnSwap MMaaS consent", "SaturnSwap MMaaS \u2014 consent")),
        ("non-breaking space", "3.3.1", "U+00A0 between 20 and bps in the fee line",
         edit(night, "at most 20 bps", "at most 20\u00a0bps")),
        ("14 lines", "3.3.2", "the reprice line removed",
         edit(night, "reprice after our price moves: 150 bps (1.5%)\n", "")),
        ("16 lines", "3.3.2", "the spread line twice",
         edit(night, spread_line + "\n", spread_line + "\n" + spread_line + "\n")),
        ("decimals 19", "3.3.4", "token decimals 19, above the keeper's 18",
         edit(night, "token decimals: 6\n", "token decimals: 19\n")),
        ("2026-02-30T00:00:00Z", "3.3.4", "a signed-at time that is no calendar instant",
         edit(night, SIGNED_AT, "2026-02-30T00:00:00Z")),
        ("spoofed readable name", "3.3.5",
         "NIGHT shown for a CIP-68 name (0014df10 + NIGHT) whose bytes have no readable form",
         shown_as_readable(cases[1][1], "NIGHT")),
        ("2,049 bytes", "3.3.1",
         "canonical in every other respect, with a book value cap long enough to reach 2,049 bytes",
         render(consent(b"NIGHT", maxDepthAda=int(widest_cap)))),
        ("readable name the bytes do not produce", "3.3.5",
         "NIGHT shown for the name bytes of NlGHT, with a lower-case L",
         shown_as_readable(consent(b"NlGHT"), "NIGHT")),
        ("name with a space shown as readable", "3.3.5",
         "MY TOKEN shown as a readable name; a space can imitate the line's own syntax",
         shown_as_readable(consent(b"MY TOKEN"), "MY TOKEN")),
        ("name with a parenthesis shown as readable", "3.3.5",
         "NIGHT) shown as a readable name; a parenthesis can imitate the line's own syntax",
         shown_as_readable(consent(b"NIGHT)"), "NIGHT)")),
        ("altered consent sentence", "3.3.3", "its bot key widened to any key",
         edit(night, "with its bot key,", "with any key,")),
    )

    golden = {
        "note": "GENERATED by tools/gen_consent_v2_golden.py from verify_ceremony.py, the "
                "reference renderer of the v2 consent statement (D2 spec 2.1, 2.3, 3.3 and "
                "section 11). Do not edit by hand. The readable case is the spec 2.2 NIGHT "
                "example with dailyLossBps 500, the section 11 default. Every variant is "
                "parsed against this ceremony; its rule is the check of spec 3.3 that refuses "
                "it first.",
        "ceremony": night_ceremony,
        "cases": [
            {"tokenLineForm": form, "consent": values, "tokenLine": text.split("\n")[7],
             "payload": text, "payloadHex": text.encode().hex()}
            for form, values, text in rendered
        ],
        "fundingCapLovelace": [
            {"maxDepthAda": cap, "fundingCapLovelace": cap * 1_000_000 * 5 // 6}
            for cap in (60, 61, 120)
        ],
        "variants": [
            {"name": name, "rule": rule, "why": why, "payloadHex": text.encode("utf-8").hex()}
            for name, rule, why, text in variants
        ],
    }
    return json.dumps(golden, indent=2) + "\n"


def emit_edges():
    night_challenge, night_ceremony = ceremony(NIGHT_PARAMS)

    def night_signed_at(signed_at):
        values = consent(b"NIGHT", signed_at=signed_at)
        return values, statement(night_challenge, NIGHT_PARAMS, values)

    signed_at_cases = []
    for signed_at, why in EARLY_SIGNED_AT:
        values, text = night_signed_at(signed_at)
        signed_at_cases.append({
            "why": why, "consent": values, "payload": text, "payloadHex": text.encode().hex(),
            "signedAtUnix": (datetime.strptime(signed_at, SIGNED_AT_FORMAT) - EPOCH)
            // timedelta(seconds=1),
        })

    decimals_cases = []
    for form, decimals, policy, name, bid_cap, ask_floor in DECIMALS_CASES:
        params = dict(NIGHT_PARAMS, min_asset1_price=bid_cap, min_asset2_price=ask_floor)
        challenge, case_ceremony = ceremony(params)
        values = consent(name, policy=policy, decimals=decimals)
        text = statement(challenge, params, values)
        lines = text.split("\n")
        decimals_cases.append({
            "tokenLineForm": form, "ceremony": case_ceremony, "consent": values,
            "tokenLine": lines[7], "priceLimitsLine": lines[6], "payload": text,
            "payloadHex": text.encode().hex(),
        })

    _, year_zero = night_signed_at("0000-01-01T00:00:00Z")
    edges = {
        "note": "GENERATED by tools/gen_consent_v2_golden.py --edges from verify_ceremony.py, "
                "the reference renderer of the v2 consent statement (D2 spec 2.1, 2.3, 3.3 and "
                "section 11). Do not edit by hand. Frozen from the push that adds it: a change "
                "is a new file, never an edit. Additive to consent-v2.golden.json, every case "
                "of which is signed in 2026 at token decimals 6. signedAtCases are that "
                "golden's readable NIGHT case signed in years 1 to 100, each with "
                "signedAtUnix, its proleptic-Gregorian seconds since 1970 (negative); "
                "JavaScript's Date.UTC reads years 0 to 99 as 1900 to 1999. The one variant, "
                "signed in year 0000, is refused by rule 3.3.4: the reference calendar starts "
                "at year 1. decimalsCases are at token decimals 0, 2 and 18, each over the "
                "NIGHT ceremony with only its price band (params 5 and 6) replaced, and carry "
                "that ceremony; their price limits are the band times 10^decimals / 10^6 ADA "
                "per token, which only at decimals 6 is the band as it is. Their policy ids "
                "are illustrative.",
        "ceremony": night_ceremony,
        "signedAtCases": signed_at_cases,
        "decimalsCases": decimals_cases,
        "variants": [
            {"name": "0000-01-01T00:00:00Z", "rule": "3.3.4",
             "why": "a signed-at time in year 0000, before year 1, where the reference calendar "
                    "starts; a proleptic-Gregorian check in JavaScript accepts it",
             "payload": year_zero, "payloadHex": year_zero.encode().hex()},
        ],
    }
    return json.dumps(edges, indent=2) + "\n"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Emit a v2 consent golden to standard output.")
    parser.add_argument("--edges", action="store_true",
                        help="emit testdata/consent-v2.edges.golden.json instead of the golden")
    sys.stdout.write(emit_edges() if parser.parse_args().edges else emit())
