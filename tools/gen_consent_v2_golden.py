#!/usr/bin/env python3
"""Emits testdata/consent-v2.golden.json, the fixture the keeper (adam-oc) and the page
(SaturnSwapWeb) pin their v2 consent statement to.

Every payload is rendered by verify_ceremony.py, the reference renderer, over the live NIGHT
ceremony. Each non-canonical variant is one of those payloads with one defect, named with the
rule of spec 3.3 that must refuse it first. Deterministic, offline, stdlib only:

    python3 tools/gen_consent_v2_golden.py > testdata/consent-v2.golden.json
"""
import json
import os
import sys

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


def consent(asset_name, **terms):
    return {"token": {"policyId": NIGHT_POLICY, "assetNameHex": asset_name.hex()},
            "decimals": 6, "terms": dict(DEFAULT_TERMS, **terms), "signedAt": SIGNED_AT}


def emit():
    encoded, _ = vc.encode_params(NIGHT_PARAMS, NETWORK)
    challenge = vc.possession_challenge(NETWORK, UNAPPLIED_SCRIPT_HASH, encoded)

    def render(values):
        return vc.canonical_consent_payload_v2(challenge, NETWORK, NIGHT_PARAMS, values)

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
        "ceremony": {
            "network": NETWORK,
            "unappliedScriptHash": UNAPPLIED_SCRIPT_HASH,
            "params": NIGHT_PARAMS,
            "paramCborHex": [p["plutus_data_cbor_hex"] for p in encoded],
            "challengeHex": challenge.hex(),
        },
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


if __name__ == "__main__":
    sys.stdout.write(emit())
