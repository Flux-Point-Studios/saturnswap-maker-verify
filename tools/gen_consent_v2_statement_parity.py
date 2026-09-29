#!/usr/bin/env python3
"""Generate statement parser parity cases from verify_ceremony.py at fc1e18d.

Run from the repository root:
    python tools/gen_consent_v2_statement_parity.py > testdata/consent-v2.statement-parity.json
"""
import json
import sys
from fractions import Fraction

import gen_consent_v2_golden as source
import verify_ceremony as reference


def rational(value):
    return {"numerator": value.numerator, "denominator": value.denominator}


def prices():
    for places in range(1, 201):
        low = Fraction(1, 10 ** places)
        high = Fraction(21, 10 ** places)
        yield f"fractional-{places}", low, high
    for digits in range(1, 201):
        low = Fraction(10 ** digits + 1)
        yield f"integer-{digits}", low, low + 1
    for places in range(1, 70):
        low = Fraction(12345 * 10 ** places + 67, 10 ** (places + 5))
        yield f"mixed-{places}", low, low + Fraction(21, 1000)


def emit():
    challenge = bytes.fromhex(source.ceremony(source.NIGHT_PARAMS)[1]["challengeHex"])
    cases = []
    for decimals in (0, 2, 18):
        scale = Fraction(10 ** decimals, 1_000_000)
        for name, low, high in prices():
            if decimals == 0 and name == "fractional-19":
                high = Fraction(21, 10_000)
            params = dict(source.NIGHT_PARAMS)
            params["min_asset1_price"] = rational(scale / low)
            params["min_asset2_price"] = rational(high / scale)
            consent = source.consent(b"NIGHT", decimals=decimals)
            payload = reference.canonical_consent_payload_v2(challenge, source.NETWORK, params, consent)
            candidates = [(name, payload)]
            if name in ("fractional-19", "integer-19", "mixed-19"):
                candidates.append((f"{name}-noncanonical", payload.replace("your book never buys above ", "your book never buys above 0", 1)))
            for case_name, statement in candidates:
                try:
                    parsed = reference.parse_consent_payload_v2(statement.encode("ascii"), challenge, source.NETWORK, params)
                    accepted = parsed == consent
                except reference.ConsentStatementRefused:
                    accepted = False
                cases.append({
                    "name": f"decimals-{decimals}-{case_name}",
                    "decimals": decimals,
                    "min_asset1_price": params["min_asset1_price"],
                    "min_asset2_price": params["min_asset2_price"],
                    "low": reference._exact_decimal(low),
                    "high": reference._exact_decimal(high),
                    "payload": statement,
                    "reference": {"accepted": accepted},
                })
    print(json.dumps({
        "provenance": {
            "repo": "Flux-Point-Studios/saturnswap-maker-verify",
            "commit": "fc1e18de3f7b44a9e4299cd3059dbc3a9cef8510",
            "reader": "verify_ceremony.py parse_consent_payload_v2",
            "generator": "tools/gen_consent_v2_statement_parity.py",
        },
        "ceremony": {"network": source.NETWORK, "challengeHex": challenge.hex(), "params": source.NIGHT_PARAMS},
        "cases": cases,
    }, ensure_ascii=True, indent=1))


if __name__ == "__main__":
    sys.stdout.reconfigure(newline="\n")
    emit()
