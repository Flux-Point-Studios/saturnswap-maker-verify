#!/usr/bin/env python3
"""Rebuild both generations and reject a current-source claim about an old address."""
import os
import unittest
from verify_ceremony_test import GOLDEN_PARAMS, GOLDEN_APPLIED_HASH, HERE, run_tool

HISTORICAL_HASH = "adc2a7f19bf63b378c06c7d941bba6b7f6312cb8cce5b153f356efe4"
HISTORICAL_APPLIED = "527d9225d577fbe82cf9dbd611379d5c49fa6d8a1610c7e658f76700"
HISTORICAL_ORDER = (
    "addr_test1xqge9z36cwm9akl3q04xhvek9cums7drdupgjl0nr3qfz76j0kfzt4thl05"
    "ze7wm6cgn082uf8axmzskzrr7vk8hvuqqj724uz"
)
HISTORICAL_REWARD = "stake_test17pf8my3964mlh6pvl8davyfhn4wyn7nd3gtpp3lxtrmkwqq2507cr"

HISTORICAL_PROOF = bytes.fromhex('831dc5939dd7b6eac6deec8793796acfc6e27684dfe86e6e81eec8ab5594be2ae1a40ba8686109c1eda9a5199e81e3c70f186017c03d6be708d3433ea265ca0f')

class Generations(unittest.TestCase):
    def test_historical_source_rebuilds_the_original_ceremony(self):
        rc, out, err, doc = run_tool(
            GOLDEN_PARAMS, project=os.path.join(HERE, "generations", HISTORICAL_HASH),
            extra=["--expect-script-hash", HISTORICAL_APPLIED,
                   "--expect-order-address", HISTORICAL_ORDER,
                   "--expect-reward-address", HISTORICAL_REWARD], proof=HISTORICAL_PROOF)
        self.assertEqual(rc, 0, out + err)
        self.assertTrue(doc["source_integrity"]["ok"])
        self.assertEqual(doc["source_integrity"]["unapplied_script_hash"], HISTORICAL_HASH)
        self.assertEqual(doc["derived"]["applied_script_hash"], HISTORICAL_APPLIED)
        self.assertNotEqual(doc["derived"]["applied_script_hash"], GOLDEN_APPLIED_HASH)

    def test_current_source_cannot_verify_the_old_order_address(self):
        rc, out, err, doc = run_tool(
            GOLDEN_PARAMS, extra=["--expect-order-address", HISTORICAL_ORDER])
        self.assertNotEqual(rc, 0, out + err)
        self.assertTrue(any(m["what"] == "order address" for m in doc["mismatches"]))

    def test_historical_source_cannot_verify_the_current_script(self):
        rc, out, err, doc = run_tool(
            GOLDEN_PARAMS, project=os.path.join(HERE, "generations", HISTORICAL_HASH),
            extra=["--expect-script-hash", GOLDEN_APPLIED_HASH], proof=HISTORICAL_PROOF)
        self.assertNotEqual(rc, 0, out + err)
        self.assertTrue(any("script hash" in m["what"] for m in doc["mismatches"]))

if __name__ == "__main__":
    unittest.main()
