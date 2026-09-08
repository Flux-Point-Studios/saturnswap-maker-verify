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

class Generations(unittest.TestCase):
    def test_historical_source_rebuilds_the_original_ceremony(self):
        rc, out, err, doc = run_tool(
            GOLDEN_PARAMS, project=os.path.join(HERE, "generations", HISTORICAL_HASH),
            extra=["--derive-only", "--expect-script-hash", HISTORICAL_APPLIED,
                   "--expect-order-address", HISTORICAL_ORDER,
                   "--expect-reward-address", HISTORICAL_REWARD], vkey=None, proof=None)
        self.assertEqual(rc, 0, out + err)
        self.assertTrue(doc["source_integrity"]["ok"])
        self.assertEqual(doc["source_integrity"]["unapplied_script_hash"], HISTORICAL_HASH)
        self.assertEqual(doc["derived"]["applied_script_hash"], HISTORICAL_APPLIED)
        self.assertNotEqual(doc["derived"]["applied_script_hash"], GOLDEN_APPLIED_HASH)

    def test_current_source_cannot_verify_the_old_order_address(self):
        rc, out, err, doc = run_tool(
            GOLDEN_PARAMS, extra=["--derive-only", "--expect-order-address", HISTORICAL_ORDER],
            vkey=None, proof=None)
        self.assertNotEqual(rc, 0, out + err)
        self.assertIn("order", doc["error"].lower())

    def test_historical_source_cannot_verify_the_current_script(self):
        rc, out, err, doc = run_tool(
            GOLDEN_PARAMS, project=os.path.join(HERE, "generations", HISTORICAL_HASH),
            extra=["--derive-only", "--expect-script-hash", GOLDEN_APPLIED_HASH],
            vkey=None, proof=None)
        self.assertNotEqual(rc, 0, out + err)
        self.assertIn("hash", doc["error"].lower())

if __name__ == "__main__":
    unittest.main()
