#!/usr/bin/env python3
"""Rebuild every published generation and reject a current-source claim about an old address.

⚠️ A GENERATION THAT SHIPS WITHOUT LANDING HERE IS A CLIENT WHO CANNOT LEAVE. An order address
commits to the applied validator, so the only source that rebuilds it is the generation its
credential hashes. If that source is not in this repository, the client cannot verify the address
they funded and `escape.sh` correctly refuses to act on it — which leaves the escape hatch needing
the operator, the one thing it is supposed to never need. So each generation gets a row here and a
directory, and `test_every_published_generation_is_documented` fails if the two ever disagree.
"""
import os
import re
import unittest
from verify_ceremony_test import GOLDEN_PARAMS, GOLDEN_APPLIED_HASH, HERE, run_tool

CURRENT_HASH = "19cc10abe5dfedee65c53d82548a1e6e2997f52c52a70af4170321fe"

# Each retired generation, with the ceremony the SAME nine parameters produce on it. The proofs are
# committed because the challenge binds the generation: a signature minted for one cannot answer
# another's, which is exactly what stops a proof being carried across a silent source swap.
HISTORICAL = {
    "adc2a7f19bf63b378c06c7d941bba6b7f6312cb8cce5b153f356efe4": {
        "applied": "527d9225d577fbe82cf9dbd611379d5c49fa6d8a1610c7e658f76700",
        "order": (
            "addr_test1xqge9z36cwm9akl3q04xhvek9cums7drdupgjl0nr3qfz76j0kfzt4thl05"
            "ze7wm6cgn082uf8axmzskzrr7vk8hvuqqj724uz"
        ),
        "reward": "stake_test17pf8my3964mlh6pvl8davyfhn4wyn7nd3gtpp3lxtrmkwqq2507cr",
        "proof": bytes.fromhex(
            "831dc5939dd7b6eac6deec8793796acfc6e27684dfe86e6e81eec8ab5594be2a"
            "e1a40ba8686109c1eda9a5199e81e3c70f186017c03d6be708d3433ea265ca0f"),
    },
    "18d2246d8b552b9e462ec93dece5716a7154314680b3f326a854789d": {
        "applied": "cb927890105ec125dfcdbad4f997a6ab04f4ff7f576dda96d30d2538",
        "order": (
            "addr_test1xqge9z36cwm9akl3q04xhvek9cums7drdupgjl0nr3qfz77tjfufq"
            "yz7cyjalnd66nue0f4tqn607l6hdhdfd5cdy5uqw4cfjh"
        ),
        "reward": "stake_test17r9ey7yszp0vzfwlekadf7vh564sfa8l0atkmk5k6vxj2wq6tu2xd",
        "proof": bytes.fromhex(
            "f6a2671d05cea9e72404a0a3b1892f0f2ea64cf05fe8251ad3c188db7d6dffc5"
            "b127010d4a9fb0db476459a0108aa53d08c33bfd584b2855ed165f624a24630d"),
    },
}


class Generations(unittest.TestCase):
    def test_each_historical_source_rebuilds_its_own_ceremony(self):
        for h, g in HISTORICAL.items():
            with self.subTest(generation=h):
                rc, out, err, doc = run_tool(
                    GOLDEN_PARAMS, project=os.path.join(HERE, "generations", h),
                    extra=["--expect-script-hash", g["applied"],
                           "--expect-order-address", g["order"],
                           "--expect-reward-address", g["reward"]], proof=g["proof"])
                self.assertEqual(rc, 0, out + err)
                self.assertTrue(doc["source_integrity"]["ok"])
                self.assertEqual(doc["source_integrity"]["unapplied_script_hash"], h)
                self.assertEqual(doc["derived"]["applied_script_hash"], g["applied"])
                self.assertNotEqual(doc["derived"]["applied_script_hash"], GOLDEN_APPLIED_HASH)

    def test_current_source_cannot_verify_an_old_order_address(self):
        for h, g in HISTORICAL.items():
            with self.subTest(generation=h):
                rc, out, err, doc = run_tool(
                    GOLDEN_PARAMS, extra=["--expect-order-address", g["order"]])
                self.assertNotEqual(rc, 0, out + err)
                self.assertTrue(any(m["what"] == "order address" for m in doc["mismatches"]))

    def test_no_historical_source_can_verify_the_current_script(self):
        for h, g in HISTORICAL.items():
            with self.subTest(generation=h):
                rc, out, err, doc = run_tool(
                    GOLDEN_PARAMS, project=os.path.join(HERE, "generations", h),
                    extra=["--expect-script-hash", GOLDEN_APPLIED_HASH], proof=g["proof"])
                self.assertNotEqual(rc, 0, out + err)
                self.assertTrue(any("script hash" in m["what"] for m in doc["mismatches"]))

    # ⚠️ The guard for the failure that produced this file's header. A generation can be retired
    # into `generations/` and never written down, or written down and never shipped; either way a
    # client reading GENERATIONS.md is told something the repository cannot do.
    def test_every_published_generation_is_documented(self):
        on_disk = {d for d in os.listdir(os.path.join(HERE, "generations"))
                   if re.fullmatch(r"[0-9a-f]{56}", d)}
        self.assertEqual(on_disk, set(HISTORICAL), "generations/ and this table disagree")
        with open(os.path.join(HERE, "GENERATIONS.md")) as fh:
            listed = set(re.findall(r"`([0-9a-f]{56})`", fh.read()))
        self.assertEqual(listed, on_disk | {CURRENT_HASH},
                         "GENERATIONS.md does not list exactly the generations this repo ships")


if __name__ == "__main__":
    unittest.main()
