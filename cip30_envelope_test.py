"""verify_cip30_envelope: the one reader of a CIP-30 COSE_Sign1 in this repository.

verify_cip30_proof judges which statement a ceremony demands and hands the envelope the rest; the
MMaaS alert service vendors it to bind a chat to a book (contract C4). Every refusal is a
CoseRejected whose `code` is the contract. The message is for a human and may change.

The proofs here are re-signed by the published fixture key of testdata/cip30-lace-kid-vectors.json
(test only, never funded) through the RFC 8032 test signer, so each refused case carries a genuine
signature and the check it names is the only thing between it and an accept.
"""
import ast
import hashlib
import inspect
import json
import os
import random
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import verify_ceremony as vc  # noqa: E402
from verify_ceremony_test import ed25519_public, ed25519_sign  # noqa: E402

LACE = json.load(open(os.path.join(HERE, "testdata", "cip30-lace-kid-vectors.json")))

C4_CODES = {
    "cbor_malformed", "cbor_noncanonical", "trailing_bytes", "protected_labels", "alg_not_eddsa",
    "address_mismatch", "unprotected_not_hashed_false", "payload_mismatch", "cose_key_shape",
    "small_order_key", "script_payment_credential", "reward_address", "key_hash_mismatch",
    "bad_signature",
}
HASHED_FALSE = b"\xa1\x66hashed\xf4"
KEY_PREFIX = b"\xa4\x01\x01\x03\x27\x20\x06\x21\x58\x20"
IDENTITY = bytes([1]) + bytes(31)


def bstr(raw):
    return vc._cbor_head(2, len(raw)) + raw


def cose_sign1(protected, payload_item, signature_item, unprotected=HASHED_FALSE):
    return b"\x84" + bstr(protected) + unprotected + payload_item + signature_item


def sig_structure(protected, payload):
    return b"\x84" + vc._cbor_head(3, 10) + b"Signature1" + bstr(protected) + b"\x40" + bstr(payload)


class Fixture:
    """The lace-kid fixture client: its key, its payout address and the statement it signed."""

    seed = hashlib.sha256(LACE["provenance"]["fixtureClientKey"]["paymentSeed"].encode()).digest()
    other_seed = hashlib.sha256(LACE["provenance"]["fixtureClientKey"]["stakeSeed"].encode()).digest()
    lucid = LACE["probe"]["lucid-shape"]["proof"]
    lace = LACE["probe"]["lace-shape"]["proof"]
    payload = LACE["probe"]["payload"].encode()
    payout = LACE["ceremony"]["params"]["client_payout_address"]
    address = vc.bech32_decode(payout)[1]
    vkey = bytes.fromhex(lace["coseKey"])[-32:]
    # The same payment key under another stake key: only the bytes tell it from `address`.
    restaked = address[:29] + hashlib.sha256(b"another stake key").digest()[:28]

    @staticmethod
    def protected(address, kid=False):
        if kid:
            return b"\xa3\x01\x27\x04" + bstr(address) + b"\x67address" + bstr(address)
        return b"\xa2\x01\x27\x67address" + bstr(address)

    @classmethod
    def signed(cls, protected=None, payload=None, unprotected=HASHED_FALSE, seed=None, cose_key=None):
        """(cose_sign1_hex, cose_key_hex): `payload` under `protected`, signed by `seed`."""
        protected = cls.protected(cls.address) if protected is None else protected
        payload = cls.payload if payload is None else payload
        seed = cls.seed if seed is None else seed
        signature = ed25519_sign(seed, sig_structure(protected, payload))
        if cose_key is None:
            cose_key = KEY_PREFIX + ed25519_public(seed)
        return cose_sign1(protected, bstr(payload), bstr(signature), unprotected).hex(), cose_key.hex()


def envelope(cose_sign1_hex, cose_key_hex, payload=None, address=None):
    return vc.verify_cip30_envelope(cose_sign1_hex, cose_key_hex,
                                    Fixture.payload if payload is None else payload,
                                    Fixture.address if address is None else address)


class TheContract(unittest.TestCase):
    def test_the_signature_is_c4(self):
        params = list(inspect.signature(vc.verify_cip30_envelope).parameters.values())
        self.assertEqual([p.name for p in params[:4]],
                         ["cose_sign1_hex", "cose_key_hex", "expected_payload", "expected_address"])
        for p in params[:4]:
            self.assertEqual(p.kind, p.POSITIONAL_OR_KEYWORD)
            self.assertIs(p.default, p.empty)
        # Anything past the four is keyword-only with a default, so every C4 call stays a valid one.
        for p in params[4:]:
            self.assertEqual(p.kind, p.KEYWORD_ONLY, p.name)
            self.assertIsNot(p.default, p.empty, p.name)

    def test_a_refusal_is_a_ceremony_error_carrying_its_code(self):
        self.assertTrue(issubclass(vc.CoseRejected, vc.CeremonyError))
        refusal = vc.CoseRejected("bad_signature", "words")
        self.assertEqual(refusal.code, "bad_signature")
        self.assertEqual(str(refusal), "words")

    def test_a_genuine_lucid_proof_returns_its_32_byte_vkey(self):
        self.assertEqual(envelope(Fixture.lucid["coseSign1"], Fixture.lucid["coseKey"]), Fixture.vkey)

    def test_a_genuine_lace_proof_returns_the_same_vkey(self):
        self.assertEqual(envelope(Fixture.lace["coseSign1"], Fixture.lace["coseKey"]), Fixture.vkey)

    def test_the_test_signer_reproduces_the_wallet_signature(self):
        """Positive control for every re-signed case below."""
        protected = vc._cose_protected_bytes(bytes.fromhex(Fixture.lucid["coseSign1"]))[0]
        self.assertEqual(Fixture.signed(protected)[0], Fixture.lucid["coseSign1"])
        self.assertEqual(ed25519_public(Fixture.seed), Fixture.vkey)


class EveryCode(unittest.TestCase):
    """One case per C4 code, each refused for that reason and no earlier one."""

    def rejects(self, code, *args, **kw):
        with self.assertRaises(vc.CoseRejected) as caught:
            envelope(*args, **kw)
        self.assertEqual(caught.exception.code, code, str(caught.exception))
        return str(caught.exception)

    def test_cbor_malformed(self):
        genuine = Fixture.lucid["coseSign1"]
        self.rejects("cbor_malformed", "not hex", Fixture.lucid["coseKey"])
        self.rejects("cbor_malformed", None, Fixture.lucid["coseKey"])
        self.rejects("cbor_malformed", genuine[:-20], Fixture.lucid["coseKey"])
        protected = Fixture.protected(Fixture.address)
        three = b"\x83" + bstr(protected) + HASHED_FALSE + bstr(Fixture.payload)
        self.rejects("cbor_malformed", three.hex(), Fixture.lucid["coseKey"])
        text_payload = vc._cbor_head(3, len(Fixture.payload)) + Fixture.payload
        self.rejects("cbor_malformed", cose_sign1(protected, text_payload, bstr(bytes(64))).hex(),
                     Fixture.lucid["coseKey"])
        not_a_map = cose_sign1(b"\x80", bstr(Fixture.payload), bstr(bytes(64)))
        self.rejects("cbor_malformed", not_a_map.hex(), Fixture.lucid["coseKey"])

    def test_cbor_noncanonical(self):
        raw = bytes.fromhex(Fixture.lucid["coseSign1"])
        wide = raw.replace(b"\x58\x40", b"\x59\x00\x40", 1)
        self.rejects("cbor_noncanonical", wide.hex(), Fixture.lucid["coseKey"])
        self.rejects("cbor_noncanonical", (b"\x9f" + raw[1:] + b"\xff").hex(), Fixture.lucid["coseKey"])

    def test_trailing_bytes(self):
        self.rejects("trailing_bytes", Fixture.lucid["coseSign1"] + "00", Fixture.lucid["coseKey"])
        inside = Fixture.protected(Fixture.address) + b"\x00"
        self.rejects("trailing_bytes", *Fixture.signed(inside))

    def test_protected_labels(self):
        address = bstr(Fixture.address)
        extra = b"\xa3\x01\x27\x05" + address + b"\x67address" + address
        self.rejects("protected_labels", *Fixture.signed(extra))
        integer_kid = b"\xa3\x01\x27\x04\x01\x67address" + address
        self.rejects("protected_labels", *Fixture.signed(integer_kid))
        other_kid = b"\xa3\x01\x27\x04" + bstr(Fixture.restaked) + b"\x67address" + address
        self.rejects("protected_labels", *Fixture.signed(other_kid))
        text_address = b"\xa2\x01\x27\x67address" + vc._cbor_head(3, 4) + b"addr"
        self.rejects("protected_labels", *Fixture.signed(text_address))

    def test_alg_not_eddsa(self):
        es256 = b"\xa2\x01\x26\x67address" + bstr(Fixture.address)
        self.rejects("alg_not_eddsa", *Fixture.signed(es256))
        self.rejects("alg_not_eddsa", *Fixture.signed(b"\xa1\x67address" + bstr(Fixture.address)))

    def test_address_mismatch(self):
        """The same payment key under another stake key: the key hash matches at bytes 1 to 28, so
        only the whole-address comparison refuses it."""
        message = self.rejects("address_mismatch", Fixture.lucid["coseSign1"], Fixture.lucid["coseKey"],
                               address=Fixture.restaked)
        self.assertRegex(message, "different address")

    def test_unprotected_not_hashed_false(self):
        hashed = bytes.fromhex(Fixture.lucid["coseSign1"]).replace(HASHED_FALSE, b"\xa1\x66hashed\xf5", 1)
        self.rejects("unprotected_not_hashed_false", hashed.hex(), Fixture.lucid["coseKey"])
        padded = bytes.fromhex(Fixture.lucid["coseSign1"]).replace(
            HASHED_FALSE, b"\xa2\x66hashed\xf4\x18\x64\x00", 1)
        self.rejects("unprotected_not_hashed_false", padded.hex(), Fixture.lucid["coseKey"])
        as_array = bytes.fromhex(Fixture.lucid["coseSign1"]).replace(HASHED_FALSE, b"\x80", 1)
        self.rejects("unprotected_not_hashed_false", as_array.hex(), Fixture.lucid["coseKey"])

    def test_payload_mismatch(self):
        other = Fixture.payload[:-2] + b"0\n"
        self.rejects("payload_mismatch", Fixture.lucid["coseSign1"], Fixture.lucid["coseKey"], payload=other)
        detached = cose_sign1(Fixture.protected(Fixture.address), b"\xf6", bstr(bytes(64)))
        self.rejects("payload_mismatch", detached.hex(), Fixture.lucid["coseKey"])

    def test_cose_key_shape(self):
        self.rejects("cose_key_shape", Fixture.lucid["coseSign1"], Fixture.lace["coseKey"])
        self.rejects("cose_key_shape", Fixture.lace["coseSign1"], Fixture.lucid["coseKey"])
        xpub = b"\xa4\x01\x01\x03\x27\x20\x06\x21" + bstr(Fixture.vkey + bytes(32))
        self.assertRegex(self.rejects("cose_key_shape", Fixture.lucid["coseSign1"], xpub.hex()), "EXTENDED")
        doubled = b"\xa5" + KEY_PREFIX[1:] + Fixture.vkey + b"\x21" + bstr(bytes(32))
        self.rejects("cose_key_shape", Fixture.lucid["coseSign1"], doubled.hex())
        not_okp = b"\xa4\x01\x02\x03\x27\x20\x06\x21" + bstr(Fixture.vkey)
        self.rejects("cose_key_shape", Fixture.lucid["coseSign1"], not_okp.hex())

    def small_order_case(self, key):
        """A proof naming a key with no private half, over an address built from that key, so
        the small-order check is the one that decides. The signature is the fixed forgery a
        cofactorless reader accepts for the identity: R the identity, s = 0."""
        address = vc.bech32_decode(vc.bech32_encode("addr", bytes([0x61]) + bytes.fromhex(vc.vkh(key))))[1]
        protected = Fixture.protected(address)
        raw = cose_sign1(protected, bstr(Fixture.payload), bstr(IDENTITY + bytes(32)))
        return raw.hex(), (KEY_PREFIX + key).hex(), Fixture.payload, address

    def test_small_order_key(self):
        for key in (IDENTITY, bytes(32), vc._ED_P.to_bytes(32, "little")):
            with self.subTest(key.hex()):
                message = self.rejects("small_order_key", *self.small_order_case(key))
                self.assertIn("in the proof", message)

    def test_script_payment_credential(self):
        """The script hash is the fixture key's own hash, so the key-hash check would pass."""
        script = bytes([0x71]) + bytes.fromhex(vc.vkh(Fixture.vkey))
        message = self.rejects("script_payment_credential", *Fixture.signed(Fixture.protected(script)),
                               address=script)
        self.assertRegex(message, "not to a verification key")

    def test_reward_address(self):
        """A stake-key address over the fixture key's own hash: CIP-8 lets a wallet sign for it
        with its stake key, which spends nothing."""
        reward = bytes([0xE1]) + bytes.fromhex(vc.vkh(Fixture.vkey))
        self.rejects("reward_address", *Fixture.signed(Fixture.protected(reward)), address=reward)

    def test_key_hash_mismatch(self):
        """Another key signs under the fixture address: every byte around it is genuine."""
        message = self.rejects("key_hash_mismatch", *Fixture.signed(
            seed=Fixture.other_seed, cose_key=KEY_PREFIX + ed25519_public(Fixture.other_seed)))
        self.assertRegex(message, "different one")

    def test_bad_signature(self):
        raw = bytearray(bytes.fromhex(Fixture.lucid["coseSign1"]))
        raw[-1] ^= 0x01
        message = self.rejects("bad_signature", raw.hex(), Fixture.lucid["coseKey"])
        self.assertIn("the signature in the proof does not verify", message)
        short = cose_sign1(Fixture.protected(Fixture.address), bstr(Fixture.payload), bstr(bytes(63)))
        self.rejects("bad_signature", short.hex(), Fixture.lucid["coseKey"])

    def test_every_c4_code_has_a_case_here(self):
        named = {name[len("test_"):] for name in dir(self) if name.startswith("test_")}
        self.assertEqual(C4_CODES - named, set())


class CallerMistakes(unittest.TestCase):
    """An expected value of the wrong type or shape is the caller's bug, never a proof's fault, so
    it is not a CoseRejected a service could report to a client."""

    def test_an_expected_address_that_is_not_bytes(self):
        with self.assertRaises(TypeError):
            envelope(Fixture.lucid["coseSign1"], Fixture.lucid["coseKey"], address=Fixture.payout)

    def test_an_expected_address_that_is_no_shelley_address(self):
        for raw in (b"", Fixture.address[:40], b"\x82" + Fixture.address[1:], Fixture.address + b"\x00"):
            with self.subTest(raw.hex()), self.assertRaises(ValueError) as caught:
                envelope(Fixture.lucid["coseSign1"], Fixture.lucid["coseKey"], address=raw)
            self.assertNotIsInstance(caught.exception, vc.CeremonyError)

    def test_an_expected_payload_that_is_not_bytes(self):
        with self.assertRaises(TypeError):
            envelope(Fixture.lucid["coseSign1"], Fixture.lucid["coseKey"], payload=Fixture.payload.decode())


class NothingButACodedRefusal(unittest.TestCase):
    """C4 promises a vkey or a CoseRejected. A RecursionError or UnicodeDecodeError on hostile
    bytes would reach a service as a 500 instead of a refusal it can name."""

    def assert_coded(self, cose_sign1_hex, cose_key_hex):
        try:
            return envelope(cose_sign1_hex, cose_key_hex)
        except vc.CoseRejected as refusal:
            self.assertIn(refusal.code, C4_CODES)
            return None

    def test_deep_nesting_is_refused_not_a_recursion_error(self):
        deep = b"\x81" * 5000 + b"\x00"
        raw = cose_sign1(Fixture.protected(Fixture.address), bstr(Fixture.payload), bstr(bytes(64)), deep)
        with self.assertRaises(vc.CoseRejected) as caught:
            envelope(raw.hex(), Fixture.lucid["coseKey"])
        self.assertEqual(caught.exception.code, "cbor_malformed")

    def test_invalid_utf8_text_is_refused_not_a_decode_error(self):
        protected = b"\xa3\x01\x27\x67address" + bstr(Fixture.address) + b"\x62\xff\xfe\x00"
        with self.assertRaises(vc.CoseRejected) as caught:
            envelope(*Fixture.signed(protected))
        self.assertEqual(caught.exception.code, "cbor_malformed")

    def test_any_mutation_of_a_genuine_proof_is_the_fixture_key_or_a_coded_refusal(self):
        rng = random.Random(0xC4)
        for proof in (Fixture.lucid, Fixture.lace):
            for which in ("coseSign1", "coseKey"):
                original = bytearray(bytes.fromhex(proof[which]))
                for _ in range(600):
                    raw = bytearray(original)
                    at = rng.randrange(len(raw))
                    op = rng.randrange(4)
                    if op == 0:
                        raw[at] ^= 1 << rng.randrange(8)
                    elif op == 1:
                        del raw[at]
                    elif op == 2:
                        raw.insert(at, rng.randrange(256))
                    else:
                        del raw[at:]
                    doc = dict(proof, **{which: raw.hex()})
                    vkey = self.assert_coded(doc["coseSign1"], doc["coseKey"])
                    if vkey is not None:
                        self.assertEqual(vkey, Fixture.vkey)


class OneBody(unittest.TestCase):
    """verify_cip30_proof is a caller of the envelope: one reader of the COSE, not two."""

    def verify_lace(self, doc):
        c = LACE["ceremony"]
        encoded, payout_info = vc.encode_params(c["params"], c["network"])
        challenge = vc.possession_challenge(c["network"], c["unappliedScriptHash"], encoded)
        band = vc.check_ceremony_coherence(c["params"], payout_info, LACE["consentTerms"]["decimals"], None, HERE)
        return vc.verify_cip30_proof(doc, "proof.json", c["params"]["client_owner_vkh"], Fixture.payout,
                                     c["network"], challenge, c["params"], band, Fixture.payout)

    def test_verify_cip30_proof_hands_the_envelope_the_statement_and_the_address(self):
        with mock.patch.object(vc, "verify_cip30_envelope", wraps=vc.verify_cip30_envelope) as spy:
            self.verify_lace(Fixture.lace)
        spy.assert_called_once()
        args, kwargs = spy.call_args
        self.assertEqual(args, (Fixture.lace["coseSign1"], Fixture.lace["coseKey"], Fixture.payload,
                                Fixture.address))
        self.assertEqual(kwargs, {"source": "proof.json"})

    def test_an_envelope_refusal_is_the_proofs_refusal(self):
        refusal = vc.CoseRejected("bad_signature", "sentinel")
        with mock.patch.object(vc, "verify_cip30_envelope", side_effect=refusal):
            with self.assertRaises(vc.CoseRejected) as caught:
                self.verify_lace(Fixture.lace)
        self.assertIs(caught.exception, refusal)

    def test_the_signature_is_verified_once(self):
        with mock.patch.object(vc, "ed25519_verify", wraps=vc.ed25519_verify) as spy:
            self.verify_lace(Fixture.lucid)
        self.assertEqual(spy.call_count, 1)

    def test_the_proof_reader_names_no_cose_primitive_itself(self):
        tree = ast.parse(inspect.getsource(vc.verify_cip30_proof))
        names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
        self.assertIn("verify_cip30_envelope", names)
        for primitive in ("ed25519_verify", "_ed_decompress", "_ed_is_small_order", "_COSE_KEY_PREFIX",
                          "_COSE_ALG_EDDSA", "_cose_protected_bytes"):
            self.assertNotIn(primitive, names)

    def test_the_proofs_own_refusals_still_name_its_file(self):
        """The parity fixture pins these two refusals with the file name in them."""
        raw = bytearray(bytes.fromhex(Fixture.lucid["coseSign1"]))
        raw[-1] ^= 0x01
        with self.assertRaises(vc.CeremonyError) as caught:
            self.verify_lace(dict(Fixture.lucid, coseSign1=raw.hex()))
        self.assertEqual(str(caught.exception),
                         "the signature in proof.json does not verify against the message it carries")


if __name__ == "__main__":
    unittest.main()
