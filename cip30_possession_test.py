"""CIP-30 possession proofs — the form a browser wallet can actually produce.

The happy-path vectors in testdata/cip30-consent-v2-vectors.json (the v2 consent
statement) and testdata/cip30-possession-vectors.json (v1, frozen for audit) were minted
by @emurgo/cardano-message-signing (through lucid's signData), the library wallets
sign with. The red cases are built HERE, by hand, so the encoder that makes a bad
proof is never the decoder that judges it.

Every refusal gets a case that fails for THAT reason. A suite that only replays
one captured vector proves the decoder parses Eternl, not that any check fires.
"""
import copy
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import verify_ceremony as vc  # noqa: E402

VECTORS = json.load(open(os.path.join(HERE, "testdata", "cip30-possession-vectors.json")))
# The v1 vectors sign an arbitrary challenge over a band at 0 decimals, so the ceremony they
# answer is only this much: the challenge, the two lines a v1 statement names, and the band.
V1_BAND = {"decimals": 0, "bid_ceiling_ada_per_display_unit": "2.6",
           "ask_floor_ada_per_display_unit": "2.7"}


def envelope(vector):
    return {
        "type": vc.CIP30_PROOF_TYPE,
        "address": vector["address"],
        "coseSign1": vector["cose_sign1_hex"],
        "coseKey": vector["cose_key_hex"],
    }


def v1_params(vector):
    return {"client_payout_address": vector["address"], "fee_bps": VECTORS["fee_bps"]}


def accept(vector, doc=None, band=V1_BAND, owner=None, address=None, payout="same",
           challenge=bytes.fromhex(VECTORS["challenge_hex"])):
    """Run the verifier the way the tool will, with this v1 vector's own facts."""
    return vc.verify_cip30_proof(
        doc if doc is not None else envelope(vector),
        "proof.json",
        owner if owner is not None else vector["client_owner_vkh"],
        address if address is not None else vector["address"],
        vector["network"],
        challenge,
        v1_params(vector),
        band,
        vector["address"] if payout == "same" else payout,
    )


def cbor_bstr(b):
    return vc._cbor_head(2, len(b)) + b


class CanonicalPayload(unittest.TestCase):
    """The payload is the whole security surface: it is the only thing the client
    reads in the wallet popup, and the only thing binding a signature to a ceremony.
    The generator renders it in JavaScript and this asserts python renders the same
    bytes — the same two-implementation split the browser will depend on."""

    def test_python_renders_byte_for_byte_what_the_wallet_signed(self):
        for v in VECTORS["vectors"]:
            with self.subTest(v["name"]):
                rendered = vc.canonical_possession_payload(
                    bytes.fromhex(VECTORS["challenge_hex"]),
                    v["network"],
                    {"client_payout_address": v["address"], "fee_bps": VECTORS["fee_bps"]},
                    VECTORS["band"],
                )
                self.assertEqual(rendered, v["payload_text"])

    def test_it_names_facts_a_human_can_refuse_in_a_wallet_popup(self):
        text = VECTORS["vectors"][0]["payload_text"]
        for fact in ("SaturnSwap", "your wallet:", "our fee:", "your band:"):
            self.assertIn(fact, text)


class AuthenticProofs(unittest.TestCase):
    def test_a_real_wallet_signature_verifies(self):
        for v in VECTORS["vectors"]:
            with self.subTest(v["name"]):
                vkey, address, payload, consent = accept(v)
                self.assertEqual(vkey.hex(), v["public_key_hex"])
                self.assertEqual(address, v["address"])
                self.assertEqual(payload, v["payload_text"].encode())
                self.assertIsNone(consent)

    def test_enterprise_and_base_addresses_both_work(self):
        names = {v["name"] for v in VECTORS["vectors"]}
        self.assertIn("mainnet-enterprise", names)
        self.assertIn("mainnet-base", names)


class Refusals(unittest.TestCase):
    def setUp(self):
        self.v = VECTORS["vectors"][0]

    def refuses(self, matching, **kw):
        with self.assertRaises(vc.CeremonyError) as caught:
            accept(self.v, **kw)
        self.assertRegex(str(caught.exception), matching)

    def test_a_proof_for_another_ceremony_is_refused(self):
        """The one that matters most: a genuine signature, by the right key, over a
        DIFFERENT ceremony's payload. Nothing about the message may come from the file."""
        self.refuses("different message|another ceremony",
                     band=dict(V1_BAND, ask_floor_ada_per_display_unit="2.8"))

    def test_a_proof_by_an_address_the_client_did_not_name_is_refused(self):
        """Without --my-address the tool proves only that SOMEBODY holding
        client_owner_vkh signed — which an operator who chose that parameter arranges
        with their own browser wallet."""
        other = VECTORS["vectors"][1]["address"]
        self.refuses("did not name|different address", address=other)

    def test_a_key_that_is_not_the_ceremony_key_is_refused(self):
        self.refuses("must be\n?\\s*the same key|different one", owner="ab" * 28)

    def test_trailing_bytes_after_the_cose_sign1_are_refused(self):
        doc = envelope(self.v)
        doc["coseSign1"] = doc["coseSign1"] + "00"
        self.refuses("trailing byte", doc=doc)

    def test_a_truncated_cose_sign1_is_a_refusal_not_a_crash(self):
        doc = envelope(self.v)
        doc["coseSign1"] = doc["coseSign1"][:-20]
        self.refuses("ends mid-item|trailing byte|4-element", doc=doc)

    def test_an_envelope_carrying_two_forms_at_once_is_refused(self):
        doc = envelope(self.v)
        doc["cborHex"] = "82" + "00" * 50
        self.refuses("both a CIP-30 proof and", doc=doc)

    def test_a_flipped_signature_bit_is_refused(self):
        doc = envelope(self.v)
        raw = bytearray(bytes.fromhex(doc["coseSign1"]))
        raw[-1] ^= 0x01
        doc["coseSign1"] = raw.hex()
        self.refuses("does not verify", doc=doc)

    def test_a_substituted_public_key_is_refused(self):
        """The COSE_Key comes from the same untrusted party as the signature, so a
        fresh keypair signing the right payload must fail on the vkh binding."""
        doc = envelope(self.v)
        other = VECTORS["vectors"][1]
        doc["coseKey"] = other["cose_key_hex"]
        self.refuses("the same key|different one", doc=doc)

    def test_a_hashed_payload_is_refused_with_the_wallet_named(self):
        doc = envelope(self.v)
        raw = bytes.fromhex(doc["coseSign1"])
        doc["coseSign1"] = raw.replace(b"\xa1\x66hashed\xf4", b"\xa1\x66hashed\xf5").hex()
        self.refuses("hashed", doc=doc)

    def test_a_non_hex_proof_is_refused(self):
        doc = envelope(self.v)
        doc["coseSign1"] = "not-hex"
        self.refuses("not hex", doc=doc)

    def test_a_missing_field_is_refused(self):
        doc = envelope(self.v)
        del doc["coseKey"]
        self.refuses("no string 'coseKey'", doc=doc)


def cose_sign1(protected, payload, signature, unprotected=b"\xa1\x66hashed\xf4"):
    """Assembled by hand, not by a CBOR library, so the encoder that produces a bad
    proof is never the decoder that judges it."""
    return b"\x84" + cbor_bstr(protected) + unprotected + payload + signature


class MalformedCose(unittest.TestCase):
    """Each case reaches ONE check. Anything refused earlier would leave the check it
    names free to be deleted."""

    def setUp(self):
        self.v = VECTORS["vectors"][0]
        self.addr_bytes = vc.bech32_decode(self.v["address"])[1]
        self.payload = self.v["payload_text"].encode()

    def run_with(self, raw, cose_key=None):
        doc = envelope(self.v)
        doc["coseSign1"] = raw.hex()
        if cose_key is not None:
            doc["coseKey"] = cose_key.hex()
        with self.assertRaises(vc.CeremonyError) as caught:
            accept(self.v, doc=doc)
        return str(caught.exception)

    def test_a_non_eddsa_algorithm_is_refused(self):
        es256 = b"\xa2\x01\x26\x67address" + cbor_bstr(self.addr_bytes)
        self.assertRegex(
            self.run_with(cose_sign1(es256, cbor_bstr(self.payload), cbor_bstr(bytes(64)))),
            "algorithm|EdDSA")

    def test_a_text_string_payload_is_refused_as_not_bytes(self):
        protected = b"\xa2\x01\x27\x67address" + cbor_bstr(self.addr_bytes)
        text_payload = vc._cbor_head(3, len(self.payload)) + self.payload
        self.assertRegex(
            self.run_with(cose_sign1(protected, text_payload, cbor_bstr(bytes(64)))),
            "not a byte string|byte string")

    def test_a_signature_that_is_not_64_bytes_is_refused(self):
        protected = b"\xa2\x01\x27\x67address" + cbor_bstr(self.addr_bytes)
        self.assertRegex(
            self.run_with(cose_sign1(protected, cbor_bstr(self.payload), cbor_bstr(bytes(63)))),
            "64")

    def test_an_extended_public_key_is_refused_and_named(self):
        protected = b"\xa2\x01\x27\x67address" + cbor_bstr(self.addr_bytes)
        raw = cose_sign1(protected, cbor_bstr(self.payload), cbor_bstr(bytes(64)))
        xpub = b"\xa4\x01\x01\x03\x27\x20\x06\x21" + cbor_bstr(bytes(64))
        self.assertRegex(self.run_with(raw, cose_key=xpub), "EXTENDED|32")

    def test_a_detached_null_payload_is_refused_rather_than_filled_in(self):
        protected = b"\xa2\x01\x27\x67address" + cbor_bstr(self.addr_bytes)
        self.assertRegex(
            self.run_with(cose_sign1(protected, b"\xf6", cbor_bstr(bytes(64)))),
            "detached|no payload")

    def test_an_array_that_is_not_four_elements_is_refused(self):
        protected = b"\xa2\x01\x27\x67address" + cbor_bstr(self.addr_bytes)
        three = b"\x83" + cbor_bstr(protected) + b"\xa0" + cbor_bstr(self.payload)
        self.assertRegex(self.run_with(three), "4-element")

    def test_a_key_that_is_not_an_ed25519_okp_is_refused(self):
        not_okp = b"\xa4\x01\x02\x03\x27\x20\x06\x21" + cbor_bstr(bytes.fromhex(self.v["public_key_hex"]))
        doc = envelope(self.v)
        doc["coseKey"] = not_okp.hex()
        with self.assertRaises(vc.CeremonyError) as caught:
            accept(self.v, doc=doc)
        self.assertRegex(str(caught.exception), "Ed25519 OKP")

    def test_a_script_controlled_wallet_is_refused(self):
        """CIP-8 will happily sign from an address whose payment half is a script; an
        escape hatch that cannot sign is not an escape hatch."""
        script_addr = vc.bech32_encode("addr", bytes([7 << 4 | 1]) + bytes(28))
        protected = b"\xa2\x01\x27\x67address" + cbor_bstr(vc.bech32_decode(script_addr)[1])
        doc = envelope(self.v)
        doc["coseSign1"] = cose_sign1(protected, cbor_bstr(self.payload), cbor_bstr(bytes(64))).hex()
        with self.assertRaises(vc.CeremonyError) as caught:
            accept(self.v, doc=doc, address=script_addr, payout=script_addr)
        self.assertRegex(str(caught.exception), "not to a verification key")


class MalleabilityAndParserAmbiguity(unittest.TestCase):
    """One signature must mean exactly one proof file. Everything here verifies
    cryptographically — the refusals are about the bytes AROUND the signature."""

    def setUp(self):
        self.v = VECTORS["vectors"][0]
        self.raw = bytes.fromhex(self.v["cose_sign1_hex"])

    def refuses(self, raw, matching, cose_key=None):
        doc = envelope(self.v)
        doc["coseSign1"] = raw.hex()
        if cose_key is not None:
            doc["coseKey"] = cose_key.hex()
        with self.assertRaises(vc.CeremonyError) as caught:
            accept(self.v, doc=doc)
        self.assertRegex(str(caught.exception), matching)

    def test_padding_the_unsigned_header_does_not_make_a_second_valid_proof(self):
        """The unprotected bucket is NOT covered by the signature. Left parsed rather
        than pinned, one signature yields unboundedly many byte-distinct files that all
        verify — and anything keyed on a proof's bytes stops meaning anything."""
        padded = self.raw.replace(b"\xa1\x66hashed\xf4",
                                  b"\xa2\x66hashed\xf4\x63kid\x41\x00", 1)
        self.refuses(padded, "unprotected header is not one this tool accepts")

    def test_an_empty_unsigned_header_is_accepted_and_that_residue_is_deliberate(self):
        """a0 is what a wallet emitting no unprotected headers produces, so refusing it
        would lock those wallets out. The bucket is outside the signature, so this DOES
        leave one signature with two valid encodings — bounded at two by the pin, where
        parsing the bucket instead would leave unboundedly many. Anything keyed on a
        proof's bytes must key on the signature, not on the file."""
        doc = envelope(self.v)
        doc["coseSign1"] = self.raw.replace(b"\xa1\x66hashed\xf4", b"\xa0", 1).hex()
        vkey, _, _, _ = accept(self.v, doc=doc)
        self.assertEqual(vkey.hex(), self.v["public_key_hex"])

    def test_a_boolean_map_key_cannot_stand_in_for_the_algorithm_label(self):
        """hash(True) == hash(1) in python, so {true: -8} answers .get(1) — a protected
        header naming NO algorithm would satisfy the algorithm check."""
        protected = b"\xa2\xf5\x27\x67address" + cbor_bstr(vc.bech32_decode(self.v["address"])[1])
        raw = cose_sign1(protected, cbor_bstr(self.v["payload_text"].encode()), cbor_bstr(bytes(64)))
        self.refuses(raw, "map key must be an integer or a text string")

    def test_a_non_shortest_form_head_is_refused(self):
        """A wider head encodes the same value, so it re-frames one signature into
        another byte-distinct proof."""
        wide = self.raw.replace(b"\x58\x40", b"\x59\x00\x40", 1)
        self.refuses(wide, "shortest-form")

    def test_an_unknown_protected_label_is_refused(self):
        addr = cbor_bstr(vc.bech32_decode(self.v["address"])[1])
        protected = b"\xa3\x01\x27\x67address" + addr + b"\x63kid\x41\x00"
        raw = cose_sign1(protected, cbor_bstr(self.v["payload_text"].encode()), cbor_bstr(bytes(64)))
        self.refuses(raw, "protected header carries labels")

    def test_a_duplicated_key_label_cannot_swap_the_public_key(self):
        """A COSE_Key parsed rather than pinned lets a repeated -2 label decide which
        key verifies — and a last-wins parser picks a different one than the signer."""
        real = bytes.fromhex(self.v["cose_key_hex"])
        doubled = b"\xa5" + real[1:] + b"\x21" + cbor_bstr(bytes(32))
        self.refuses(self.raw, "canonical Ed25519 OKP key", cose_key=doubled)

    def test_the_payout_address_must_be_the_one_that_signed(self):
        """check_ceremony_coherence constrains only the PAYMENT credential, so an
        address with a substituted stake part shares most of its bech32 and still
        passes there — while every payout lands where the operator holds delegation."""
        with self.assertRaises(vc.CeremonyError) as caught:
            accept(self.v, payout=VECTORS["vectors"][2]["address"])
        self.assertRegex(str(caught.exception), "pays out to")

    def test_a_proof_over_another_challenge_is_refused(self):
        """The statement is rebuilt inside the verifier from the challenge it is handed, so
        every other line matching cannot carry a signature over a different ceremony."""
        with self.assertRaises(vc.CeremonyError) as caught:
            accept(self.v, challenge=b"\xab" * 32)
        self.assertRegex(str(caught.exception), "different message")


class SmallOrderKeys(unittest.TestCase):
    """A small-order point has no private half, so a 'proof' by one is a published
    forgery: anyone can mint it, for a key nobody holds.

    The ceremony must NAME that key for this to be the deciding check — otherwise the
    vkh binding refuses first and the case passes for a reason that would survive
    deleting the small-order guard entirely."""

    SMALL_ORDER = bytes(32)  # the identity point: order 1

    def _proof_naming_a_small_order_key(self):
        vkey = self.SMALL_ORDER
        owner = vc.vkh(vkey)
        address = vc.bech32_encode("addr", bytes([6 << 4 | 1]) + bytes.fromhex(owner))
        params = {"client_payout_address": address, "fee_bps": 20}
        payload = vc.canonical_possession_payload(
            bytes(32), "mainnet", params, "2.6 - 2.7 ADA per token").encode()
        protected = b"\xa2\x01\x27\x67address" + cbor_bstr(vc.bech32_decode(address)[1])
        cose_sign1 = (b"\x84" + cbor_bstr(protected) + b"\xa1\x66hashed\xf4"
                      + cbor_bstr(payload) + cbor_bstr(bytes(64)))
        doc = {"type": vc.CIP30_PROOF_TYPE, "address": address,
               "coseSign1": cose_sign1.hex(),
               "coseKey": (b"\xa4\x01\x01\x03\x27\x20\x06\x21" + cbor_bstr(vkey)).hex()}
        return doc, owner, address, params

    def test_the_cip30_path_rejects_small_order_points(self):
        doc, owner, address, params = self._proof_naming_a_small_order_key()
        with self.assertRaises(vc.CeremonyError) as caught:
            vc.verify_cip30_proof(doc, "proof.json", owner, address, "mainnet",
                                  bytes(32), params, V1_BAND, address)
        self.assertRegex(str(caught.exception), "small-order")

    def test_the_case_really_does_reach_the_small_order_check(self):
        """If the vkh binding refused first, the case above would pass with the
        small-order guard deleted."""
        doc, owner, address, _ = self._proof_naming_a_small_order_key()
        self.assertEqual(vc.vkh(self.SMALL_ORDER), owner)
        _, mine = vc.address_to_plutus_data(address, "mainnet")
        self.assertEqual(mine["payment_hash"], owner)


class DecoderHardening(unittest.TestCase):
    def test_cbor_load_refuses_trailing_bytes_when_asked(self):
        with self.assertRaises(vc.CeremonyError):
            vc.cbor_load(b"\x01\x02", require_exact=True)
        self.assertEqual(vc.cbor_load(b"\x01\x02"), 1)

    def test_strict_mode_refuses_indefinite_lengths(self):
        indefinite = b"\x5f\x41\x61\xff"
        self.assertEqual(vc.cbor_load(indefinite), b"a")
        with self.assertRaises(vc.CeremonyError):
            vc.cbor_load(indefinite, strict=True)

    def test_a_declared_length_past_the_buffer_is_a_refusal(self):
        with self.assertRaises(vc.CeremonyError):
            vc.cbor_load(b"\x58\x20\x00")

    def test_duplicate_map_keys_are_refused(self):
        with self.assertRaises(vc.CeremonyError):
            vc.cbor_load(b"\xa2\x01\x01\x01\x02")



class MyAddressIsFormScoped(unittest.TestCase):
    """--my-address binds the proof to an address the CLIENT supplies, and only the
    CIP-30 form reads it. Consumed silently by another form it would be a client
    believing a check ran that did not — so a mismatched pairing is refused loudly.

    The underlying weakness is pre-existing: the cardano-cli forms bind only
    vkh(vkey) == client_owner_vkh, and client_owner_vkh is a parameter the OPERATOR
    writes. This does not close that; it stops the flag from implying otherwise."""

    def _tx_witness(self, tmp):
        # [vkey, signature] — the shape cardano-cli conway transaction witness emits.
        raw = b"\x82\x58\x20" + bytes(32) + b"\x58\x40" + bytes(64)
        path = os.path.join(tmp, "witness.json")
        with open(path, "w") as fh:
            json.dump({"type": "TxWitness ConwayEra", "cborHex": raw.hex()}, fh)
        return path

    def test_my_address_with_a_cardano_cli_proof_is_refused_not_ignored(self):
        import tempfile
        tmp = tempfile.mkdtemp(prefix="mmaas-formscope-")
        try:
            with self.assertRaises(vc.CeremonyError) as caught:
                vc.check_possession("ab" * 28, b"\x00" * 32, self._tx_witness(tmp), None, None,
                                    ["cardano-cli"], my_address="addr1vtest")
            self.assertRegex(str(caught.exception), "--my-address")
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    def test_a_cardano_cli_proof_without_my_address_still_works_as_before(self):
        """The pre-existing forms are untouched for clients who never pass the flag."""
        import tempfile
        tmp = tempfile.mkdtemp(prefix="mmaas-formscope-")
        try:
            with self.assertRaises(vc.CeremonyError) as caught:
                vc.check_possession("ab" * 28, b"\x00" * 32, self._tx_witness(tmp), None, None,
                                    ["cardano-cli"])
            # Refused on the KEY, which is the old behaviour — not on the flag.
            self.assertNotRegex(str(caught.exception), "--my-address")
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)


V2 = json.load(open(os.path.join(HERE, "testdata", "cip30-consent-v2-vectors.json")))
ADC2A7F1 = "adc2a7f19bf63b378c06c7d941bba6b7f6312cb8cce5b153f356efe4"
# The bot key D1 moves every ceremony to (spec section 11, decision 4).
D1_BOT_KEY = "1aba8f0a279e88d7aacd20a1f8e6d6ae4293a4f18fcb17cd43f20fd8"


def on_testnet(address):
    _, raw = vc.bech32_decode(address)
    return vc.bech32_encode("addr_test", bytes([raw[0] & 0xF0]) + raw[1:])


def ceremony(vector, network=None, unapplied=None, decimals=6, **changes):
    """(challenge, params, band) for the ceremony `vector` signed, or for that ceremony with
    `changes`, derived the way the tool derives them."""
    network = network or vector["network"]
    params = dict(vector["params"], **changes)
    encoded, payout = vc.encode_params(params, network)
    challenge = vc.possession_challenge(network, unapplied or V2["unapplied_script_hash"], encoded)
    return challenge, params, vc.check_ceremony_coherence(params, payout, decimals, None, HERE)


def verify_v2(vector, network=None, **ceremony_changes):
    challenge, params, band = ceremony(vector, network, **ceremony_changes)
    return vc.verify_cip30_proof(envelope(vector), "proof.json", vector["client_owner_vkh"],
                                 vector["address"], network or vector["network"], challenge,
                                 params, band, vector["address"])


class ConsentV2Proofs(unittest.TestCase):
    """Real wallet signatures over the v2 statement. The generator built the parameter
    encoding, the challenge and the statement in JavaScript, the page's way; every one of
    them is recomputed here in Python and must agree byte for byte."""

    def test_python_computes_the_challenge_the_generator_did(self):
        for v in V2["vectors"]:
            with self.subTest(v["name"]):
                self.assertEqual(ceremony(v)[0].hex(), v["challenge_hex"])

    def test_python_renders_byte_for_byte_what_the_wallet_signed(self):
        for v in V2["vectors"]:
            with self.subTest(v["name"]):
                challenge, params, _ = ceremony(v)
                self.assertEqual(
                    vc.canonical_consent_payload_v2(challenge, v["network"], params,
                                                    v["consent_terms"]),
                    v["payload_text"])

    def test_the_vectors_cover_all_three_token_line_forms_on_both_networks(self):
        lines = [v["payload_text"].split("\n")[7] for v in V2["vectors"]]
        self.assertTrue(any(line.endswith("empty asset name") for line in lines))
        self.assertTrue(any(line.startswith("your token: policy ") and "asset name hex" in line
                            for line in lines))
        self.assertTrue(any(not line.startswith("your token: policy ") for line in lines))
        self.assertEqual({v["network"] for v in V2["vectors"]}, {"mainnet", "testnet"})

    def test_a_real_v2_vector_verifies_and_yields_the_terms_it_signed(self):
        for v in V2["vectors"]:
            with self.subTest(v["name"]):
                vkey, address, payload, consent = verify_v2(v)
                self.assertEqual(vkey.hex(), v["public_key_hex"])
                self.assertEqual(address, v["address"])
                self.assertEqual(payload, v["payload_text"].encode())
                self.assertIn(b"I consent", payload)
                self.assertEqual(consent, v["consent_terms"])

    def refused_by_the_rebuild(self, **ceremony_changes):
        with self.assertRaises(vc.ConsentStatementRefused) as caught:
            verify_v2(V2["vectors"][0], **ceremony_changes)
        self.assertEqual(caught.exception.rule, "3.3.5", str(caught.exception))

    def test_the_same_vector_is_refused_against_the_adc2a7f1_generation(self):
        self.refused_by_the_rebuild(unapplied=ADC2A7F1)

    def test_the_same_vector_is_refused_against_another_band(self):
        self.refused_by_the_rebuild(min_asset2_price={"numerator": 1, "denominator": 8})

    def test_the_same_vector_is_refused_against_another_bot_key(self):
        self.refused_by_the_rebuild(adam_bot_pkh=D1_BOT_KEY)

    def test_the_same_vector_is_refused_on_testnet(self):
        v = V2["vectors"][0]
        self.assertEqual(v["network"], "mainnet")
        self.refused_by_the_rebuild(
            network="testnet",
            client_payout_address=on_testnet(v["params"]["client_payout_address"]),
            fee_address=on_testnet(v["params"]["fee_address"]))

    def test_decimals_7_against_a_statement_signed_at_6_is_refused(self):
        """The statement verifies on its own terms at 6; the refusal is that the client checked
        the band at 7, which is not the band they signed."""
        v = V2["vectors"][0]
        self.assertEqual(v["consent_terms"]["decimals"], 6)
        with self.assertRaises(vc.CeremonyError) as caught:
            verify_v2(v, decimals=7)
        self.assertRegex(str(caught.exception), "token decimals 6.*--decimals 7")


class StatementVersionIsReported(unittest.TestCase):
    """check_possession is what the tool calls, and its record is what --json-out carries."""

    def possession(self, vector, envelope_doc, challenge, params, band):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(envelope_doc, fh)
        try:
            return vc.check_possession(
                vector["client_owner_vkh"], bytes(32), fh.name, None, None, ["cardano-cli"],
                my_address=vector["address"], network=vector["network"], challenge=challenge,
                params=params, band=band, payout_address=vector["address"])
        finally:
            os.unlink(fh.name)

    def test_a_v2_proof_reports_the_terms_it_signed(self):
        v = V2["vectors"][0]
        challenge, params, band = ceremony(v)
        record = self.possession(v, envelope(v), challenge, params, band)
        self.assertTrue(record["proved"])
        self.assertEqual(record["statement"], "v2")
        self.assertEqual(record["consent_terms"], v["consent_terms"])

    def test_a_v1_vector_verifies_as_audit_only(self):
        """It still proves the key; it is not consent, and the keeper refuses it (spec 3.6)."""
        v = VECTORS["vectors"][0]
        record = self.possession(v, envelope(v), bytes.fromhex(VECTORS["challenge_hex"]),
                                 v1_params(v), V1_BAND)
        self.assertTrue(record["proved"])
        self.assertEqual(record["statement"], "v1, audit only, not accepted by the keeper")
        self.assertIsNone(record["consent_terms"])


if __name__ == "__main__":
    unittest.main()
