"""The v2 consent statement: its canonical render, its strict parse, and the golden the keeper
and the page are pinned to.

The golden is emitted by tools/gen_consent_v2_golden.py from this repository's renderer, which
is the reference. Two inputs here do not come from that renderer, and they are what make the
golden worth pinning to: the statement text deci approved (spec 2.2 with the section 11
daily-loss line), written out below by hand, and the live NIGHT ceremony's parameters and
challenges, captured from the mainnet artefact.

The same generator emits consent-v2.edges.golden.json, which pins what that golden leaves open:
signed-at years 0000 to 0100, and token decimals other than 6. Its epoch seconds and price
limits are also written out below by hand.
"""
import importlib.util
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import verify_ceremony as vc  # noqa: E402

GOLDEN_PATH = os.path.join(HERE, "testdata", "consent-v2.golden.json")
GENERATOR_PATH = os.path.join(HERE, "tools", "gen_consent_v2_golden.py")
EDGES_PATH = os.path.join(HERE, "testdata", "consent-v2.edges.golden.json")

# Spec 2.2, approved 2026-09-24 (section 11) with exactly one change: the daily-loss line, in
# basis points of the book's day-open value. 500 is the section 11 default for dailyLossBps.
SPEC_2_2_NIGHT = (
    "SaturnSwap MMaaS consent, version 2\n"
    "I consent to SaturnSwap making a market in my token with its bot key, on the terms below.\n"
    "network: mainnet\n"
    "your wallet: addr1v9vll8849ud8e76zhcv688racky3p50z7gmusrct3gskhzsuk43my\n"
    "our bot key: cea98dfce26e0ffbf5ab892edcb8f8ab8b794d5390f80ec0b9aafed3\n"
    "our fee: at most 20 bps (0.2%) of the ADA we pay out to your wallet, none when we close your order\n"
    "your price limits: your book never buys above 0.097 or sells below 0.1 ADA per token\n"
    "your token: NIGHT (policy 0691b2fecca1ac4f53cb6dfb00b7013e561d1f34403b957cbb5af1fa, asset name hex 4e49474854)\n"
    "token decimals: 6\n"
    "spread: 800 bps (8%) between your book's buying and selling prices\n"
    "book value cap: 120 ADA (your ADA plus your tokens at our price); above it we return the book to your wallet\n"
    "daily loss limit: 500 bps (5%) of your book's value at the start of each UTC day; past it we return the book to your wallet\n"
    "reprice after our price moves: 150 bps (1.5%)\n"
    "signed at: 2026-09-23T18:40:26Z\n"
    "challenge: eafa5a1fb4b9c264634760d568e34eed0b6182c11fe2f070a6e595c1260cee3f\n"
)

# The live NIGHT ceremony's nine parameters as Plutus Data, captured verbatim from the mainnet
# artefact (adam-oc packages/agent-core/src/__tests__/fixtures/mainnetCeremonyPossession.json),
# and the challenge each generation gives them: adc2a7f1 from that artefact, 19cc10ab from spec 2.2.
LIVE_NIGHT_PARAM_CBOR = [
    "581ccea98dfce26e0ffbf5ab892edcb8f8ab8b794d5390f80ec0b9aafed3",
    "581c59ff9cf52f1a7cfb42be19a39c7dc58910d1e2f237c80f0b8a216b8a",
    "d8799fd8799f581c59ff9cf52f1a7cfb42be19a39c7dc58910d1e2f237c80f0b8a216b8affd87a80ff",
    "581c11928a3ac3b65edbf103ea6bb3362e39b879a36f02897df31c40917b",
    "581c8a199a17ef4517215945aaf3c8c5204c60fd94d34c46d341e99c8fcf",
    "d8799f1903e81861ff",
    "d8799f010aff",
    "d8799fd8799f581c5c3d142a598ed32bfd59c6214fb735ea6ba7eff5082d9f86daef55b3ffd87a80ff",
    "14",
]
LIVE_NIGHT_CHALLENGES = {
    "adc2a7f19bf63b378c06c7d941bba6b7f6312cb8cce5b153f356efe4":
        "0a516a82baa54eea7f4da8ec33eb05d5e2abeda3320859138dcf21307b9a72a9",
    "19cc10abe5dfedee65c53d82548a1e6e2997f52c52a70af4170321fe":
        "eafa5a1fb4b9c264634760d568e34eed0b6182c11fe2f070a6e595c1260cee3f",
}

# Every non-canonical variant spec 6.1 and 6.2 name, plus one per rule they leave uncovered.
REQUIRED_VARIANTS = {
    "CR", "trailing space", "leading zero", "8.0%", "upper-case hex", "em dash",
    "non-breaking space", "14 lines", "16 lines", "decimals 19", "2026-02-30T00:00:00Z",
    "spoofed readable name", "2,049 bytes", "readable name the bytes do not produce",
    "name with a space shown as readable", "name with a parenthesis shown as readable",
    "altered consent sentence",
}

# Proleptic-Gregorian epoch seconds, as GNU date and JavaScript's Date.parse give them.
# Date.UTC reads years 0 to 99 as 1900 to 1999, so it is wrong for the first three.
EARLY_SIGNED_AT_UNIX = {
    "0001-01-01T00:00:00Z": -62135596800,
    "0050-06-15T00:00:00Z": -60575040000,
    "0099-12-31T23:59:59Z": -59011459201,
    "0100-01-01T00:00:00Z": -59011459200,
}

# Worked by hand from each band: lovelace per base unit times 10^decimals / 10^6 ADA per token.
PRICE_LIMITS_AT_DECIMALS = {
    0: "your price limits: your book never buys above 0.00000025 or sells below 0.0000003 ADA per token",
    2: "your price limits: your book never buys above 12.5 or sells below 13.0625 ADA per token",
    18: "your price limits: your book never buys above 0.35 or sells below 0.3625 ADA per token",
}


def load_golden():
    with open(GOLDEN_PATH) as fh:
        return json.load(fh)


def load_edges():
    with open(EDGES_PATH) as fh:
        return json.load(fh)


def load_generator():
    spec = importlib.util.spec_from_file_location("gen_consent_v2_golden", GENERATOR_PATH)
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    return generator


def ceremony_of(golden):
    c = golden["ceremony"]
    return bytes.fromhex(c["challengeHex"]), c["network"], c["params"]


def render(golden, consent):
    return vc.canonical_consent_payload_v2(*ceremony_of(golden), consent)


def parse(golden, payload):
    return vc.parse_consent_payload_v2(payload, *ceremony_of(golden))


def token_line_of(payload_text):
    return payload_text.split("\n")[7]


class GoldenIsTheVerifierOutput(unittest.TestCase):
    def test_the_generator_reproduces_the_committed_golden_byte_for_byte(self):
        """A golden someone edited by hand pins the other repos to text this renderer does not
        produce, and every client signing through the page would then be refused here."""
        with open(GOLDEN_PATH) as fh:
            self.assertEqual(load_generator().emit(), fh.read())

    def test_the_generator_reproduces_the_committed_edges_byte_for_byte(self):
        with open(EDGES_PATH) as fh:
            self.assertEqual(load_generator().emit_edges(), fh.read())


class TheGoldenCeremonyIsTheLiveNightBook(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.golden = load_golden()

    def test_its_params_encode_to_the_live_mainnet_artefact(self):
        c = self.golden["ceremony"]
        encoded, _ = vc.encode_params(c["params"], c["network"])
        self.assertEqual([p["plutus_data_cbor_hex"] for p in encoded], LIVE_NIGHT_PARAM_CBOR)
        self.assertEqual(c["paramCborHex"], LIVE_NIGHT_PARAM_CBOR)

    def test_its_challenge_is_the_live_one_on_both_generations(self):
        c = self.golden["ceremony"]
        encoded, _ = vc.encode_params(c["params"], c["network"])
        for unapplied, challenge in LIVE_NIGHT_CHALLENGES.items():
            with self.subTest(unapplied[:8]):
                self.assertEqual(
                    vc.possession_challenge(c["network"], unapplied, encoded).hex(), challenge)
        self.assertEqual(c["unappliedScriptHash"], "19cc10abe5dfedee65c53d82548a1e6e2997f52c52a70af4170321fe")
        self.assertEqual(c["challengeHex"], LIVE_NIGHT_CHALLENGES[c["unappliedScriptHash"]])


class Render(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.golden = load_golden()
        cls.cases = {case["tokenLineForm"]: case for case in cls.golden["cases"]}

    def test_the_night_example_is_spec_2_2_with_only_the_section_11_daily_loss_line(self):
        case = self.cases["readable"]
        self.assertEqual(case["consent"]["terms"]["dailyLossBps"], 500)
        self.assertEqual(case["payload"], SPEC_2_2_NIGHT)
        self.assertEqual(render(self.golden, case["consent"]), SPEC_2_2_NIGHT)

    def test_render_equals_the_golden_in_all_three_token_forms(self):
        self.assertEqual(set(self.cases), {"readable", "hex", "empty"})
        for form, case in self.cases.items():
            with self.subTest(form):
                rendered = render(self.golden, case["consent"])
                self.assertEqual(rendered, case["payload"])
                self.assertEqual(rendered.encode(), bytes.fromhex(case["payloadHex"]))
                self.assertEqual(token_line_of(rendered), case["tokenLine"])

    def test_the_three_token_line_forms_are_chosen_from_the_name_bytes(self):
        policy = "0691b2fecca1ac4f53cb6dfb00b7013e561d1f34403b957cbb5af1fa"
        self.assertEqual(self.cases["readable"]["tokenLine"],
                         f"your token: NIGHT (policy {policy}, asset name hex 4e49474854)")
        self.assertEqual(self.cases["hex"]["tokenLine"],
                         f"your token: policy {policy}, asset name hex 0014df104e49474854")
        self.assertEqual(self.cases["empty"]["tokenLine"],
                         f"your token: policy {policy}, empty asset name")

    def test_a_readable_name_is_1_to_32_bytes_drawn_from_the_safe_set(self):
        """A name that could imitate the line's own syntax (spaces, parentheses, commas) is
        never shown, so a token line always says exactly one policy and one name."""
        base = self.cases["readable"]["consent"]
        for name, readable in ((b"A" * 32, True), (b"a.b_c-D9", True), (b"A" * 33, False),
                               (b"MY TOKEN", False), (b"NIGHT)", False), (b"NIGHT,", False),
                               (b"caf\xc3\xa9", False)):
            with self.subTest(name):
                consent = dict(base, token=dict(base["token"], assetNameHex=name.hex()))
                line = token_line_of(render(self.golden, consent))
                shown = f"your token: {name.decode('ascii')} (policy " if readable else "your token: policy "
                self.assertTrue(line.startswith(shown), line)

    def test_the_rebuild_spells_hex_from_the_bytes_whatever_spelling_it_is_given(self):
        """Spec 3.3: the round trip on its own refuses upper-case hex. A rebuild that echoed the
        parsed spelling would reproduce it, and only the line pattern would stand in the way."""
        base = self.cases["readable"]["consent"]
        shouting = dict(base, token={key: value.upper() for key, value in base["token"].items()})
        self.assertEqual(render(self.golden, shouting), self.cases["readable"]["payload"])

    def test_every_case_is_fifteen_ascii_lines_that_say_i_consent_with_no_dash(self):
        for form, case in self.cases.items():
            with self.subTest(form):
                raw = bytes.fromhex(case["payloadHex"])
                self.assertTrue(all(b == 0x0A or 0x20 <= b <= 0x7E for b in raw))
                self.assertLessEqual(len(raw), 2048)
                text = raw.decode("ascii")
                self.assertEqual(text.count("\n"), 15)
                self.assertTrue(text.endswith("\n"))
                self.assertIn("I consent", text)
                self.assertNotIn("\u2014", text)
                self.assertNotIn("\u2013", text)

    def test_percentages_are_exact_decimals_with_trailing_zeros_stripped(self):
        """Spec 2.3: 800 -> 8, 150 -> 1.5, 20 -> 0.2, 405 -> 4.05; every integer bps terminates."""
        text = "".join(case["payload"] for case in self.cases.values())
        for shown in ("800 bps (8%)", "150 bps (1.5%)", "20 bps (0.2%)", "405 bps (4.05%)",
                      "5000 bps (50%)", "6000 bps (60%)", "100 bps (1%)", "1000 bps (10%)",
                      "500 bps (5%)", "200 bps (2%)"):
            self.assertIn(shown, text)

    def test_price_limits_with_no_exact_decimal_yield_no_statement(self):
        """A rounded limit would be a second spelling of the band, and the keeper rebuilds the
        statement byte for byte in another language."""
        challenge, network, params = ceremony_of(self.golden)
        thirds = dict(params, min_asset2_price={"numerator": 1, "denominator": 3})
        with self.assertRaisesRegex(vc.CeremonyError, "no exact decimal"):
            vc.canonical_consent_payload_v2(challenge, network, thirds,
                                            self.cases["readable"]["consent"])


class Parse(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.golden = load_golden()

    def test_each_case_parses_back_to_the_values_it_was_rendered_from(self):
        for case in self.golden["cases"]:
            with self.subTest(case["tokenLineForm"]):
                self.assertEqual(parse(self.golden, bytes.fromhex(case["payloadHex"])),
                                 case["consent"])

    def test_the_golden_names_every_variant_the_spec_lists(self):
        self.assertLessEqual(REQUIRED_VARIANTS, {v["name"] for v in self.golden["variants"]})

    def test_every_variant_is_a_different_byte_string_from_every_case(self):
        cases = {case["payloadHex"] for case in self.golden["cases"]}
        for variant in self.golden["variants"]:
            self.assertNotIn(variant["payloadHex"], cases, variant["name"])

    def test_every_variant_is_refused_by_the_rule_the_golden_names(self):
        """The rule, not just the refusal: a check deleted from the parser shows up as a variant
        refused one rule later, which a bare assertRaises would pass."""
        for variant in self.golden["variants"]:
            with self.subTest(variant["name"]):
                with self.assertRaises(vc.ConsentStatementRefused) as caught:
                    parse(self.golden, bytes.fromhex(variant["payloadHex"]))
                self.assertEqual(caught.exception.rule, variant["rule"], str(caught.exception))

    def test_the_2049_byte_variant_is_canonical_but_for_its_size(self):
        """So its refusal is the size limit and nothing else: one digit shorter, it is accepted."""
        variant = next(v for v in self.golden["variants"] if v["name"] == "2,049 bytes")
        raw = bytes.fromhex(variant["payloadHex"])
        self.assertEqual(len(raw), 2049)
        digits = raw.split(b"book value cap: ")[1].split(b" ")[0]
        shorter = raw.replace(b"book value cap: " + digits, b"book value cap: " + digits[1:], 1)
        self.assertEqual(len(shorter), 2048)
        self.assertEqual(parse(self.golden, shorter)["terms"]["maxDepthAda"], int(digits[1:]))

    def test_a_statement_for_another_generation_is_refused_by_the_rebuild(self):
        challenge, network, params = ceremony_of(self.golden)
        encoded, _ = vc.encode_params(params, network)
        other = vc.possession_challenge(
            network, "adc2a7f19bf63b378c06c7d941bba6b7f6312cb8cce5b153f356efe4", encoded)
        with self.assertRaises(vc.ConsentStatementRefused) as caught:
            vc.parse_consent_payload_v2(SPEC_2_2_NIGHT.encode(), other, network, params)
        self.assertEqual(caught.exception.rule, "3.3.5")


class EdgesTheGoldenLeavesOpen(unittest.TestCase):
    """consent-v2.edges.golden.json. Every case of the main golden is signed in 2026 at decimals
    6, where the price-limits line prints params 5 and 6 as they are; a TypeScript port can pass
    all of it and still misread an early year or a token with other decimals."""

    @classmethod
    def setUpClass(cls):
        cls.golden = load_golden()
        cls.edges = load_edges()
        cls.night = next(c for c in cls.golden["cases"] if c["tokenLineForm"] == "readable")

    def accepted(self):
        """(label, the document holding the ceremony it was rendered over, case)."""
        for case in self.edges["signedAtCases"]:
            yield case["consent"]["signedAt"], self.edges, case
        for case in self.edges["decimalsCases"]:
            yield f"decimals {case['consent']['decimals']}", case, case

    def test_render_equals_every_edges_payload(self):
        for label, owner, case in self.accepted():
            with self.subTest(label):
                rendered = render(owner, case["consent"])
                self.assertEqual(rendered, case["payload"])
                self.assertEqual(rendered.encode(), bytes.fromhex(case["payloadHex"]))

    def test_every_edges_payload_parses_back_to_the_values_it_was_rendered_from(self):
        for label, owner, case in self.accepted():
            with self.subTest(label):
                self.assertEqual(parse(owner, bytes.fromhex(case["payloadHex"])), case["consent"])

    def test_the_signed_at_cases_are_the_night_example_signed_in_early_years(self):
        self.assertEqual(self.edges["ceremony"], self.golden["ceremony"])
        cases = self.edges["signedAtCases"]
        self.assertEqual([c["consent"]["signedAt"] for c in cases], list(EARLY_SIGNED_AT_UNIX))
        for case in cases:
            with self.subTest(case["consent"]["signedAt"]):
                self.assertEqual(case["consent"],
                                 dict(self.night["consent"], signedAt=case["consent"]["signedAt"]))

    def test_early_years_carry_their_proleptic_gregorian_epoch_seconds(self):
        self.assertEqual(
            {c["consent"]["signedAt"]: c["signedAtUnix"] for c in self.edges["signedAtCases"]},
            EARLY_SIGNED_AT_UNIX)

    def test_year_0000_is_refused_at_3_3_4(self):
        """The reference calendar starts at year 1, Python's MINYEAR. A proleptic-Gregorian check
        in JavaScript accepts 0000-01-01, so a port that is not pinned here accepts a statement
        this verifier refuses."""
        self.assertEqual([v["name"] for v in self.edges["variants"]], ["0000-01-01T00:00:00Z"])
        variant = self.edges["variants"][0]
        self.assertEqual(variant["payload"], self.night["payload"].replace(
            "signed at: 2026-09-23T18:40:26Z\n", "signed at: 0000-01-01T00:00:00Z\n"))
        self.assertEqual(bytes.fromhex(variant["payloadHex"]), variant["payload"].encode())
        self.assertEqual(variant["rule"], "3.3.4")
        with self.assertRaises(vc.ConsentStatementRefused) as caught:
            parse(self.edges, bytes.fromhex(variant["payloadHex"]))
        self.assertEqual(caught.exception.rule, "3.3.4", str(caught.exception))

    def test_decimals_cases_are_0_2_and_18_with_a_readable_and_a_hex_only_name(self):
        cases = self.edges["decimalsCases"]
        self.assertEqual([c["consent"]["decimals"] for c in cases], [0, 2, 18])
        self.assertLessEqual({"readable", "hex"}, {c["tokenLineForm"] for c in cases})
        for case in cases:
            with self.subTest(case["consent"]["decimals"]):
                line = token_line_of(case["payload"])
                self.assertEqual(line, case["tokenLine"])
                self.assertEqual(line.startswith("your token: policy "),
                                 case["tokenLineForm"] == "hex", line)

    def test_the_price_limits_are_the_band_scaled_by_ten_to_the_decimals(self):
        """Read at decimals 6, as every case of the main golden is, the same band prints another
        line. Binary floating point prints 2.5e-7 and 0.35000000000000003 for two of these."""
        for case in self.edges["decimalsCases"]:
            decimals = case["consent"]["decimals"]
            with self.subTest(decimals):
                self.assertEqual(case["priceLimitsLine"], PRICE_LIMITS_AT_DECIMALS[decimals])
                self.assertEqual(case["payload"].split("\n")[6], case["priceLimitsLine"])
                at_six = render(case, dict(case["consent"], decimals=6)).split("\n")[6]
                self.assertNotEqual(at_six, case["priceLimitsLine"])

    def test_each_decimals_ceremony_is_the_night_ceremony_with_only_its_band_replaced(self):
        night = self.golden["ceremony"]
        band = {"min_asset1_price", "min_asset2_price"}
        for case in self.edges["decimalsCases"]:
            ceremony = case["ceremony"]
            with self.subTest(case["consent"]["decimals"]):
                self.assertEqual(
                    {k: v for k, v in ceremony["params"].items() if k not in band},
                    {k: v for k, v in night["params"].items() if k not in band})
                self.assertEqual((ceremony["network"], ceremony["unappliedScriptHash"]),
                                 (night["network"], night["unappliedScriptHash"]))
                encoded, _ = vc.encode_params(ceremony["params"], ceremony["network"])
                self.assertEqual(ceremony["paramCborHex"],
                                 [p["plutus_data_cbor_hex"] for p in encoded])
                self.assertEqual(ceremony["challengeHex"], vc.possession_challenge(
                    ceremony["network"], ceremony["unappliedScriptHash"], encoded).hex())


class ConsentTermsFile(unittest.TestCase):
    """--consent-terms reads the same object the parser returns and --json-out reports, with
    nothing missing and nothing extra: a key this tool does not render must not look accepted."""

    def load(self, doc):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(doc, fh)
        self.addCleanup(os.unlink, fh.name)
        return vc.load_consent_terms(fh.name)

    def test_a_consent_object_from_the_golden_loads_as_it_is(self):
        consent = load_golden()["cases"][0]["consent"]
        self.assertEqual(self.load(consent), consent)

    def test_a_missing_or_extra_key_is_refused_at_any_depth(self):
        consent = load_golden()["cases"][0]["consent"]
        for bad in (dict(consent, fee=20), {k: v for k, v in consent.items() if k != "signedAt"},
                    dict(consent, terms=dict(consent["terms"], dailyLossKillAda=5)),
                    dict(consent, token={"policyId": consent["token"]["policyId"]})):
            with self.subTest(sorted(bad)):
                with self.assertRaisesRegex(vc.CeremonyError, "exactly"):
                    self.load(bad)

    def test_an_integer_too_long_to_read_is_refused_rather_than_crashing(self):
        """json.load raises a bare ValueError, not JSONDecodeError, for an integer longer than
        sys.get_int_max_str_digits(), and the tool reports only CeremonyError as a refusal."""
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            fh.write('{"decimals": ' + "9" * (sys.get_int_max_str_digits() + 1) + "}")
        self.addCleanup(os.unlink, fh.name)
        with self.assertRaisesRegex(vc.CeremonyError, "cannot be read as JSON"):
            vc.load_consent_terms(fh.name)

    def test_a_value_of_the_wrong_type_is_refused(self):
        consent = load_golden()["cases"][0]["consent"]
        for bad in (dict(consent, decimals=True), dict(consent, decimals="6"),
                    dict(consent, terms=dict(consent["terms"], spreadBps=800.0)),
                    dict(consent, token=dict(consent["token"], assetNameHex=None))):
            with self.subTest(bad):
                with self.assertRaisesRegex(vc.CeremonyError, "must be"):
                    self.load(bad)


class FundingCap(unittest.TestCase):
    def test_the_golden_carries_the_spec_funding_caps(self):
        """Spec 5, MEASURED: floor(maxDepthAda * 1,000,000 * 5 / 6) lovelace."""
        caps = {row["maxDepthAda"]: row["fundingCapLovelace"]
                for row in load_golden()["fundingCapLovelace"]}
        self.assertEqual(caps, {60: 50_000_000, 61: 50_833_333, 120: 100_000_000})


if __name__ == "__main__":
    unittest.main()
