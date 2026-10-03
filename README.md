# SaturnSwap MMaaS: verify your own ceremony

This repository publishes source generations for your market-making instance, plus the tool that
checks it. It exists so you never have to take SaturnSwap's word for anything.

**Check your generation first.** The repository root publishes the current source generation;
every generation it has ever published is retained under `generations/`. Which one YOUR address
was built on is decided by your credential, not by which is newest, so read
[Validator generations](GENERATIONS.md). It lists every published generation with the source
selector, exact pins, security differences, and migration requirements.


Your liquidity rests at an address derived from nine parameters. Two are yours
alone; five are ours to publish and yours to check; two are prices you set. Once
bound they cannot be changed, so verify before you fund.

## Verify

```bash
git clone https://github.com/Flux-Point-Studios/saturnswap-maker-verify
cd saturnswap-maker-verify

python3 verify_ceremony.py \
  --params my-ceremony.params.json \
  --network mainnet \
  --decimals <your token's decimals> \
  --expect-band-ada-per-display-unit <low>:<high> \
  --expect-order-address <the address SaturnSwap gave you> \
  --possession-proof possession-proof.json \
  --my-address <your own wallet address>
```

It rebuilds the validator from the source in this repo, re-applies your nine
parameters, derives the address, and **refuses loudly** if anything disagrees.
`--derive-only` shows what your parameters produce without asserting a verdict.

Requires [aiken](https://aiken-lang.org) v1.1.22 and Python 3.

### Proving the escape-hatch key is yours

A verdict is a sentence about *your* protections, so this tool will not print one
until somebody has proved they can sign for `client_owner_vkh`. Otherwise it would
only be checking that our arithmetic is self-consistent.

Three ways to prove it, and you need exactly one:

| you have | pass |
|---|---|
| a browser wallet | `--possession-proof possession-proof.json --my-address <your address>`; the onboarding page produces that file from a wallet signature |
| a signing key file | `--my-skey-file payment.skey` |
| a hardware or offline signer | `--possession-proof <witness or detached signature>` (see `--derive-only` for the challenge) |

**`--my-address` must be an address you recognise as your own.** It is the one
input that comes from you rather than from us, and the tool binds it to the
proof's own header, to the ceremony's payout address, and to the key that signed.
Supplied with a non-wallet proof it is refused rather than ignored, because a flag
that is silently dropped is worse than one that was never there.

What no tool can establish: that you are the *only* holder of that key. That
follows from you having generated it yourself and produced the signature yourself.
**If we handed you either one, the verdict is worth nothing.**

A wallet proof is accepted in exactly two shapes:

| wallet | COSE protected header | COSE_Key |
|---|---|---|
| lucid, Eternl | `{1: -8, "address": <address>}` | `{1: 1, 3: -8, -1: 6, -2: <32-byte key>}` |
| Lace, any `@cardano-sdk/key-management` wallet | `{1: -8, 4: <address>, "address": <address>}` | `{1: 1, 2: <address>, 3: -8, -1: 6, -2: <32-byte key>}` |

The `kid` (label 4, and label 2 of the key) must be the signing address byte for byte.
Any other kid, any other label, a kid in the unsigned header, or a key that does not match
the header's shape is refused. `testdata/cip30-lace-kid-vectors.json` holds one genuine
proof of each shape.

### Consenting to be market-made

The keeper quotes a book only under a v2 consent statement its owner signed: fifteen plain
ASCII lines that say "I consent to SaturnSwap making a market in my token with its bot key,
on the terms below." and name the token, the fee bound, your price limits and the four terms
(spread, book value cap, daily loss limit, reprice step).

- `--consent-terms terms.json` builds the exact statement for your ceremony. It is the
  `possession_payload` in `--json-out`. Without the flag, no statement is offered.
- No statement is offered for terms outside the operator bounds, because the keeper returns a
  book signed on them to your wallet. The bounds are read from `consentTerms.bounds.json`, the
  file the keeper and the page are tested against. Nor is one offered by a run that refuses the
  ceremony; a run missing only your key proof still offers it, since signing it is that proof.
- The `your wallet:` line is the address the `client_payout_address` parameter encodes, in lower
  case, however the params file spells it.
- Verifying a wallet proof over it prints `You consented to:` with the lines you signed, and
  `--json-out` carries them as `consent_terms`. A proof over any other message is refused; when
  that message is a damaged v2 statement, the refusal names the rule it breaks.
- A proof over the older v1 statement still proves the key. It is reported as `v1, audit
  only, not accepted by the keeper`, because it never says "I consent".

```json
{"token": {"policyId": "<56 hex>", "assetNameHex": "<hex, empty for no name>"},
 "decimals": 6,
 "terms": {"spreadBps": 800, "maxDepthAda": 120, "dailyLossBps": 500, "minRepriceBps": 150},
 "signedAt": "2026-09-24T12:00:00Z"}
```

## Checking a CIP-30 signature in your own code

The tool reads every wallet proof through one function, and a service can call it directly:

```python
from verify_ceremony import verify_cip30_envelope, CoseRejected

vkey = verify_cip30_envelope(cose_sign1_hex, cose_key_hex, expected_payload, expected_address)
```

It returns the 32-byte ed25519 key that signed exactly `expected_payload` (bytes) from
`expected_address` (the address as raw bytes), or raises `CoseRejected`, whose
`code` says why. The payload is never read out of the proof: you say what must have been signed.
The function proves that the key the address pays to signed. **Whose key that is remains your
check**: compare the key's hash with the owner you expect. A non-bytes argument, or bytes that are
no Shelley address, is a mistake in the calling code and raises `TypeError` or `ValueError`.

| `code` | refused because |
|---|---|
| `cbor_malformed` | not hex, not one COSE_Sign1, or CBOR that does not decode |
| `cbor_noncanonical` | a head wider than shortest form, or an indefinite length |
| `trailing_bytes` | bytes after the COSE_Sign1, or inside the protected header after its map |
| `protected_labels` | the protected header is not exactly one of the two shapes above |
| `alg_not_eddsa` | the algorithm is not EdDSA (-8) |
| `address_mismatch` | the header's address is not `expected_address`, byte for byte |
| `unprotected_not_hashed_false` | the unsigned header is not `{}` or exactly `{hashed: false}` |
| `payload_mismatch` | the signed payload is not `expected_payload`, or there is none |
| `cose_key_shape` | the COSE_Key is not one of the two shapes above, or carries an extended key |
| `small_order_key` | the key is a small-order point, which has no private half |
| `script_payment_credential` | the address pays to a script, which no wallet key signs for |
| `reward_address` | the address is a reward address, signed for with a stake key |
| `key_hash_mismatch` | the key is not the one the address pays to |
| `bad_signature` | the ed25519 signature does not verify |

A proof's bytes do not identify it. The unsigned header lies outside the signature and may be `{}`
(a wallet that writes no unsigned header) or `{hashed: false}`, and hex has more than one spelling,
so one signature can arrive as several byte-different proofs that all verify. Key replay protection
and de-duplication on the single-use nonce inside `expected_payload`, never on `cose_sign1`.

A map key in either header that is not an integer or a text string is `cbor_malformed` as soon as
it is read, so a proof costs time and memory in proportion to its length.

`testdata/cip30-alert-vectors.json` holds wallet-library proofs over the SaturnSwap MMaaS alert
binding payloads, each with its expected verdict: a bind and an unbind, a Lace bind, a signature
relayed to the other purpose, a wallet whose stake part differs from the expected address, a
small-order forgery, and trailing bytes. They are signed by a published test key that was never
funded, and `node tools/gen_cip30_vectors.mjs alert` regenerates them byte for byte.

## The published mainnet parameters

Cross-check these against <https://saturnswap.io/v3/mmaas#manifest>, and against
any source that is not us.

| parameter | value |
|---|---|
| `adam_bot_pkh` | `1aba8f0a279e88d7aacd20a1f8e6d6ae4293a4f18fcb17cd43f20fd8` |
| `dapp_hash` | `11928a3ac3b65edbf103ea6bb3362e39b879a36f02897df31c40917b` |
| `beacon_id` | `8a199a17ef4517215945aaf3c8c5204c60fd94d34c46d341e99c8fcf` |
| `fee_address` | `addr1v9wr69p2tx8dx2lat8rzznahxh4xhfl075yzm8uxmth4tvcf3lx47` |
| `fee_bps` | `20` (0.20%) |

Each is checkable on chain rather than by trust:

- `beacon_id` is a policy id, which *is* the hash of its own minting script. Fetch
  that script from any mainnet indexer and read the error strings inside it: they
  say `Two-way swaps must have exactly three kinds of beacons`, `Wrong
  asset1_beacon` and `Wrong asset2_beacon`. A **one-way** policy says `One-way`
  and `Wrong offer_beacon` instead. That is how the two deployments are told
  apart, and they are otherwise indistinguishable. This validator is two-way: its
  datum has twelve fields with an `asset1_price` and an `asset2_price`, where the
  one-way datum has eleven and a single `swap_price`.
- `dapp_hash` appears inside that same beacon script as an applied parameter, so
  one fetch checks both rows.
- `adam_bot_pkh` is the payment credential of
  `addr1vydt4rc2y70g34a2e5s2r78x66hy9yay7x8uk97dg0eqlkqefwst2`, the address the
  bot key pays reprice fees from. Anyone can check its spends on any mainnet
  explorer. It replaces the retired key
  `cea98dfce26e0ffbf5ab892edcb8f8ab8b794d5390f80ec0b9aafed3` and its address
  `addr1v882nr0uufhql7l44wyjah9clz4ck72d2wg0srkqhx40a5c6g5gjp`.
- `fee_address` is an enterprise address (header `0x61`) used for this fee and
  nothing else.

## What the validator does and does not bound

`maker_stake_bound` is the perimeter. A keeper-signed action may only return
value to your order address, pay your payout address, or take one ADA-only fee
leg at the published fee address, bounded by `fee_bps`, which the validator
refuses to build above `max_fee_bps = 500`. Anything else fails the per-asset
conservation check.

It does **not** bound quote quality, and it cannot prove the constants above are
the ones we actually run. That is what the on-chain checks are for.

Your escape-hatch key cancels every order and reclaims your funds alone, with no
cooperation or notice from us.

## Licence

Apache-2.0. Published for independent review; issues and findings welcome.
