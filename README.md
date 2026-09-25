# SaturnSwap MMaaS — verify your own ceremony

This repository publishes source generations for your market-making instance, plus the tool that
checks it. It exists so you never have to take SaturnSwap's word for anything.

**Check your generation first.** The repository root publishes the current source generation;
every generation it has ever published is retained under `generations/`. Which one YOUR address
was built on is decided by your credential, not by which is newest, so read
[Validator generations](GENERATIONS.md) — it lists every published generation with the source
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
| a browser wallet | `--possession-proof possession-proof.json --my-address <your address>` — the onboarding page produces that file from a wallet signature |
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

## The published mainnet parameters

Cross-check these against <https://saturnswap.io/v3/mmaas#manifest>, and against
any source that is not us.

| parameter | value |
|---|---|
| `adam_bot_pkh` | `cea98dfce26e0ffbf5ab892edcb8f8ab8b794d5390f80ec0b9aafed3` |
| `dapp_hash` | `11928a3ac3b65edbf103ea6bb3362e39b879a36f02897df31c40917b` |
| `beacon_id` | `8a199a17ef4517215945aaf3c8c5204c60fd94d34c46d341e99c8fcf` |
| `fee_address` | `addr1v9wr69p2tx8dx2lat8rzznahxh4xhfl075yzm8uxmth4tvcf3lx47` |
| `fee_bps` | `20` (0.20%) |

Each is checkable on chain rather than by trust:

- `beacon_id` is a policy id, which *is* the hash of its own minting script. Fetch
  that script from any mainnet indexer and read the error strings inside it: they
  say `Two-way swaps must have exactly three kinds of beacons`, `Wrong
  asset1_beacon` and `Wrong asset2_beacon`. A **one-way** policy says `One-way`
  and `Wrong offer_beacon` instead — that is how the two deployments are told
  apart, and they are otherwise indistinguishable. This validator is two-way: its
  datum has twelve fields with an `asset1_price` and an `asset2_price`, where the
  one-way datum has eleven and a single `swap_price`.
- `dapp_hash` appears inside that same beacon script as an applied parameter, so
  one fetch checks both rows.
- `adam_bot_pkh` is the payment credential of
  `addr1v882nr0uufhql7l44wyjah9clz4ck72d2wg0srkqhx40a5c6g5gjp`, the address that
  key funds and has signed from many times on mainnet.
- `fee_address` is an enterprise address (header `0x61`) used for this fee and
  nothing else.

## What the validator does and does not bound

`maker_stake_bound` is the perimeter. A keeper-signed action may only return
value to your order address, pay your payout address, or take one ADA-only fee
leg at the published fee address — bounded by `fee_bps`, which the validator
refuses to build above `max_fee_bps = 500`. Anything else fails the per-asset
conservation check.

It does **not** bound quote quality, and it cannot prove the constants above are
the ones we actually run. That is what the on-chain checks are for.

Your escape-hatch key cancels every order and reclaims your funds alone, with no
cooperation or notice from us.

## Licence

Apache-2.0. Published for independent review; issues and findings welcome.
