# SaturnSwap MMaaS — verify your own ceremony

This is the validator your market-making instance runs on, plus the tool that
checks it. It exists so you never have to take SaturnSwap's word for anything.

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
  --expect-order-address <the address SaturnSwap gave you>
```

It rebuilds the validator from the source in this repo, re-applies your nine
parameters, derives the address, and **refuses loudly** if anything disagrees.
`--derive-only` shows what your parameters produce without asserting a verdict.

Requires [aiken](https://aiken-lang.org) v1.1.22 and Python 3.

## The published mainnet parameters

Cross-check these against <https://saturnswap.io/v3/mmaas#manifest>, and against
any source that is not us.

| parameter | value |
|---|---|
| `adam_bot_pkh` | `cea98dfce26e0ffbf5ab892edcb8f8ab8b794d5390f80ec0b9aafed3` |
| `dapp_hash` | `1d6cff26bcab91d2061aad0bd259cbb7d76d25ced2eeaed5926a42ad` |
| `beacon_id` | `c4d7d117d9ebcde6db28db40837ff2b1401e9eaaa6eecea9e070e209` |
| `fee_address` | `addr1v9wr69p2tx8dx2lat8rzznahxh4xhfl075yzm8uxmth4tvcf3lx47` |
| `fee_bps` | `20` (0.20%) |

Each is checkable on chain rather than by trust:

- `dapp_hash` is the payment credential of any live order address.
- `beacon_id` is the policy id of the beacon tokens resting on any order.
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
