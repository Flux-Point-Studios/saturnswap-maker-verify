# Validator generations

An order address commits to the **applied** validator: source plus the client's nine
ceremony parameters. The hashes below identify the **unapplied** source generations;
they are not a client's stake credential. Updating this repository cannot upgrade an
existing address or move its funds.

| Source generation | Source location | Bot continuation pair | Staking rewards in fee basis |
|---|---|---|---|
| `18d2246d8b552b9e462ec93dece5716a7154314680b3f326a854789d` | Repository root | Must match the pair in the spent order inputs | Subtracted, with the basis clamped at zero |
| `adc2a7f19bf63b378c06c7d941bba6b7f6312cb8cce5b153f356efe4` | `generations/adc2a7f19bf63b378c06c7d941bba6b7f6312cb8cce5b153f356efe4` | Not checked against the spent pair | Not excluded |

The historical files are retained byte-for-byte from public verifier commit
`a1972d3f70a03c51ee448ed31f13ebb4c3298e99`. The current source and ceremony fixtures
come from SaturnSwapContract commit `2bf0f99835d502fda54162049650d9288bf9925d`.
Both generations pin Aiken **v1.1.22+39d6b04**, Plutus V3, and stdlib **v3.1.0**.
`verify_project.sh` checksums the compiler release and runs current-source tests,
rebuilds both generations, and checks that an address from one cannot pass as the other.

## Check an existing address

Start with the ceremony JSON and order address you actually funded. Use the command in
[README.md](README.md), including your expected order address, independent price-band
check, and wallet possession proof. For an `adc2…` ceremony, add:

```sh
--project ./generations/adc2a7f19bf63b378c06c7d941bba6b7f6312cb8cce5b153f356efe4
```

Run the **root** `verify_ceremony.py` with that option. It rebuilds the selected source,
compares it with its committed blueprint, applies the parameters, and compares the
result with your expected address. The historical directory contains source artifacts,
not a second copy of the CLI. Do not change an expected address to make a mismatch pass.
Do not substitute another generation's possession proof: its challenge also changes.
`--derive-only` proves neither wallet possession nor live chain state.
Seven-parameter and other unlisted generations need their own matching source release;
neither of these nine-parameter packages verifies them.

## What the distinction means

The `adc2…` validator conserves assets during a bot transaction but does not bind a
continuation's declared trading pair to the input pair. The bot can split an order and
redeclare the ADA leg against another token while meeting the numeric price floors.
A later permissionless taker fill can exploit that quote. The `18d…` generation rejects
those pair changes. Its bot fee calculation also excludes withdrawn staking rewards;
the older generation does not provide that exclusion.

These are generation-specific guarantees, not claims of a complete audit. The band is
an immutable bid ceiling and ask floor, not an oracle-relative price guarantee. Public
taker fills run the DEX's trading rules and are distinct from bot owner actions.

Moving an old book to the current generation requires a new ceremony and address, and
client-authorized recovery and funding transactions. The client-signature branch
remains available on both generations; changing the verifier does not migrate a book.
The included CLI escape helper uses a zero withdrawal and refuses a nonzero or
unreadable reward balance by default. Verification support is not a claim that this
helper can recover every delegated account without additional client-signed steps.
