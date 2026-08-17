# MMaaS fee collection — design & recommendation

**Status:** design, for deci's decision. Nothing built. 2026-07-31.
**Problem:** billing today is *metering-only* — the backend computes `operator_fee_lovelace` per client and displays it; nothing collects it. This designs the collector.

---

## TL;DR / recommendation

**Ship D now, fold A into the custody re-ceremony we already owe for mainnet, skip B.**

- **Build the collection *spine* once** (metering delta + reorg-safe watermark + reuse the live 1% treasury sweep). Every option below is just a different *on-chain draw mechanism* bolted onto that same spine — so Phase 0 is never thrown away.
- **Phase 0 (days): D — prepaid fee-channel.** A client-funded native-script channel the keeper draws the metered fee from. No audited-validator change, no re-ceremony. Trading capital stays non-custodial; the fee is bounded by a channel balance the client sets and can reclaim anytime. Starts earning revenue immediately. Enforcement is *commercial* (suspend market-making if unfunded), not on-chain — acceptable because there are no live clients yet and first clients are dogfood/disclosed anyway.
- **Phase 1 (target): A — validator-bounded fee leg.** Bake `fee_bps` + `fee_address` into `maker_stake_bound`; the fee output rides the same tx that returns the client their realized ADA, and the client's *own applied script hash* caps it at `fee ≤ fee_bps × realized-ADA`. Trust the hash, nothing else — the only design that fully delivers the non-custodial promise. Its expensive part (a full re-ceremony + fund migration) **is already required for the mainnet custody-rail hardening** (#258/#260/#261 all force a new applied hash), so the fee params are ~15 incremental lines on a ceremony we're doing regardless.
- **Skip B** (a separate fee-bond escrow validator). Its only advantage over A is "avoids re-ceremony" — moot, because mainnet forces the re-ceremony anyway. B adds a whole new audited validator + a session-signer daemon to get ~90% of A's guarantee.

**Why phased and not "A only":** A is the right *end state*, but it cannot ship today (no audited validator, re-ceremony, migration) and there is **no live client, book, or fill on mainnet yet** — so gating revenue on A means zero revenue for weeks while the beacon book and custody rail reach mainnet. D collects safely in the meantime and its metering/watermark/sweep code *is* A's, verbatim.

---

## The core constraint (why this is a cursed problem)

MMaaS is **non-custodial**: the client's funds live under their own `maker_stake_bound` instance; the operator holds only a bot key that can act *within* the validator's payout bound. "Collect the fee" therefore **cannot** mean "sweep the client's wallet" — that would destroy the product.

Verified against the audited validator (`maker_stake/validators/maker_stake_bound.ak`):

- A bot-signed action is only a **reprice or cancel**, gated by `payout_bound` (L149-290). Value may go to **exactly two sinks**: a continuation at the client's own order address, or a bare output to `client_payout` (the client's own key). **Anything to any other address fails per-asset conservation** (L281-287) — proven by `bot_skims_one_lovelace_rejected` (L698): *even one lovelace* to a non-client address is rejected.
- So the operator earns **nothing** through the bound path today. A fee has to be *authorized* by the client's script, not smuggled past it.

**The minimal trustless fix (Approach A), exact:** add two positional ceremony params — `fee_address: Address`, `fee_bps: Int` — and a third recognized output sink in the `allowed_out` fold that accumulates ADA-only, datum-free outputs to `fee_address`, plus one conjunct:

```
fee_out_lovelace * 10_000  ≤  fee_bps * lovelace_paid_to_client_payout
```

~15 lines. The token side stays fully conserved to the client (fee is ADA-only, mirroring the live 1% model). The bound is in the applied hash the client re-derives with `verify_ceremony.py` **before funding** — no oracle, no daemon, no operator honesty assumption.

---

## The options (adversarially scored, 1–5, higher better)

| Approach | custody | trustless-bound | reorg-safe | enforcement | ship-cost | reuse | **total** |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| **A** — validator-bounded fee leg on the harvest tx | 4 | **5** | 5 | 3 | 2 | 5 | **24** |
| **B** — prepaid fee-bond escrow (new validator + session daemon) | 4 | 4 | 4 | 4 | 3 | 4 | **23** |
| **D** — prepaid fee-channel (native script, off-chain metered) | 4 | 2 | 4 | 3 | **5** | 5 | **23** |
| **C** — segregated on-chain accrual + batch sweep | 3 | 5 | 4 | 3 | 1 | 4 | **20** |

- **A wins on the property that matters:** the over-charge cap lives in the client-verifiable script hash. Atomic with the ADA return (no separate desync-able collection tx). Sizing reuses the proven k-final billable view + a collection watermark. Cost: a new audited validator + re-ceremony + fund migration of every live bound book.
- **C is strictly dominated by A** — same on-chain bound, bigger edit to the audited rail, more risk. Rejected.
- **D is the ship-now bridge, not the target:** a native `any[operator, client]` script has **no on-chain `fee_bps` bound** — within the channel balance the operator-keep amount is *trust-based* (keeper-metered, not ledger-enforced). Its hard bound is only "draw ≤ channel balance, client can reclaim anytime." Good enough to start, explicitly temporary.
- **B** gets a hard on-chain bound without touching `maker_stake_bound`, but needs a new validator **and** a live session-signer daemon. Skipped because mainnet forces the re-ceremony that erases its one advantage.

---

## Recommended architecture

### The spine (build once, Phase 0 — reused by every phase)

1. **Delta engine.** `delta_owed = billable operator_fee_lovelace (BeaconClientStatsMaterializedViews) − collected`. The billable view is already **k-final** (only volume past the `high_water_slot`/`high_water_block` finality horizon counts), so the delta never charges un-final volume.
2. **Collection watermark.** New `mmaas_fee_collection` table (per `owner_stake_credential`), cloned from the `MmaasClientGrantService` pattern. Advance the watermark **only after the draw tx confirms to depth**, carrying a `pending_draw_tx_hash` so a keeper crash mid-draw is idempotent (never double-charges).
3. **Sweep.** Reuse the live 1% treasury path (`FeeComponentService` / `SweepSplitService`) + the fee-address config. The metered ADA lands in the same treasury the 1% fee already sweeps.

### Phase 0 draw — D (native fee-channel)
Client pre-funds a small native-script channel `any[operator_fee_hotkey, client_owner_vkh]`. Keeper builds a `cardano-cli` draw of `delta_owed` → fee treasury, bounded by channel balance; **suspends market-making** below a low-water threshold (the enforcement lever). Client can reclaim the channel anytime (non-custodial).

### Phase 1 draw — A (validator-bounded fee leg)
Same spine computes `delta_owed`. The keeper (adam-oc `build-cli-recipe.sh`) adds one ADA-only output to `fee_address` on the harvest/cancel tx the bot already signs. The validator caps it at `fee_bps × realized-payout`. **Only the draw mechanism changes** — D→A is param/validator work, not a rewrite.

---

## Honest limitations (true of the whole class, not bugs to fix)

1. **Escape-hatch evasion (structural, unclosable):** a client holding their own key can always cancel fee-free (validator L323, no value constraint on the client path). Accrued-but-uncollected fee at a self-exit is an **operator write-off**. This is the price of non-custody; it cannot be closed without becoming custodial.
2. **Notional base = realized ADA returned to `client_payout`, not gross traded volume.** That's the only quantity the validator can see on-chain. If the operator rarely harvests to the client (keeps repricing), little is billable on-chain and the rest is an off-chain receivable. Metering (volume) and the on-chain collectible bound (realized payout) are different quantities — worth being explicit with clients.
3. **A caps the MAX, not a MIN:** the validator prevents over-collection; it does not force the operator to collect. Minimum-fee correctness stays keeper-side (fine — the operator wants the max owed).
4. **Token-token pairs earn no fee** (no ADA leg to charge, matching the 1% `EnsureAdaLeg` model). Accept zero, or build a token-fee path the treasury sweep can't currently handle.
5. **D's enforcement is commercial** (suspend service), not on-chain.

---

## Decisions for deci (genuinely yours)

1. **Fee model:** confirm bps rate + period cap; ADA-on-the-ADA-leg (mirror the live 1%); and accept the notional base = **realized `client_payout` ADA** (not gross volume) — that's what A/C can bind trustlessly.
2. **Gate go-live on trustless (A), or ship the bridge (D) first?** My rec: **ship D now** (revenue + non-custodial trading capital immediately), audit/re-ceremony A **in parallel, folded into the mainnet custody-rail hardening**.
3. **Skip B?** My rec: **yes** — its no-re-ceremony advantage is moot once mainnet forces the re-ceremony.
4. **Prepaid float sizing + auto-top-up + low-water pause UX** — this is real capital friction for clients; how big a float, and pause vs auto-top-up.
5. **Disclosure/consent + first clients:** any mainnet fee from third-party funds must be disclosed, consented, deci-gated (matching existing MMaaS custody posture). Dogfood first (our own bound book) before an external client.
6. **Token-token pairs:** accept zero fee, or fund a token-fee path?
7. **Receivable write-off policy:** how large an uncollected receivable the keeper tolerates before it pauses service, and the accepted-loss stance on escape-hatch self-exits.

---

## What compounds

The spine reuses three things already live and proven: the k-final billable view (#255), the `high_water_slot` finality machinery (just migrated), and the 1% treasury sweep. A folds two params into a re-ceremony already required for mainnet. Nothing here is greenfield — it activates dormant value (the metering engine) into actual revenue.
