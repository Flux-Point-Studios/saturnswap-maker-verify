//// SaturnSwap MMaaS — payout-constrained market-maker staking validator.
////
//// A client's inventory rests at the canonical cardano-swaps spend script
//// with THIS script as its stake credential:
////
////   Address(Script(dapp_hash), Some(Inline(Script(maker_stake_bound_hash))))
////
//// Canonical owner-auth (`common/utils.ak: staking_credential_approves`)
//// approves a reprice (`SpendWithStake` + beacon `UpdateSwaps`) or a cancel
//// (`SpendWithMint` + beacon burn) IFF this credential appears in
//// `tx.withdrawals` — the withdraw-0 trick. Unlike `maker_stake` (bot-sig
//// only, full owner authority), this variant binds the OPERATOR's authority
//// to the client's payout address:
////
////   withdraw passes iff
////     (a) the CLIENT signed (unconstrained self-custody escape hatch), or
////     (b) the ADAM bot signed AND, per asset, everything spent from the
////         client's order addresses (plus any staking reward withdrawn by
////         this credential) lands either back at an order address carrying
////         this same stake credential (with a continuation datum the dApp
////         validator can decode — anti-lock) or in an exact-address,
////         datum-free output to `client_payout`.
////
//// Beacon-policy assets are exempt from the conservation check (cancels
//// burn them; beacon integrity is the beacon script's own invariant), and
//// the min-ADA riding on beacon UTxOs is conserved like any other value:
//// a consolidation that frees min-ADA must pay it to the client.
////
//// Cross-instance double-satisfaction (two clients' bound scripts sharing
//// one payout output) is blocked structurally: the only script withdrawals
//// allowed in the tx are this credential and the beacon script, so no
//// second bound instance can even execute alongside this one.

use aiken/builtin
use aiken/cbor
use aiken/collection/list
use aiken/crypto.{ScriptHash, VerificationKeyHash}
use cardano/address.{Address, Credential, Inline, Script, VerificationKey}
use cardano/assets.{AssetName, PolicyId, Value}
use cardano/certificate.{
  AlwaysAbstain, Certificate, DelegateBlockProduction, DelegateCredential,
  DelegateVote, RegisterAndDelegateCredential, RegisterCredential,
  UnregisterCredential,
}
use cardano/script_context.{ScriptContext}
use cardano/transaction.{
  Datum, InlineDatum, Input, NoDatum, Output, OutputReference, Transaction,
  placeholder,
}

// ---------------------------------------------------------------------------
// Legacy datum mirror (cardano-swaps compiled against stdlib 1.7.0, where
// `TransactionId` wraps the hash in a record — Constr(0,[Constr(0,[bytes]),i])
// — unlike modern `OutputReference`). Continuation outputs must carry a datum
// the LEGACY dApp validator can destructure, or the UTxO is bricked for the
// client too; these mirrors reproduce that exact Data schema.
// ---------------------------------------------------------------------------

pub type LegacyTransactionId {
  hash: ByteArray,
}

pub type LegacyOutputReference {
  transaction_id: LegacyTransactionId,
  output_index: Int,
}

pub type LegacyRational {
  numerator: Int,
  denominator: Int,
}

pub type LegacySwapDatum {
  beacon_id: PolicyId,
  pair_beacon: AssetName,
  asset1_id: PolicyId,
  asset1_name: AssetName,
  asset1_beacon: AssetName,
  asset2_id: PolicyId,
  asset2_name: AssetName,
  asset2_beacon: AssetName,
  asset1_price: LegacyRational,
  asset2_price: LegacyRational,
  prev_input: Option<LegacyOutputReference>,
  expiration: Option<Int>,
}

fn is_order_address(
  addr: Address,
  dapp_hash: ScriptHash,
  own_cred: Credential,
) -> Bool {
  addr.payment_credential == Script(dapp_hash) && addr.stake_credential == Some(
    Inline(own_cred),
  )
}

// price >= floor for two strictly-positive rationals, by cross-multiplication:
// multiplying both sides of `price.num/price.den >= floor.num/floor.den` by
// the positive product `price.den * floor.den` preserves the inequality's
// direction and leaves only integer comparison. Aiken Ints are
// arbitrary-precision, so the products cannot overflow. Callers assert
// positivity on both sides — a negative denominator would flip the direction.
fn rational_geq(price: LegacyRational, floor: LegacyRational) -> Bool {
  price.numerator * floor.denominator >= floor.numerator * price.denominator
}

fn rational_positive(r: LegacyRational) -> Bool {
  r.numerator > 0 && r.denominator > 0
}

// Continuation datums must be inline, decodable by the legacy dApp validator,
// point at the real beacon policy, and price BOTH legs at or above the
// client's ceremony floors — otherwise the bot could park client value in a
// UTxO nobody can spend, or reprice a leg to dust so a colluding filler drains
// the inventory through the public TakeAsset path (conservation alone can't
// see a dust reprice: the value never leaves the order address).
/// The trading pair a swap datum declares, or `None` when the datum is not one.
///
/// ⚠️ THE CEREMONY FLOORS CARRY NO ASSET. `min_asset1_price` and
/// `min_asset2_price` are bare rationals; the datum is what says which pair they
/// price. Without this, a bot holding only its own key could re-declare a
/// client's order against a token it minted for nothing, quote AT both of the
/// client's own floors, and conserve every asset — the value does not move in
/// that transaction at all. The theft is a later permissionless TAKER fill,
/// which never invokes this validator, so neither conservation nor the floors
/// can see it. Proven executably: `bot_repair_to_foreign_pair_rejected` and
/// `bot_split_repair_rejected`.
fn declared_pair(
  datum: Datum,
) -> Option<(PolicyId, AssetName, PolicyId, AssetName)> {
  when datum is {
    InlineDatum(d) ->
      if d is sd: LegacySwapDatum {
        Some((sd.asset1_id, sd.asset1_name, sd.asset2_id, sd.asset2_name))
      } else {
        None
      }
    _ -> None
  }
}

fn is_spendable_continuation_datum(
  output: Output,
  beacon_id: ScriptHash,
  min_asset1_price: LegacyRational,
  min_asset2_price: LegacyRational,
  sanctioned_pair: Option<(PolicyId, AssetName, PolicyId, AssetName)>,
) -> Bool {
  when output.datum is {
    InlineDatum(d) ->
      if d is sd: LegacySwapDatum {
        and {
          // The pair this continuation prices must be the pair that was spent.
          // `None` — no order input, or order inputs that disagree — blesses
          // nothing, so the bot cannot conjure a pair it did not carry in.
          sanctioned_pair == Some(
            (sd.asset1_id, sd.asset1_name, sd.asset2_id, sd.asset2_name),
          ),
          sd.beacon_id == beacon_id,
          // Sign guard, self-contained: cross-multiplication in rational_geq is
          // only direction-preserving for positive rationals, and the dApp's
          // own num/den > 0 checks live in a different validator.
          rational_positive(sd.asset1_price),
          rational_positive(sd.asset2_price),
          // asset2_price = lovelace per token = the ASK a taker pays in ADA to
          // take the client's TOKEN. Too low and the token side sells for
          // near-zero ADA, so require asset2_price >= min_asset2_price.
          rational_geq(sd.asset2_price, min_asset2_price),
          // asset1_price = token per lovelace = the BID a taker pays in TOKEN
          // to take the client's ADA. Too low and the ADA side drains for
          // near-zero token, so require asset1_price >= min_asset1_price.
          rational_geq(sd.asset1_price, min_asset1_price),
        }
      } else {
        False
      }
    _ -> False
  }
}

/// The contracted ceiling. A ceremony naming a rate above this produces an
/// instance that refuses every bot action, so a mis-parameterised fee cannot be
/// signed into existence — the client does not have to notice the number.
const max_fee_bps: Int = 500

/// An ADA-only, datum-free output at the ceremony's fee address. Anything else at
/// that address is not a fee leg and is never blessed, so it falls out of both
/// `allowed_out` and `fee_taken` and the conservation check rejects the tx.
///
/// The lovelace clause is load-bearing and its absence was a real drain: a single
/// flattened entry means "exactly one non-zero asset", which a TOKEN-ONLY value
/// satisfies just as well as an ADA-only one. Such an output was blessed into
/// `allowed_out` and scored at zero by `fee_taken`, so client inventory left the
/// perimeter for a fee of nothing. The test that was supposed to catch it used
/// lovelace PLUS a token — which flattens to two entries and exercises a
/// different branch entirely.
/// OPERATIONAL, and it bites: this recognises a fee leg by its SHAPE, so ANY ADA-only
/// datum-free output at the fee address is one — including the operator's own change.
/// An operator whose fee address is also the address they balance change to sums that
/// change into `fee_taken` and can never build a valid action again. It fails closed,
/// which is the right direction, but it fails opaquely. The fee address must be used
/// for nothing but fees. Measured on preprod 2026-08-06: change of ~9,500 ADA landing
/// there would have been scored as the fee.
fn is_fee_leg(output: Output, fee_address: Address) -> Bool {
  and {
    output.address == fee_address,
    output.datum == NoDatum,
    output.reference_script == None,
    list.length(assets.flatten(output.value)) == 1,
    assets.lovelace_of(output.value) > 0,
  }
}

fn payout_bound(
  own_cred: Credential,
  self: Transaction,
  client_owner_vkh: VerificationKeyHash,
  client_payout: Address,
  dapp_hash: ScriptHash,
  beacon_id: ScriptHash,
  min_asset1_price: LegacyRational,
  min_asset2_price: LegacyRational,
  fee_address: Address,
  fee_bps_param: Int,
) -> Bool {
  // The payout leg must land at the escape-hatch key's own address. Binding it
  // to `client_owner_vkh` rather than merely "some key address" is what stops a
  // ceremony from naming an operator key as the payout target: the two
  // client-supplied parameters have to agree, so a mis-parameterisation is
  // visible in the parameters themselves rather than only on drain day. It also
  // subsumes the weaker script/dapp_hash exclusions — a Script credential can
  // never equal a VerificationKey one.
  //
  // Cost, deliberate: a hot escape key with a separate cold payout address is
  // foreclosed. The escape key must be the payout key.
  let payout_cred_ok = client_payout.payment_credential == VerificationKey(
    client_owner_vkh,
  )

  // A zero or non-positive ceremony floor disables the dust-reprice protection
  // and restores the drain, and a CROSSED band — an ask floor below the bid
  // ceiling — lets a filler buy at the ask and sell straight back at the bid.
  // `min_asset1_price` is token per lovelace, so it caps the bid at
  // 1/min_asset1_price lovelace per token; `min_asset2_price` is lovelace per
  // token, so it floors the ask. Requiring
  //   min_asset2_price >= 1 / min_asset1_price
  // cross-multiplied over the positive rationals asserted on the line above,
  // puts the ask floor at or above the bid ceiling. Every quote the per-leg
  // checks then admit satisfies bid <= ceiling <= floor <= ask, so no pair of
  // accepted quotes can be round-tripped for a profit — across two reprices or
  // across two of the client's UTxOs in one transaction, which a per-datum
  // non-crossing predicate cannot see. Both fail the bot path closed; the
  // client escape hatch never reaches here, so recovery stays open.
  let floors_ok = and {
    rational_positive(min_asset1_price),
    rational_positive(min_asset2_price),
    min_asset1_price.numerator * min_asset2_price.numerator >= min_asset1_price.denominator * min_asset2_price.denominator,
  }

  // No script withdrawal other than this credential and the beacon script may
  // run in this tx. Every spend of a script-staked order requires its stake
  // credential in `withdrawals`, so this bars a second bound instance (or the
  // legacy bot-only maker_stake) from co-executing and double-counting a
  // shared payout output.
  let withdrawals_ok = list.all(
    self.withdrawals,
    fn(w) {
      let Pair(cred, _amt) = w
      when cred is {
        Script(h) -> cred == own_cred || h == beacon_id
        VerificationKey(_) -> True
      }
    },
  )

  // Staking rewards withdrawn by this credential are client value too. Rewards
  // can only accrue if the CLIENT delegates — `publish` denies the bot every
  // delegation certificate — and if they ever do, every builder in the stack
  // withdraws a hardcoded `+0`, which the ledger rejects once the balance is
  // non-zero — so the fold is unreachable until that changes, which is exactly
  // what task #379 is changing. It carries two guarantees: the yield is client
  // value for conservation (`guarded_in` below), and it is NOT operator revenue
  // (`fee_basis`, further down). A client who delegates cannot have the yield
  // taken, and cannot be charged for it either.
  let rewards = list.foldl(
    self.withdrawals,
    0,
    fn(w, acc) {
      let Pair(cred, amt) = w
      if cred == own_cred {
        acc + amt
      } else {
        acc
      }
    },
  )

  // The conservation perimeter is keyed on the STAKE credential, which the
  // ledger hands to `withdraw` as `own_cred` and which therefore cannot be
  // mis-parameterised — unlike `dapp_hash`. Every input this credential
  // delegates to is client value whatever payment script holds it, so value
  // resting at a sibling cardano-swaps address (the live one-way order form is
  // the real instance) is inside the perimeter instead of invisible to it. The
  // OUTPUT side below still blesses only the sanctioned order form, so such
  // value is drainable nowhere.
  //
  // Scope cost, deliberate, and NOT symmetric: only beacon-free sibling value is
  // bot-rescuable to `client_payout`. A live sibling order carries beacons of
  // the SIBLING's policy, which this ceremony does not exempt; closing it burns
  // them, the burn is a per-asset deficit here, and the transaction fails. The
  // bot can move a live sibling order nowhere at all — the client's escape hatch
  // is the only thing that reaches it. A multi-dApp book stays foreclosed until
  // the ceremony takes a list of sanctioned payment scripts and beacon policies.
  let guarded_in = list.foldl(
    self.inputs,
    assets.from_lovelace(rewards),
    fn(input, acc) {
      if input.output.address.stake_credential == Some(Inline(own_cred)) {
        assets.merge(acc, input.output.value)
      } else {
        acc
      }
    },
  )

  // The pair the bot is allowed to write, taken from what it SPENT. A ceremony
  // bounds one band, and a band is a statement about one pair — so a
  // transaction that spends orders on two different pairs has no single
  // sanctioned answer and blesses no continuation at all. Fails closed: the
  // keeper batches per pair, which is what it already does.
  let spent_pairs = list.foldl(
    self.inputs,
    [],
    fn(input, acc) {
      if is_order_address(input.output.address, dapp_hash, own_cred) {
        when declared_pair(input.output.datum) is {
          Some(p) -> [p, ..acc]
          None -> acc
        }
      } else {
        acc
      }
    },
  )
  let sanctioned_pair = when spent_pairs is {
    [] -> None
    [p, ..rest] ->
      if list.all(rest, fn(q) { q == p }) {
        Some(p)
      } else {
        None
      }
  }

  let allowed_out = list.foldl(
    self.outputs,
    assets.zero,
    fn(output, acc) {
      if is_order_address(output.address, dapp_hash, own_cred) {
        if is_spendable_continuation_datum(
          output,
          beacon_id,
          min_asset1_price,
          min_asset2_price,
          sanctioned_pair,
        ) {
          assets.merge(acc, output.value)
        } else {
          acc
        }
      } else if output.address == client_payout && output.datum == NoDatum && output.reference_script == None {
        assets.merge(acc, output.value)
      } else if is_fee_leg(output, fee_address) {
        // Blessed only up to the bound checked below. Admitting it here and
        // capping it there keeps ONE conservation statement rather than two
        // that could disagree.
        assets.merge(acc, output.value)
      } else {
        acc
      }
    },
  )

  // The basis is what the position REALIZED — the payout leg plus the fee leg —
  // not what the client was left with. Both readings are safe; this one is
  // chosen because it makes `fee_bps` mean what a client reads it to mean ("you
  // take 2% of what my position realizes") instead of 2% of a number that
  // already has the fee removed, and because it keeps the arithmetic exact
  // rather than recurring.
  //
  // Either way the client's floor is the same statement: taking more requires
  // realizing more. Consensus checks it, which is the entire point of moving
  // this out of a service that kept getting it wrong.
  let payout_realized = list.foldl(
    self.outputs,
    0,
    fn(output, acc) {
      if output.address == client_payout && output.datum == NoDatum && output.reference_script == None {
        acc + assets.lovelace_of(output.value)
      } else {
        acc
      }
    },
  )

  // Summed across every fee output: splitting the leg must not multiply the
  // allowance.
  let fee_taken = list.foldl(
    self.outputs,
    0,
    fn(output, acc) {
      if is_fee_leg(output, fee_address) {
        acc + assets.lovelace_of(output.value)
      } else {
        acc
      }
    },
  )

  // A fee leg carrying anything but ADA would let the operator take inventory and
  // call it a fee. `is_fee_leg` is what makes that true; see the drain described
  // there for why the lovelace clause is not decoration.
  // A cancel hands the client back their own capital, and a stateless validator
  // cannot tell a returned deposit from a realized gain — the arithmetic below
  // scores both identically. Without this clause the bound permits fee_bps of
  // principal that never traded: 10,000 ADA deposited, never filled, cancelled,
  // and 200 of it leaves as a fee. Burning a beacon of this ceremony's policy IS
  // how a cardano-swaps order closes, so a transaction that closes one takes no
  // fee at all. The operator is paid for running a position, not for returning
  // it.
  //
  // What this does NOT close, stated rather than implied: an operator that
  // leaves a continuation open keeps the fee available on everything else the
  // same transaction returns. No predicate over one transaction can do better —
  // "this inventory never traded" is not a fact any transaction carries.
  let closes_an_order = list.any(
    assets.flatten(self.mint),
    fn(entry) {
      let (pid, _name, qty) = entry
      pid == beacon_id && qty < 0
    },
  )

  // deci's rule, second reading: the operator is paid for RUNNING the position,
  // and staking yield is not something the operator ran. `publish` only ever
  // lets the CLIENT delegate, so every lovelace of `rewards` was produced by the
  // client's own credential — and `payout_realized` cannot tell it apart from a
  // realized gain, because both arrive as lovelace at `client_payout`.
  //
  // So the yield leaves the basis. Subtracted rather than forbidden outright: a
  // transaction that harvests AND realizes a genuine trade may still be paid on
  // the trade, and a blunt "no fee whenever rewards move" would only push the
  // keeper into extra transactions and extra gas for no gain to the client.
  //
  // Clamped at zero because the subtraction is not a conservation statement:
  // rewards can be routed into inventory rather than to the payout, and a
  // negative basis must read as "nothing the operator earned", never as a
  // credit against some other transaction's fee.
  let fee_basis = if payout_realized > rewards {
    payout_realized - rewards
  } else {
    0
  }

  let fee_ok = and {
    fee_bps_param >= 0,
    fee_bps_param <= max_fee_bps,
    fee_taken * 10_000 <= ( fee_basis + fee_taken ) * fee_bps_param,
    or {
      !closes_an_order,
      fee_taken == 0,
    },
  }

  // Per-asset conservation: nothing guarded may end up anywhere else. Beacon
  // tokens are exempt (burned on cancel; the beacon script constrains them).
  let conserved = list.all(
    assets.flatten(assets.merge(allowed_out, assets.negate(guarded_in))),
    fn(entry) {
      let (pid, _name, qty) = entry
      pid == beacon_id || qty >= 0
    },
  )

  payout_cred_ok && withdrawals_ok && conserved && floors_ok && fee_ok
}

validator maker_stake_bound(
  adam_bot_pkh: VerificationKeyHash,
  client_owner_vkh: VerificationKeyHash,
  client_payout: Address,
  dapp_hash: ScriptHash,
  beacon_id: ScriptHash,
  min_asset1_price: LegacyRational,
  min_asset2_price: LegacyRational,
  // Phase 1 A. Appended LAST so every earlier parameter keeps its position:
  // `aiken blueprint apply` is positional and same-typed parameters swap
  // silently, so inserting anywhere else would re-order an audited ceremony.
  fee_address: Address,
  fee_bps: Int,
) {
  // Register-only stays open, so the credential can enter `withdrawals` and so a
  // mistaken deregistration is repairable by anyone for the 2 ADA deposit rather
  // than being a brick. Every other certificate is CLIENT-only: the bot has no
  // operational need for any of them (the withdraw-0 trick needs registration,
  // not delegation), and each one it could publish is either a theft or a brick
  // — deregistration pockets the deposit and freezes every resting order;
  // delegation diverts the staking yield and the governance weight, and the
  // first accrued reward makes every `+0` withdrawal in the stack — reprice,
  // cancel, and the client's own escape tooling — unbuildable.
  //
  // Vote delegation is left client-SIGNABLE rather than impossible, so a future
  // tightening that requires a DRep delegation to withdraw cannot brick this
  // credential.
  publish(_redeemer: Data, certificate: Certificate, self: Transaction) {
    when certificate is {
      RegisterCredential { .. } -> True
      _ -> list.has(self.extra_signatories, client_owner_vkh)
    }
  }

  withdraw(_redeemer: Data, account: Credential, self: Transaction) {
    or {
      list.has(self.extra_signatories, client_owner_vkh),
      and {
        list.has(self.extra_signatories, adam_bot_pkh),
        payout_bound(
          account,
          self,
          client_owner_vkh,
          client_payout,
          dapp_hash,
          beacon_id,
          min_asset1_price,
          min_asset2_price,
          fee_address,
          fee_bps,
        ),
      },
    }
  }

  // Mint/spend/vote/propose under this hash: client only. The bot never
  // needs these powers.
  else(ctx: ScriptContext) {
    list.has(ctx.transaction.extra_signatories, client_owner_vkh)
  }
}

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

const bot: VerificationKeyHash =
  #"01010101010101010101010101010101010101010101010101010101"

const client: VerificationKeyHash =
  #"02020202020202020202020202020202020202020202020202020202"

const other: VerificationKeyHash =
  #"03030303030303030303030303030303030303030303030303030303"

const dapp: ScriptHash =
  #"04040404040404040404040404040404040404040404040404040404"

const own_hash: ScriptHash =
  #"05050505050505050505050505050505050505050505050505050505"

const beacon: ScriptHash =
  #"06060606060606060606060606060606060606060606060606060606"

const tkn: PolicyId =
  #"07070707070707070707070707070707070707070707070707070707"

const foreign_stake: ScriptHash =
  #"08080808080808080808080808080808080808080808080808080808"

const fake_pid: PolicyId =
  #"09090909090909090909090909090909090909090909090909090909"

// A second cardano-swaps payment script — the one-way order form is the real
// instance of this — that a client's inventory could be *placed* at while
// wearing this same bound stake credential.
const foreign_dapp: ScriptHash =
  #"0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d"

const own_cred: Credential = Script(own_hash)

// Ceremony price floors used by the tests. valid_order_datum prices asset1 at
// 1/2 (bid 2 lovelace per token) and asset2 at 2/1 (ask 2 lovelace per token),
// so it sits exactly on both floors and every pre-existing continuation test
// keeps counting its outputs as guarded. The pair is non-crossed at the
// boundary (product exactly 1), which also pins the ceremony relation's
// inclusivity: turning `>=` into `>` reddens the whole continuation suite.
const min_a1: LegacyRational = LegacyRational { numerator: 1, denominator: 2 }

const min_a2: LegacyRational = LegacyRational { numerator: 2, denominator: 1 }

const zero_floor: LegacyRational =
  LegacyRational { numerator: 0, denominator: 1 }

// The pair applied to the preprod instance 87a61b9b…: a BID CEILING of
// 3 ADA/token against an ASK FLOOR of 2 ADA/token. Product 2/3 < 1, so a datum
// resting on both floors is bought at 2 and sold back at 3.
const crossed_a1: LegacyRational =
  LegacyRational { numerator: 1, denominator: 3_000_000 }

const crossed_a2: LegacyRational =
  LegacyRational { numerator: 2_000_000, denominator: 1 }

// An honest band around the same ~2.6 ADA mid: bid ceiling 2.5922, ask floor
// 2.6078. Product 2_607_800/2_592_200 > 1.
const honest_a1: LegacyRational =
  LegacyRational { numerator: 1, denominator: 2_592_200 }

const honest_a2: LegacyRational =
  LegacyRational { numerator: 2_607_800, denominator: 1 }

const order_addr: Address =
  Address {
    payment_credential: Script(dapp),
    stake_credential: Some(Inline(own_cred)),
  }

const fee_key: VerificationKeyHash =
  #"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

/// Where the operator fee lands. A ceremony parameter like every other bound:
/// the client's own applied script hash is what caps what may go here.
const fee_addr: Address =
  Address {
    payment_credential: VerificationKey(fee_key),
    stake_credential: None,
  }

/// 200 bps = 2%, the standard contracted rate.
const fee_bps: Int = 200

const payout_addr: Address =
  Address {
    payment_credential: VerificationKey(client),
    stake_credential: None,
  }

const bot_addr: Address =
  Address { payment_credential: VerificationKey(bot), stake_credential: None }

const other_addr: Address =
  Address { payment_credential: VerificationKey(other), stake_credential: None }

/// The order fixture as the RECORD. Every variant below is built from this by
/// field update, so none of them has to round-trip through `Data` and `expect`
/// the record back out — the fixtures state what they are instead of asserting it.
fn base_order_datum() -> LegacySwapDatum {
  LegacySwapDatum {
    beacon_id: beacon,
    pair_beacon: "PAIR",
    asset1_id: "",
    asset1_name: "",
    asset1_beacon: "A1",
    asset2_id: tkn,
    asset2_name: "TKN",
    asset2_beacon: "A2",
    asset1_price: LegacyRational { numerator: 1, denominator: 2 },
    asset2_price: LegacyRational { numerator: 2, denominator: 1 },
    prev_input: Some(
      LegacyOutputReference {
        transaction_id: LegacyTransactionId {
          hash: #"0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
        },
        output_index: 0,
      },
    ),
    expiration: None,
  }
}

fn valid_order_datum() -> Data {
  let data: Data = base_order_datum()
  data
}

fn wrong_beacon_datum() -> Data {
  let data: Data = LegacySwapDatum { ..base_order_datum(), beacon_id: tkn }
  data
}

// valid_order_datum repriced to arbitrary asset1/asset2 prices.
fn priced_datum(a1n: Int, a1d: Int, a2n: Int, a2d: Int) -> Data {
  let data: Data = LegacySwapDatum {
    ..base_order_datum(),
    asset1_price: LegacyRational { numerator: a1n, denominator: a1d },
    asset2_price: LegacyRational { numerator: a2n, denominator: a2d },
  }
  data
}

// The sibling instance's beacon policy. cardano-swaps parameterises the beacon
// minting policy by the order script it serves, so the one-way order form the
// same client's credential also sits on mints under a DIFFERENT policy id from
// the two-way `beacon_id` this ceremony exempts.
const foreign_beacon: PolicyId =
  #"0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e"

// 2 ADA min-ADA carve + 100 TKN inventory + the three pair beacons.
fn inventory() -> Value {
  assets.from_lovelace(2_000_000)
    |> assets.add(tkn, "TKN", 100)
    |> assets.add(beacon, "PAIR", 1)
    |> assets.add(beacon, "A1", 1)
    |> assets.add(beacon, "A2", 1)
}

// The same holding as `inventory`, but wearing the SIBLING order form's
// beacons: same client, same stake credential, a different beacon policy.
fn sibling_inventory() -> Value {
  assets.from_lovelace(2_000_000)
    |> assets.add(tkn, "TKN", 100)
    |> assets.add(foreign_beacon, "PAIR", 1)
    |> assets.add(foreign_beacon, "A1", 1)
    |> assets.add(foreign_beacon, "A2", 1)
}

fn oref(ix: Int) -> OutputReference {
  OutputReference {
    transaction_id: #"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
    output_index: ix,
  }
}

fn input_at(ix: Int, addr: Address, value: Value) -> Input {
  Input {
    output_reference: oref(ix),
    output: Output {
      address: addr,
      value,
      datum: InlineDatum(valid_order_datum()),
      reference_script: None,
    },
  }
}

fn out(addr: Address, value: Value) -> Output {
  Output { address: addr, value, datum: NoDatum, reference_script: None }
}

fn cont(value: Value, datum_data: Data) -> Output {
  Output {
    address: order_addr,
    value,
    datum: InlineDatum(datum_data),
    reference_script: None,
  }
}

/// The same transaction, closing its orders: cardano-swaps burns an order's
/// beacons to close it, so this is what a cancel looks like to the validator.
fn burning(t: Transaction, v: Value) -> Transaction {
  Transaction { ..t, mint: v }
}

fn burned_pair_beacon() -> Value {
  assets.from_asset(beacon, "PAIR", -1)
}

fn tx(
  inputs: List<Input>,
  outputs: List<Output>,
  withdrawals: Pairs<Credential, Int>,
  signers: List<VerificationKeyHash>,
) -> Transaction {
  Transaction {
    ..placeholder,
    inputs,
    outputs,
    withdrawals,
    extra_signatories: signers,
  }
}

// A ceremony other than the fixture one: any of the nine parameters may vary.
fn run_withdraw_with(
  payout: Address,
  dapp_h: ScriptHash,
  beacon_h: ScriptHash,
  a1: LegacyRational,
  a2: LegacyRational,
  t: Transaction,
) -> Bool {
  maker_stake_bound.withdraw(
    bot,
    client,
    payout,
    dapp_h,
    beacon_h,
    a1,
    a2,
    fee_addr,
    0,
    Void,
    own_cred,
    t,
  )
}

/// The A-ceremony harness: the standard bound plus a fee address and rate.
fn run_withdraw_fee(t: Transaction) -> Bool {
  run_withdraw_fee_bps(fee_bps, t)
}

fn run_withdraw_fee_bps(bps: Int, t: Transaction) -> Bool {
  maker_stake_bound.withdraw(
    bot,
    client,
    payout_addr,
    dapp,
    beacon,
    min_a1,
    min_a2,
    fee_addr,
    bps,
    Void,
    own_cred,
    t,
  )
}

fn run_withdraw(t: Transaction) -> Bool {
  run_withdraw_with(payout_addr, dapp, beacon, min_a1, min_a2, t)
}

// The two KEY slots and the payout varied together — the shape of a p1<->p2
// ceremony swap, which the operator can only make coherent by also naming its
// own address as the payout.
fn run_withdraw_keys(
  p1_bot: VerificationKeyHash,
  p2_client: VerificationKeyHash,
  payout: Address,
  t: Transaction,
) -> Bool {
  maker_stake_bound.withdraw(
    p1_bot,
    p2_client,
    payout,
    dapp,
    beacon,
    min_a1,
    min_a2,
    fee_addr,
    0,
    Void,
    own_cred,
    t,
  )
}

fn run_publish(
  certificate: Certificate,
  signers: List<VerificationKeyHash>,
) -> Bool {
  maker_stake_bound.publish(
    bot,
    client,
    payout_addr,
    dapp,
    beacon,
    min_a1,
    min_a2,
    fee_addr,
    0,
    Void,
    certificate,
    tx([], [], [], signers),
  )
}

// The order's whole non-beacon inventory routed to `dest`, beacons burned.
fn steal_to(dest: Address, signers: List<VerificationKeyHash>) -> Transaction {
  tx(
    [input_at(0, order_addr, inventory())],
    [out(dest, assets.from_lovelace(2_000_000) |> assets.add(tkn, "TKN", 100))],
    [Pair(own_cred, 0)],
    signers,
  )
}

// A cancel that steals: order inventory routed to the bot, client gets nothing.
fn theft_tx(signers: List<VerificationKeyHash>) -> Transaction {
  steal_to(bot_addr, signers)
}

// A clean cancel: full inventory (minus burned beacons) to `dest`, the signer
// pays the fee from its own input and takes only its own change.
fn cancel_to(
  dest: Address,
  withdrawals: Pairs<Credential, Int>,
  signers: List<VerificationKeyHash>,
) -> Transaction {
  tx(
    [
      input_at(0, order_addr, inventory()),
      input_at(1, bot_addr, assets.from_lovelace(5_000_000)),
    ],
    [
      out(dest, assets.from_lovelace(2_000_000) |> assets.add(tkn, "TKN", 100)),
      out(bot_addr, assets.from_lovelace(4_800_000)),
    ],
    withdrawals,
    signers,
  )
}

fn clean_cancel(withdrawals: Pairs<Credential, Int>) -> Transaction {
  cancel_to(payout_addr, withdrawals, [bot])
}

// ---------------------------------------------------------------------------
// Core authorization
// ---------------------------------------------------------------------------

// Client escape hatch: client-signed passes with NO value constraint.
test client_signed_arbitrary_passes() {
  run_withdraw(theft_tx([client]))
}

// Neither signer: rejected outright.
test neither_signer_rejected() {
  !run_withdraw(theft_tx([other]))
}

// Bot-signed cancel with everything to the client: passes. Beacons are
// burned (absent from outputs) — exempt from conservation.
test bot_cancel_all_to_client_passes() {
  run_withdraw(clean_cancel([Pair(own_cred, 0)]))
}

// Bot-signed theft: the exact tx the legacy maker_stake would allow.
test bot_theft_rejected() {
  !run_withdraw(theft_tx([bot]))
}

// Bot routes the token to itself and only ADA to the client.
test bot_token_to_foreign_rejected() {
  let t = tx(
    [input_at(0, order_addr, inventory())],
    [
      out(payout_addr, assets.from_lovelace(2_000_000)),
      out(bot_addr, assets.from_asset(tkn, "TKN", 100)),
    ],
    [Pair(own_cred, 0)],
    [bot],
  )
  !run_withdraw(t)
}

// Dust skim: client shorted by a single lovelace.
test bot_skims_one_lovelace_rejected() {
  let t = tx(
    [input_at(0, order_addr, inventory())],
    [
      out(
        payout_addr,
        assets.from_lovelace(1_999_999) |> assets.add(tkn, "TKN", 100),
      ),
      out(bot_addr, assets.from_lovelace(1)),
    ],
    [Pair(own_cred, 0)],
    [bot],
  )
  !run_withdraw(t)
}

// ---------------------------------------------------------------------------
// Reprice / continuation
// ---------------------------------------------------------------------------

// Straight reprice: full inventory continues at the order address.
test bot_reprice_continuation_passes() {
  let t = tx(
    [
      input_at(0, order_addr, inventory()),
      input_at(1, bot_addr, assets.from_lovelace(5_000_000)),
    ],
    [
      cont(inventory(), valid_order_datum()),
      out(bot_addr, assets.from_lovelace(4_800_000)),
    ],
    [Pair(own_cred, 0)],
    [bot],
  )
  run_withdraw(t)
}

// Multi-output split: one order split into two continuations, value conserved.
test bot_reprice_split_passes() {
  let cont1 = assets.from_lovelace(1_000_000)
    |> assets.add(tkn, "TKN", 50)
    |> assets.add(beacon, "PAIR", 1)
    |> assets.add(beacon, "A1", 1)
    |> assets.add(beacon, "A2", 1)
  let cont2 = assets.from_lovelace(1_000_000) |> assets.add(tkn, "TKN", 50)
  let t = tx(
    [input_at(0, order_addr, inventory())],
    [cont(cont1, valid_order_datum()), cont(cont2, valid_order_datum())],
    [Pair(own_cred, 0)],
    [bot],
  )
  run_withdraw(t)
}

// Consolidation frees one order's min-ADA carve: it must go to the client...
test consolidation_freed_min_ada_to_client_passes() {
  let t = tx(
    [
      input_at(0, order_addr, inventory()),
      input_at(
        1,
        order_addr,
        assets.from_lovelace(2_000_000) |> assets.add(beacon, "PAIR", 1),
      ),
    ],
    [
      cont(inventory(), valid_order_datum()),
      out(payout_addr, assets.from_lovelace(2_000_000)),
    ],
    [Pair(own_cred, 0)],
    [bot],
  )
  run_withdraw(t)
}

// ...and NOT to the bot.
test consolidation_freed_min_ada_to_bot_rejected() {
  let t = tx(
    [
      input_at(0, order_addr, inventory()),
      input_at(
        1,
        order_addr,
        assets.from_lovelace(2_000_000) |> assets.add(beacon, "PAIR", 1),
      ),
    ],
    [
      cont(inventory(), valid_order_datum()),
      out(bot_addr, assets.from_lovelace(2_000_000)),
    ],
    [Pair(own_cred, 0)],
    [bot],
  )
  !run_withdraw(t)
}

// Poisoned continuation datum (undecodable by the legacy dApp validator)
// would brick the UTxO for the client — not a valid continuation.
test continuation_undecodable_datum_rejected() {
  let poison: Data = Void
  let t = tx(
    [input_at(0, order_addr, inventory())],
    [cont(inventory(), poison)],
    [Pair(own_cred, 0)],
    [bot],
  )
  !run_withdraw(t)
}

// Continuation without an inline datum: same brick risk.
test continuation_no_datum_rejected() {
  let t = tx(
    [input_at(0, order_addr, inventory())],
    [out(order_addr, inventory())],
    [Pair(own_cred, 0)],
    [bot],
  )
  !run_withdraw(t)
}

// Continuation datum pointing at a bogus beacon policy.
test continuation_wrong_beacon_id_rejected() {
  let t = tx(
    [input_at(0, order_addr, inventory())],
    [cont(inventory(), wrong_beacon_datum())],
    [Pair(own_cred, 0)],
    [bot],
  )
  !run_withdraw(t)
}

// Fake continuation: bot-spendable payment credential wearing THIS stake
// credential. Must not count as staying guarded.
test fake_continuation_bot_payment_cred_rejected() {
  let fake_addr = Address {
    payment_credential: VerificationKey(bot),
    stake_credential: Some(Inline(own_cred)),
  }
  let t = tx(
    [input_at(0, order_addr, inventory())],
    [
      Output {
        address: fake_addr,
        value: inventory(),
        datum: InlineDatum(valid_order_datum()),
        reference_script: None,
      },
    ],
    [Pair(own_cred, 0)],
    [bot],
  )
  !run_withdraw(t)
}

// is_order_address's STAKE-credential equality is the only thing stopping the bot from migrating
// the client's whole inventory to a continuation at the same dApp payment script under a DIFFERENT
// stake credential — e.g. the deployment's own maker_stake, which authorises on the bot signature
// alone with no payout constraint. One output shape, two stake credentials, opposite verdicts:
// under the client's OWN credential it is a legal reprice; under a foreign one the value has left
// the conservation perimeter (guarded_in still counts the input, allowed_out no longer counts the
// output) and conserved fails. Neuter the stake conjunct and the foreign-stake drain validates.
test bot_continuation_to_foreign_stake_credential_rejected() {
  let migrate = fn(stake: Credential) {
    run_withdraw(
      tx(
        [input_at(0, order_addr, inventory())],
        [
          Output {
            address: Address {
              payment_credential: Script(dapp),
              stake_credential: Some(Inline(stake)),
            },
            value: inventory(),
            datum: InlineDatum(valid_order_datum()),
            reference_script: None,
          },
        ],
        [Pair(own_cred, 0)],
        [bot],
      ),
    )
  }
  and {
    // the deployment's own bot-signature-only maker_stake credential: the drain must be REJECTED
    !migrate(Script(foreign_stake)),
    // the byte-identical output under the client's OWN credential is a legal reprice: ACCEPTED
    migrate(own_cred),
  }
}

// ---------------------------------------------------------------------------
// Cross-instance double-satisfaction / withdrawal restriction
// ---------------------------------------------------------------------------

// A second script withdrawal (another client's bound instance, or the legacy
// maker_stake) in the same tx: structurally blocked.
test foreign_script_withdrawal_rejected() {
  !run_withdraw(
    clean_cancel([Pair(own_cred, 0), Pair(Script(foreign_stake), 0)]),
  )
}

// The beacon script's own withdraw-0 (UpdateSwaps) is whitelisted.
test beacon_script_withdrawal_allowed() {
  run_withdraw(clean_cancel([Pair(own_cred, 0), Pair(Script(beacon), 0)]))
}

// Ordinary verification-key reward withdrawals are harmless.
test vk_withdrawal_allowed() {
  run_withdraw(
    clean_cancel([Pair(own_cred, 0), Pair(VerificationKey(other), 0)]),
  )
}

// ---------------------------------------------------------------------------
// Reward routing
// ---------------------------------------------------------------------------

// Staking rewards withdrawn by this credential must reach the client.
test rewards_to_client_passes() {
  let t = tx(
    [input_at(0, bot_addr, assets.from_lovelace(5_000_000))],
    [
      out(payout_addr, assets.from_lovelace(5_000_000)),
      out(bot_addr, assets.from_lovelace(4_800_000)),
    ],
    [Pair(own_cred, 5_000_000)],
    [bot],
  )
  run_withdraw(t)
}

test rewards_to_bot_rejected() {
  let t = tx(
    [input_at(0, bot_addr, assets.from_lovelace(5_000_000))],
    [out(bot_addr, assets.from_lovelace(9_800_000))],
    [Pair(own_cred, 5_000_000)],
    [bot],
  )
  !run_withdraw(t)
}

// ---------------------------------------------------------------------------
// Payout output shape
// ---------------------------------------------------------------------------

// A datum-bearing output to the payout address does not count (datum
// poisoning must never satisfy the payout leg).
// ---- Phase 1 A: the fee leg is bounded by the client's own applied hash ----
// The whole point of A is that the fee stops being a promise enforced by our
// service and becomes an arithmetic bound consensus checks. These tests are the
// bound: what may be taken, what may not, and the ways an operator could try to
// take more without the conservation check noticing.

/// The honest shape: the position stays open, the client takes the ADA it
/// realized at their payout, and the operator takes fee_bps of that.
///
/// This test used to spend a bare 100 ADA with no beacons and no continuation —
/// a client's deposit being handed back — and call that a realization. It passed,
/// and it pinned the wrong meaning: nothing in the suite distinguished principal
/// from profit, because this was the only shape anyone wrote.
test fee_leg_within_the_bound_is_allowed() {
  let t = tx(
    [
      input_at(
        0,
        order_addr,
        assets.merge(inventory(), assets.from_lovelace(100_000_000)),
      ),
    ],
    [
      cont(inventory(), valid_order_datum()),
      Output {
        address: payout_addr,
        value: assets.from_lovelace(98_000_000),
        datum: NoDatum,
        reference_script: None,
      },
      Output {
        address: fee_addr,
        value: assets.from_lovelace(2_000_000),
        datum: NoDatum,
        reference_script: None,
      },
    ],
    [Pair(own_cred, 0)],
    [bot],
  )
  run_withdraw_fee(t)
}

/// deci's rule, second reading: the operator is paid for RUNNING the position,
/// and staking yield is not something the operator ran. It is produced by the
/// client's own delegation of their own credential — a delegation `publish`
/// only ever lets the CLIENT make.
///
/// Without this the harvest is billable: withdraw R from the credential, route
/// it to `client_payout`, and `payout_realized` counts it, so `fee_taken` is
/// allowed fee_bps of the client's yield. No order is spent and no beacon is
/// burned, so the `closes_an_order` clause never fires; the bot's signature is
/// the only one needed. Bounded (0.2% of yield at the live fee_bps) and the
/// client can always harvest fee-free themselves — but it is a fee on money the
/// operator did not earn, and the ceremony's own copy says otherwise.
test fee_on_harvested_yield_is_rejected() {
  let t = tx(
    [input_at(0, bot_addr, assets.from_lovelace(5_000_000))],
    [
      Output {
        address: payout_addr,
        value: assets.from_lovelace(98_000_000),
        datum: NoDatum,
        reference_script: None,
      },
      Output {
        address: fee_addr,
        value: assets.from_lovelace(2_000_000),
        datum: NoDatum,
        reference_script: None,
      },
    ],
    [Pair(own_cred, 100_000_000)],
    [bot],
  )
  !run_withdraw_fee(t)
}

/// ...and the client still gets their yield, in full, on the same shape without
/// the fee leg. Removing the basis must not remove the harvest.
test harvesting_yield_without_a_fee_is_allowed() {
  let t = tx(
    [input_at(0, bot_addr, assets.from_lovelace(5_000_000))],
    [
      Output {
        address: payout_addr,
        value: assets.from_lovelace(100_000_000),
        datum: NoDatum,
        reference_script: None,
      },
    ],
    [Pair(own_cred, 100_000_000)],
    [bot],
  )
  run_withdraw_fee(t)
}

/// The precise reading, not the blunt one: a transaction that harvests AND
/// realizes a genuine trade may still be paid on the TRADE. Only the yield
/// leaves the basis. A blunt "no fee whenever rewards move" would push the
/// keeper into extra transactions and extra gas for no gain to the client.
/// 89 ADA out, of which 40 is withdrawn yield -> the basis is 49, and at the
/// fixture's 200 bps the ceiling is basis/49 = 1_000_000 exactly.
test fee_on_the_trade_half_of_a_harvest_is_allowed() {
  let t = tx(
    [input_at(0, bot_addr, assets.from_lovelace(5_000_000))],
    [
      Output {
        address: payout_addr,
        value: assets.from_lovelace(89_000_000),
        datum: NoDatum,
        reference_script: None,
      },
      Output {
        address: fee_addr,
        value: assets.from_lovelace(1_000_000),
        datum: NoDatum,
        reference_script: None,
      },
    ],
    [Pair(own_cred, 40_000_000)],
    [bot],
  )
  run_withdraw_fee(t)
}

/// ...and one lovelace past that ceiling is refused, so the subtraction is a
/// real bound and not a decoration.
test fee_over_the_trade_half_of_a_harvest_is_rejected() {
  let t = tx(
    [input_at(0, bot_addr, assets.from_lovelace(5_000_000))],
    [
      Output {
        address: payout_addr,
        value: assets.from_lovelace(89_000_000),
        datum: NoDatum,
        reference_script: None,
      },
      Output {
        address: fee_addr,
        value: assets.from_lovelace(1_000_001),
        datum: NoDatum,
        reference_script: None,
      },
    ],
    [Pair(own_cred, 40_000_000)],
    [bot],
  )
  !run_withdraw_fee(t)
}

/// deci's rule. The same money, moving the same way, on a transaction that
/// CLOSES the order — which is the transaction a client's untouched deposit
/// comes back on.
test fee_on_a_cancel_is_rejected() {
  let t = tx(
    [input_at(0, order_addr, assets.from_lovelace(100_000_000))],
    [
      Output {
        address: payout_addr,
        value: assets.from_lovelace(98_000_000),
        datum: NoDatum,
        reference_script: None,
      },
      Output {
        address: fee_addr,
        value: assets.from_lovelace(2_000_000),
        datum: NoDatum,
        reference_script: None,
      },
    ],
    [Pair(own_cred, 0)],
    [bot],
  )
  !run_withdraw_fee(burning(t, burned_pair_beacon()))
}

/// And the client still gets everything back — the cancel itself is untouched,
/// only the fee on it is refused.
test a_cancel_taking_no_fee_is_allowed() {
  let t = tx(
    [input_at(0, order_addr, assets.from_lovelace(100_000_000))],
    [
      Output {
        address: payout_addr,
        value: assets.from_lovelace(100_000_000),
        datum: NoDatum,
        reference_script: None,
      },
    ],
    [Pair(own_cred, 0)],
    [bot],
  )
  run_withdraw_fee(burning(t, burned_pair_beacon()))
}

/// Burning a beacon of ANOTHER policy is not this book closing, so it must not
/// silently disable the fee — otherwise the rule would be trivially avoidable in
/// one direction and trivially triggerable in the other.
test a_foreign_burn_does_not_disable_the_fee() {
  let t = tx(
    [
      input_at(
        0,
        order_addr,
        assets.merge(inventory(), assets.from_lovelace(100_000_000)),
      ),
    ],
    [
      cont(inventory(), valid_order_datum()),
      Output {
        address: payout_addr,
        value: assets.from_lovelace(98_000_000),
        datum: NoDatum,
        reference_script: None,
      },
      Output {
        address: fee_addr,
        value: assets.from_lovelace(2_000_000),
        datum: NoDatum,
        reference_script: None,
      },
    ],
    [Pair(own_cred, 0)],
    [bot],
  )
  run_withdraw_fee(burning(t, assets.from_asset(foreign_beacon, "PAIR", -1)))
}

/// MINTING this ceremony's beacon is a create, not a close, so it must not trip
/// the rule either — the sign is what carries the meaning.
test a_beacon_mint_does_not_disable_the_fee() {
  let t = tx(
    [
      input_at(
        0,
        order_addr,
        assets.merge(inventory(), assets.from_lovelace(100_000_000)),
      ),
    ],
    [
      cont(inventory(), valid_order_datum()),
      Output {
        address: payout_addr,
        value: assets.from_lovelace(98_000_000),
        datum: NoDatum,
        reference_script: None,
      },
      Output {
        address: fee_addr,
        value: assets.from_lovelace(2_000_000),
        datum: NoDatum,
        reference_script: None,
      },
    ],
    [Pair(own_cred, 0)],
    [bot],
  )
  run_withdraw_fee(burning(t, assets.from_asset(beacon, "A1", 1)))
}

/// One lovelace over the bound. The bound is arithmetic, not approximate.
test fee_leg_one_lovelace_over_the_bound_is_rejected() {
  let t = tx(
    [input_at(0, order_addr, assets.from_lovelace(100_000_000))],
    [
      Output {
        address: payout_addr,
        value: assets.from_lovelace(97_999_999),
        datum: NoDatum,
        reference_script: None,
      },
      Output {
        address: fee_addr,
        value: assets.from_lovelace(2_000_001),
        datum: NoDatum,
        reference_script: None,
      },
    ],
    [Pair(own_cred, 0)],
    [bot],
  )
  !run_withdraw_fee(t)
}

/// A fee with no realized payout is a drain wearing a fee's clothes: the bound is
/// a proportion OF the client's realization, so zero realized means zero fee.
test fee_without_a_payout_is_rejected() {
  let t = tx(
    [input_at(0, order_addr, assets.from_lovelace(100_000_000))],
    [
      Output {
        address: fee_addr,
        value: assets.from_lovelace(2_000_000),
        datum: NoDatum,
        reference_script: None,
      },
      Output {
        address: order_addr,
        value: assets.from_lovelace(98_000_000),
        datum: InlineDatum(valid_order_datum()),
        reference_script: None,
      },
    ],
    [Pair(own_cred, 0)],
    [bot],
  )
  !run_withdraw_fee(t)
}

/// Splitting the fee across several outputs must not multiply the allowance.
test fee_split_across_outputs_is_summed_against_the_bound() {
  let t = tx(
    [input_at(0, order_addr, assets.from_lovelace(100_000_000))],
    [
      Output {
        address: payout_addr,
        value: assets.from_lovelace(98_000_000),
        datum: NoDatum,
        reference_script: None,
      },
      Output {
        address: fee_addr,
        value: assets.from_lovelace(1_500_000),
        datum: NoDatum,
        reference_script: None,
      },
      Output {
        address: fee_addr,
        value: assets.from_lovelace(1_500_000),
        datum: NoDatum,
        reference_script: None,
      },
    ],
    [Pair(own_cred, 0)],
    [bot],
  )
  !run_withdraw_fee(t)
}

/// The fee is denominated in ADA. Letting tokens ride the fee leg would let the
/// operator take a client's inventory and call it a fee.
/// AUDIT PROBE: a fee leg carrying ONLY tokens and no lovelace.
test probe_token_only_fee_leg() {
  let t = tx(
    [input_at(0, order_addr, inventory())],
    [
      Output {
        address: payout_addr,
        value: assets.from_lovelace(2_000_000),
        datum: NoDatum,
        reference_script: None,
      },
      Output {
        address: fee_addr,
        value: assets.from_asset(tkn, "TKN", 100),
        datum: NoDatum,
        reference_script: None,
      },
    ],
    [Pair(own_cred, 0)],
    [bot],
  )
  !run_withdraw_fee(t)
}

test fee_leg_carrying_tokens_is_rejected() {
  let t = tx(
    [input_at(0, order_addr, inventory())],
    [
      Output {
        address: payout_addr,
        value: assets.from_lovelace(98_000_000),
        datum: NoDatum,
        reference_script: None,
      },
      Output {
        address: fee_addr,
        value: assets.from_lovelace(2_000_000) |> assets.add(tkn, "TKN", 100),
        datum: NoDatum,
        reference_script: None,
      },
    ],
    [Pair(own_cred, 0)],
    [bot],
  )
  !run_withdraw_fee(t)
}

/// A datum or reference script on the fee leg is a different output shape than
/// the one the bound reasons about; refuse it rather than guess.
test fee_leg_with_a_datum_is_rejected() {
  let t = tx(
    [input_at(0, order_addr, assets.from_lovelace(100_000_000))],
    [
      Output {
        address: payout_addr,
        value: assets.from_lovelace(98_000_000),
        datum: NoDatum,
        reference_script: None,
      },
      Output {
        address: fee_addr,
        value: assets.from_lovelace(2_000_000),
        datum: InlineDatum(valid_order_datum()),
        reference_script: None,
      },
    ],
    [Pair(own_cred, 0)],
    [bot],
  )
  !run_withdraw_fee(t)
}

/// Taking no fee is always legal — the bound is a ceiling, not a quota.
test taking_no_fee_is_allowed() {
  let t = tx(
    [input_at(0, order_addr, assets.from_lovelace(100_000_000))],
    [
      Output {
        address: payout_addr,
        value: assets.from_lovelace(100_000_000),
        datum: NoDatum,
        reference_script: None,
      },
    ],
    [Pair(own_cred, 0)],
    [bot],
  )
  run_withdraw_fee(t)
}

/// A ceremony that names a fee rate above the contracted maximum is refused at
/// the validator, so a mis-parameterised instance cannot over-charge even if a
/// client signs it by mistake.
///
/// The transaction must CONSERVE, or conservation rejects it at every rate and the
/// assertion carries no information — which is what the first version of this test
/// did. It is paired with the 500 bps case below so the two differ only in the
/// number under test.
fn ceiling_probe_tx() -> Transaction {
  tx(
    [input_at(0, order_addr, assets.from_lovelace(100_000_000))],
    [
      Output {
        address: payout_addr,
        value: assets.from_lovelace(95_000_000),
        datum: NoDatum,
        reference_script: None,
      },
      Output {
        address: fee_addr,
        value: assets.from_lovelace(5_000_000),
        datum: NoDatum,
        reference_script: None,
      },
    ],
    [Pair(own_cred, 0)],
    [bot],
  )
}

test a_fee_rate_over_the_ceiling_fails_the_instance() {
  !run_withdraw_fee_bps(501, ceiling_probe_tx())
}

test the_ceiling_rate_itself_is_allowed() {
  run_withdraw_fee_bps(500, ceiling_probe_tx())
}

/// A negative rate. The inequality alone already rejects this whenever a fee is
/// actually taken, so the sign guard only bites on a PURE REPRICE where both
/// sides are zero and `0 <= 0` holds at any rate. Testing it on a fee-taking
/// transaction would pass without the guard and prove nothing, so this is the
/// reprice shape — a nonsensical ceremony parameter should make the instance
/// inert, the same argument as the ceiling.
test a_negative_fee_rate_fails_the_instance_even_on_a_pure_reprice() {
  let t = tx(
    [input_at(0, order_addr, assets.from_lovelace(100_000_000))],
    [
      Output {
        address: order_addr,
        value: assets.from_lovelace(100_000_000),
        datum: InlineDatum(valid_order_datum()),
        reference_script: None,
      },
    ],
    [Pair(own_cred, 0)],
    [bot],
  )
  !run_withdraw_fee_bps(-1, t)
}

/// The same reprice at a legal rate must still work, so the test above is
/// discriminating rather than rejecting the shape itself.
test a_pure_reprice_at_a_legal_rate_still_works() {
  let t = tx(
    [input_at(0, order_addr, assets.from_lovelace(100_000_000))],
    [
      Output {
        address: order_addr,
        value: assets.from_lovelace(100_000_000),
        datum: InlineDatum(valid_order_datum()),
        reference_script: None,
      },
    ],
    [Pair(own_cred, 0)],
    [bot],
  )
  run_withdraw_fee(t)
}

/// A reference script on the fee leg is a different output shape than the bound
/// reasons about. Asserted separately from the datum, because one test varying
/// only the datum leaves this clause uncovered.
test fee_leg_with_a_reference_script_is_rejected() {
  let t = tx(
    [input_at(0, order_addr, assets.from_lovelace(100_000_000))],
    [
      Output {
        address: payout_addr,
        value: assets.from_lovelace(98_000_000),
        datum: NoDatum,
        reference_script: None,
      },
      Output {
        address: fee_addr,
        value: assets.from_lovelace(2_000_000),
        datum: NoDatum,
        reference_script: Some(dapp),
      },
    ],
    [Pair(own_cred, 0)],
    [bot],
  )
  !run_withdraw_fee(t)
}

/// The client's escape hatch bypasses the fee bound entirely: recovery must stay
/// open even when the operator is the thing being escaped from.
///
/// Paired with its bot-signed control so it DISCRIMINATES. The earlier version
/// survived fee_ok being forced FALSE — the client branch short-circuits before
/// the bound is reached — so it exercised no fee logic and was named for
/// something it did not test.
fn escape_probe_tx(signer: VerificationKeyHash) -> Transaction {
  tx(
    [input_at(0, order_addr, assets.from_lovelace(100_000_000))],
    [
      Output {
        address: payout_addr,
        value: assets.from_lovelace(1_000_000),
        datum: NoDatum,
        reference_script: None,
      },
      Output {
        address: fee_addr,
        value: assets.from_lovelace(99_000_000),
        datum: NoDatum,
        reference_script: None,
      },
    ],
    [Pair(own_cred, 0)],
    [signer],
  )
}

test the_escape_hatch_is_not_subject_to_the_fee_bound() {
  run_withdraw_fee(escape_probe_tx(client))
}

test the_same_shape_bot_signed_is_rejected_by_the_bound() {
  !run_withdraw_fee(escape_probe_tx(bot))
}

test payout_with_datum_rejected() {
  let t = tx(
    [input_at(0, order_addr, inventory())],
    [
      Output {
        address: payout_addr,
        value: assets.from_lovelace(2_000_000) |> assets.add(tkn, "TKN", 100),
        datum: InlineDatum(valid_order_datum()),
        reference_script: None,
      },
    ],
    [Pair(own_cred, 0)],
    [bot],
  )
  !run_withdraw(t)
}

// Right payment credential, wrong full address (hijacked stake part).
test payout_wrong_stake_cred_rejected() {
  let hijacked = Address {
    payment_credential: VerificationKey(client),
    stake_credential: Some(Inline(VerificationKey(bot))),
  }
  let t = tx(
    [input_at(0, order_addr, inventory())],
    [
      out(
        hijacked,
        assets.from_lovelace(2_000_000) |> assets.add(tkn, "TKN", 100),
      ),
    ],
    [Pair(own_cred, 0)],
    [bot],
  )
  !run_withdraw(t)
}

// Minting a lookalike token to the client cannot cover taking the real one.
test mint_cover_rejected() {
  let t = tx(
    [input_at(0, order_addr, inventory())],
    [
      out(
        payout_addr,
        assets.from_lovelace(2_000_000) |> assets.add(fake_pid, "TKN", 100),
      ),
      out(bot_addr, assets.from_asset(tkn, "TKN", 100)),
    ],
    [Pair(own_cred, 0)],
    [bot],
  )
  !run_withdraw(t)
}

// ---------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------

const pool: VerificationKeyHash =
  #"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"

const stake_delegation: Certificate =
  DelegateCredential(own_cred, DelegateBlockProduction(pool))

const vote_delegation: Certificate =
  DelegateCredential(own_cred, DelegateVote(AlwaysAbstain))

const register_and_delegate: Certificate =
  RegisterAndDelegateCredential(
    own_cred,
    DelegateBlockProduction(pool),
    2_000_000,
  )

// Registration stays open so a mistaken deregistration is repairable by anyone
// for the 2 ADA deposit, and so the credential can enter `tx.withdrawals`.
test registration_without_sig_passes() {
  run_publish(RegisterCredential(own_cred, Never), [])
}

test deregistration_without_sig_rejected() {
  !run_publish(UnregisterCredential(own_cred, Never), [])
}

test deregistration_client_signed_passes() {
  run_publish(UnregisterCredential(own_cred, Never), [client])
}

// The bot alone must NOT be able to deregister the client's stake credential
// and pocket the ~2 ADA deposit refund.
test deregistration_bot_signed_rejected() {
  !run_publish(UnregisterCredential(own_cred, Never), [bot])
}

// Delegation diverts the client's staking yield to a pool the operator picks —
// and, because every builder in the stack withdraws `+0`, the first accrued
// reward makes every reprice, cancel and client escape unbuildable. The bot has
// no operational need for it: the withdraw-0 trick needs registration only.
test stake_delegation_bot_signed_rejected() {
  !run_publish(stake_delegation, [bot])
}

test stake_delegation_client_signed_passes() {
  run_publish(stake_delegation, [client])
}

// Vote delegation is left client-SIGNABLE rather than impossible, so a future
// `ConwayWdrlNotDelegatedToDRep` tightening cannot brick the credential.
test vote_delegation_bot_signed_rejected() {
  !run_publish(vote_delegation, [bot])
}

test vote_delegation_client_signed_passes() {
  run_publish(vote_delegation, [client])
}

// The combined certificate is the same authority by another name.
test register_and_delegate_bot_signed_rejected() {
  !run_publish(register_and_delegate, [bot])
}

test register_and_delegate_client_signed_passes() {
  run_publish(register_and_delegate, [client])
}

// ---------------------------------------------------------------------------
// Finding 1: delegated-price-authority floor (the drain)
// ---------------------------------------------------------------------------

// Bot reprices the ASK to dust (asset2_price 1/1_000_000, far below the 1/1
// floor) while parking full inventory at the order address. The continuation
// no longer counts as guarded, so conservation fails and the reprice is
// rejected — a colluding filler can never buy the token side for ~1 lovelace.
test bot_reprice_dust_ask_rejected() {
  let t = tx(
    [input_at(0, order_addr, inventory())],
    [cont(inventory(), priced_datum(1, 2, 1, 1_000_000))],
    [Pair(own_cred, 0)],
    [bot],
  )
  !run_withdraw(t)
}

// Bot reprices the BID to dust (asset1_price 1/1_000_000, below the 1/4
// floor): the ADA side would drain for near-zero token. Rejected.
test bot_reprice_dust_bid_rejected() {
  let t = tx(
    [input_at(0, order_addr, inventory())],
    [cont(inventory(), priced_datum(1, 1_000_000, 2, 1))],
    [Pair(own_cred, 0)],
    [bot],
  )
  !run_withdraw(t)
}

// Bot reprices EXACTLY to both floors of a NON-CROSSED band (bid 2 lovelace per
// token, ask 2 lovelace per token): >= is inclusive, the continuation counts as
// guarded, conservation holds. Passes.
test bot_reprice_at_floor_passes() {
  let t = tx(
    [input_at(0, order_addr, inventory())],
    [cont(inventory(), priced_datum(1, 2, 2, 1))],
    [Pair(own_cred, 0)],
    [bot],
  )
  run_withdraw(t)
}

// A bid BETTER than the ceiling and an ask BETTER than the floor — both
// favourable to the client — stay inside the band.
test bot_reprice_inside_band_passes() {
  let t = tx(
    [input_at(0, order_addr, inventory())],
    [cont(inventory(), priced_datum(1, 1, 3, 1))],
    [Pair(own_cred, 0)],
    [bot],
  )
  run_withdraw(t)
}

// Escape hatch: the client may reprice to any dust price they choose — the
// floors only bind the bot path.
test client_dust_reprice_passes() {
  let t = tx(
    [input_at(0, order_addr, inventory())],
    [cont(inventory(), priced_datum(1, 1_000_000, 1, 1_000_000))],
    [Pair(own_cred, 0)],
    [client],
  )
  run_withdraw(t)
}

// ---------------------------------------------------------------------------
// Floor self-containment: the sign guard and the ceremony floors themselves
// ---------------------------------------------------------------------------

// A negative denominator flips the cross-multiplication's direction, so a
// crafted continuation datum could slip a dust ask past the floor if the gate
// trusted the dApp validator to reject non-positive rationals. The gate must
// reject them itself.
test continuation_negative_ask_denominator_rejected() {
  let t = tx(
    [input_at(0, order_addr, inventory())],
    [cont(inventory(), priced_datum(1, 2, 1, -1_000_000))],
    [Pair(own_cred, 0)],
    [bot],
  )
  !run_withdraw(t)
}

test continuation_negative_bid_denominator_rejected() {
  let t = tx(
    [input_at(0, order_addr, inventory())],
    [cont(inventory(), priced_datum(1, -1_000_000, 2, 1))],
    [Pair(own_cred, 0)],
    [bot],
  )
  !run_withdraw(t)
}

// A clean bot reprice — the shape every keeper round emits. Used to judge a
// CEREMONY rather than a transaction: if this fails, the bot path is closed.
fn honest_bot_reprice() -> Transaction {
  tx(
    [
      input_at(0, order_addr, inventory()),
      input_at(1, bot_addr, assets.from_lovelace(5_000_000)),
    ],
    [
      cont(inventory(), valid_order_datum()),
      out(bot_addr, assets.from_lovelace(4_800_000)),
    ],
    [Pair(own_cred, 0)],
    [bot],
  )
}

// A ceremony that zeroes a floor disables the dust-reprice protection and
// restores the drain, so the bot path fails closed under non-positive floors...
test zero_floor_ceremony_bot_rejected() {
  !run_withdraw_with(
    payout_addr,
    dapp,
    beacon,
    zero_floor,
    zero_floor,
    honest_bot_reprice(),
  )
}

// ...while the client escape hatch stays available to recover the funds.
test zero_floor_ceremony_client_escape_passes() {
  run_withdraw_with(
    payout_addr,
    dapp,
    beacon,
    zero_floor,
    zero_floor,
    theft_tx([client]),
  )
}

// ---------------------------------------------------------------------------
// B2: the ceremony relation — the ask floor must sit at or above the bid ceiling
//
// min_asset1_price is token-per-lovelace, so it bounds the bid from ABOVE:
// asset1_price >= min_asset1_price means the client never pays more than
// 1/min_asset1_price lovelace for a token. min_asset2_price is lovelace-per-
// token, so it bounds the ask from BELOW. Nothing related the two, so a
// ceremony could hand the bot a band whose worst legal bid is above its worst
// legal ask — and a filler then buys at the ask and sells straight back at the
// bid. The relation is a CEREMONY property, not a per-datum one: two quotes that
// are each individually non-crossed extract the same value across two reprices,
// or across two of the client's UTxOs in one transaction.
// ---------------------------------------------------------------------------

// A bot reprice to an arbitrary quote, judged under an arbitrary ceremony band.
fn bot_reprice_at(a1n: Int, a1d: Int, a2n: Int, a2d: Int) -> Transaction {
  tx(
    [input_at(0, order_addr, inventory())],
    [cont(inventory(), priced_datum(a1n, a1d, a2n, a2d))],
    [Pair(own_cred, 0)],
    [bot],
  )
}

// The pair actually applied to preprod, with the datum resting on BOTH of its
// floors — so every per-leg check is satisfied and only the ceremony relation
// can see the problem. This is the exact quote a filler round-trips for
// +1 ADA/token: buy the token at the 2.0 ask, sell it back at the 3.0 bid.
test crossed_ceremony_bot_rejected() {
  !run_withdraw_with(
    payout_addr,
    dapp,
    beacon,
    crossed_a1,
    crossed_a2,
    bot_reprice_at(1, 3_000_000, 2_000_000, 1),
  )
}

// The honest band's own at-the-floor quote, by contrast, is accepted. Same
// shape, same code path, opposite verdict: this is the empirical proof that the
// inequality points the right way.
test honest_ceremony_at_floor_bot_passes() {
  run_withdraw_with(
    payout_addr,
    dapp,
    beacon,
    honest_a1,
    honest_a2,
    bot_reprice_at(1, 2_592_200, 2_607_800, 1),
  )
}

// ...and, exactly as with a zeroed floor, the client's escape hatch is
// untouched, so a crossed ceremony strands nothing.
test crossed_ceremony_client_escape_passes() {
  run_withdraw_with(
    payout_addr,
    dapp,
    beacon,
    crossed_a1,
    crossed_a2,
    theft_tx([client]),
  )
}

// The same two floors read in the inverted direction — product <= 1 instead of
// >= 1 — would accept the crossed pair and reject the honest one. ONE quote,
// judged under each band, so the direction of the relation is the only thing
// deciding which way round the two answers come out: inverting it reddens both
// conjuncts, deleting it reddens the first.
//
// It has to run the validator to say that. An earlier version recomputed the
// product on the fixture constants instead, and stayed green both when the
// relation was inverted and when it was deleted outright.
test ceremony_relation_direction_is_not_inverted() {
  let quote = bot_reprice_at(1, 2_592_200, 2_607_800, 1)
  and {
    !run_withdraw_with(payout_addr, dapp, beacon, crossed_a1, crossed_a2, quote),
    run_withdraw_with(payout_addr, dapp, beacon, honest_a1, honest_a2, quote),
  }
}

// `floors_ok`'s POSITIVITY conjuncts, which nothing else reaches. The crossing
// relation is cross-multiplied, so a pair with BOTH parts negative satisfies it
// — (-1)(-2) >= (-2)(-1) is 2 >= 2 — and the negative denominators then flip
// every `rational_geq` judged against them, so a dust quote reads as sitting
// above both floors. `zero_floor_ceremony_bot_rejected` cannot cover this: a
// zero floor fails the crossing relation first, so positivity is never the
// reason anything fails there.
//
// This BOTH-negative fixture only reddens when BOTH `rational_positive(min_*)`
// lines are dropped: whichever survives catches its own negative floor. Each
// line individually is covered by the SINGLE-SIDED tests below, where one floor
// is honest and only the other's positivity check stands between a dust quote
// and a drain.
const negative_a1: LegacyRational =
  LegacyRational { numerator: -1, denominator: -2 }

const negative_a2: LegacyRational =
  LegacyRational { numerator: -2, denominator: -1 }

test negatively_signed_ceremony_floors_bot_rejected() {
  !run_withdraw_with(
    payout_addr,
    dapp,
    beacon,
    negative_a1,
    negative_a2,
    // one lovelace per token base unit on both legs: dust under any real band
    bot_reprice_at(1, 1_000_000, 1, 1_000_000),
  )
}

// A LONE negative bid ceiling (min_asset1_price), with an honest ask floor. The
// pair still clears the crossing relation — (-1)(2_500_000) >= (-2_600_000)(1)
// is -2_500_000 >= -2_600_000 — and the negative denominator inverts
// rational_geq on the BID leg, so a dust bid (1 token per 1e9 lovelace, draining
// the client's ADA for ~0 token) reads as in-band. Only
// rational_positive(min_asset1_price) rejects it: drop that ONE line and this
// reddens, drop the other and it does not.
const lone_negative_a1: LegacyRational =
  LegacyRational { numerator: -1, denominator: -2_600_000 }

const honest_ask_floor: LegacyRational =
  LegacyRational { numerator: 2_500_000, denominator: 1 }

test negative_min_asset1_price_floor_bot_rejected() {
  !run_withdraw_with(
    payout_addr,
    dapp,
    beacon,
    lone_negative_a1,
    honest_ask_floor,
    bot_reprice_at(1, 1_000_000_000, 2_500_000, 1),
  )
}

// The mirror: a LONE negative ask floor (min_asset2_price), honest bid ceiling.
// Crossing holds — (1)(-2_700_000) >= (2_700_000)(-1) is -2_700_000 >= -2_700_000
// — and the negative denominator inverts rational_geq on the ASK leg, so a dust
// ask (1 lovelace per 1e9 token base units, draining the client's TOKEN for ~0
// ADA) reads as in-band. Only rational_positive(min_asset2_price) rejects it.
const honest_bid_ceiling: LegacyRational =
  LegacyRational { numerator: 1, denominator: 2_700_000 }

const lone_negative_a2: LegacyRational =
  LegacyRational { numerator: -2_700_000, denominator: -1 }

test negative_min_asset2_price_floor_bot_rejected() {
  !run_withdraw_with(
    payout_addr,
    dapp,
    beacon,
    honest_bid_ceiling,
    lone_negative_a2,
    bot_reprice_at(1, 2_600_000, 1, 1_000_000_000),
  )
}

// ...while the client escape hatch still recovers the inventory from one.
test negatively_signed_ceremony_client_escape_passes() {
  run_withdraw_with(
    payout_addr,
    dapp,
    beacon,
    negative_a1,
    negative_a2,
    theft_tx([client]),
  )
}

// The probe-proven bypass of a per-datum `ask >= bid` conjunct: two sequential
// reprices, each with ZERO spread and therefore each individually non-crossed
// (bid = ask = 3.0 ADA, then bid = ask = 2.0 ADA), extract the same 1 ADA per
// token for one extra reprice fee. A stateless per-datum predicate is blind to
// it. The ceremony relation is not: under a non-crossed band the first leg
// breaches the bid ceiling and the second breaches the ask floor, so NEITHER
// reprice can be written in the first place.
test noncrossed_band_blocks_sequential_reprice_bypass() {
  let leg = fn(a1n, a1d, a2n, a2d) {
    run_withdraw_with(
      payout_addr,
      dapp,
      beacon,
      honest_a1,
      honest_a2,
      bot_reprice_at(a1n, a1d, a2n, a2d),
    )
  }
  and {
    // step 1: bid = ask = 3.0 ADA — bid above the 2.5922 ceiling
    !leg(1, 3_000_000, 3_000_000, 1),
    // step 2: bid = ask = 2.0 ADA — ask below the 2.6078 floor
    !leg(1, 2_000_000, 2_000_000, 1),
  }
}

// ---------------------------------------------------------------------------
// THE CEREMONY FLOORS CARRY NO ASSET. The bot writes the datum that says which
// pair the two rationals price, and nothing here reads it back.
//
// `min_asset1_price` and `min_asset2_price` are bare rationals. The client
// signed them meaning "0.09 ADA per NIGHT". A datum declaring the SAME numbers
// against a token the bot minted for nothing means "0.09 ADA per JUNK", clears
// both floors identically, and conserves every asset — the value does not move
// in this transaction at all. The theft is a later, permissionless TAKER fill
// that never invokes this validator, exactly as in the ladder drain.
//
// Junk pair: the SAME asset1 (ada) and a worthless asset2, so both floors are
// compared against numbers that are no longer about the client's token.
const junk: PolicyId =
  #"0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f"

fn repaired_datum() -> Data {
  let data: Data = LegacySwapDatum {
    ..base_order_datum(),
    asset2_id: junk,
    asset2_name: "JUNK",
    // The beacon NAMES the bot declares for the new pair. cardano-swaps binds
    // these to the asset ids; this validator never looks at them.
    pair_beacon: "JUNKPAIR",
    asset2_beacon: "JUNKA2",
    // Quoted exactly ON both ceremony floors — the honest band, untouched.
    asset1_price: honest_a1,
    asset2_price: honest_a2,
  }
  data
}

// The bot re-pairs the client's order onto a worthless asset, quoting at the
// client's own floors, conserving every asset. If this validates, the sentence
// "the bot can never quote outside the band you set" is false: the band is
// still enforced, and it is no longer a band on the client's token.
test bot_repair_to_foreign_pair_rejected() {
  !run_withdraw_with(
    payout_addr,
    dapp,
    beacon,
    honest_a1,
    honest_a2,
    tx(
      [input_at(0, order_addr, inventory())],
      [cont(inventory(), repaired_datum())],
      [Pair(own_cred, 0)],
      [bot],
    ),
  )
}

// The realistic shape, and the one that survives cardano-swaps: the bot SPLITS
// the book. One continuation keeps the client's token as an honest order; the
// other carries the ADA re-paired onto junk. Per-asset conservation is exact —
// every lovelace and every TKN stays inside the perimeter — so `conserved`
// cannot object, and each output clears both floors on its own.
test bot_split_repair_rejected() {
  let honest_half: Data = LegacySwapDatum {
    ..base_order_datum(),
    asset1_price: honest_a1,
    asset2_price: honest_a2,
  }
  !run_withdraw_with(
    payout_addr,
    dapp,
    beacon,
    honest_a1,
    honest_a2,
    tx(
      [input_at(0, order_addr, inventory())],
      [
        // the client's TKN, still an honest ADA/TKN order
        cont(
          assets.from_lovelace(1_000_000)
            |> assets.add(tkn, "TKN", 100)
            |> assets.add(beacon, "A1", 1),
          honest_half,
        ),
        // the client's ADA, now priced against a token worth nothing
        cont(
          assets.from_lovelace(1_000_000)
            |> assets.add(beacon, "PAIR", 1)
            |> assets.add(beacon, "A2", 1),
          repaired_datum(),
        ),
      ],
      [Pair(own_cred, 0)],
      [bot],
    ),
  )
}

// A single crossed quote under an honest band, for completeness: bid 2.8 ADA
// against ask 2.6 ADA breaches the bid ceiling.
test bot_reprice_crossed_pair_rejected() {
  !run_withdraw_with(
    payout_addr,
    dapp,
    beacon,
    honest_a1,
    honest_a2,
    bot_reprice_at(1, 2_800_000, 2_600_000, 1),
  )
}

// ---------------------------------------------------------------------------
// B1 / Finding 3: client_payout must be the client's OWN key address
// ---------------------------------------------------------------------------

// A ceremony that points client_payout at a script payment credential must not
// validate any bot spend, even one that "pays" the guarded value there.
test payout_to_script_rejected() {
  let script_payout = Address {
    payment_credential: Script(foreign_stake),
    stake_credential: None,
  }
  let t = tx(
    [input_at(0, order_addr, inventory())],
    [
      out(
        script_payout,
        assets.from_lovelace(2_000_000) |> assets.add(tkn, "TKN", 100),
      ),
    ],
    [Pair(own_cred, 0)],
    [bot],
  )
  !run_withdraw_with(script_payout, dapp, beacon, min_a1, min_a2, t)
}

// The dApp order-form script hash specifically may not be the payout target.
test payout_to_dapp_hash_rejected() {
  let dapp_payout = Address {
    payment_credential: Script(dapp),
    stake_credential: None,
  }
  let t = tx(
    [input_at(0, order_addr, inventory())],
    [
      out(
        dapp_payout,
        assets.from_lovelace(2_000_000) |> assets.add(tkn, "TKN", 100),
      ),
    ],
    [Pair(own_cred, 0)],
    [bot],
  )
  !run_withdraw_with(dapp_payout, dapp, beacon, min_a1, min_a2, t)
}

// A key address that is not the client's own: `client_payout` was only ever
// required to be SOME key address, so a ceremony could name an operator key and
// every "clean cancel" would pay the operator while the validator returned True.
test payout_to_foreign_key_rejected() {
  let foreign_payout = Address {
    payment_credential: VerificationKey(other),
    stake_credential: None,
  }
  let t = tx(
    [input_at(0, order_addr, inventory())],
    [
      out(
        foreign_payout,
        assets.from_lovelace(2_000_000) |> assets.add(tkn, "TKN", 100),
      ),
    ],
    [Pair(own_cred, 0)],
    [bot],
  )
  !run_withdraw_with(foreign_payout, dapp, beacon, min_a1, min_a2, t)
}

// The client's escape hatch still recovers the inventory under that ceremony.
test payout_to_foreign_key_client_escape_passes() {
  let foreign_payout = Address {
    payment_credential: VerificationKey(other),
    stake_credential: None,
  }
  run_withdraw_with(
    foreign_payout,
    dapp,
    beacon,
    min_a1,
    min_a2,
    theft_tx([client]),
  )
}

// ---------------------------------------------------------------------------
// B1, the half that is NOT fixable here: the p1<->p2 (bot <-> client) slot swap.
//
// RULING: irreducible on chain. `withdraw` compares its two key parameters for
// equality against `extra_signatories`, and `client_payout` for equality against
// an output address. Rename the two 28-byte strings consistently — which the
// operator can do, because it also chooses the payout it names — and every
// predicate over them answers exactly as it did before. There is no oracle on
// chain that maps a key hash to the human holding it, so nothing here can prefer
// one labelling to the other, and no reordering of the disjuncts helps: the
// first disjunct is simply whichever slot the attacker put its own key in.
//
// The tests below are EVIDENCE FOR THAT RULING, not a fix. The fix is off-chain
// and is now mandatory: `verify_ceremony.py` refuses to print a verdict without
// `--my-vkey-file`, which hashes the client's own key file and compares it to
// `client_owner_vkh`.
// ---------------------------------------------------------------------------

// Under the swapped ceremony the OPERATOR's key sits in the client slot and
// takes the unconstrained escape branch: its signature alone moves the whole
// inventory to a third address it controls, with no conservation check reached.
test p1_p2_swap_hands_the_operator_the_unconstrained_branch() {
  run_withdraw_keys(client, bot, bot_addr, steal_to(other_addr, [bot]))
}

// ...and the CLIENT's key, now in the bot slot, is the one left
// conservation-bound. The roles are inverted, not blurred.
test p1_p2_swap_puts_the_clients_key_on_the_constrained_branch() {
  !run_withdraw_keys(client, bot, bot_addr, steal_to(other_addr, [client]))
}

// The honest ceremony returns the mirror-image verdicts for the mirror-image
// transactions. Same code path, same answers, different humans — which is the
// whole ruling in one test.
test p1_p2_swap_is_a_relabelling_no_on_chain_predicate_can_see() {
  and {
    run_withdraw(steal_to(other_addr, [client])),
    !run_withdraw(steal_to(other_addr, [bot])),
    run_withdraw_keys(client, bot, bot_addr, steal_to(other_addr, [bot])),
    !run_withdraw_keys(client, bot, bot_addr, steal_to(other_addr, [client])),
  }
}

// And the swapped ceremony does not fail closed anywhere: its bot path — now the
// client's key — validates an ordinary cancel to the swapped payout, so
// `payout_cred_ok` is satisfied too and no on-chain conjunct is left unmet.
test p1_p2_swapped_ceremony_is_internally_coherent() {
  run_withdraw_keys(
    client,
    bot,
    bot_addr,
    cancel_to(bot_addr, [Pair(own_cred, 0)], [client]),
  )
}

// The one on-chain signal that exists, and it is destructive and after the fact:
// the client's own escape — cancel everything to their own address — is REJECTED
// under the swapped ceremony, because their key is on the constrained branch and
// their address is not `client_payout`. By the time a client can observe that,
// their inventory is already resting under the operator's unconstrained key.
// Hashing the key file before funding is the only non-destructive check.
test p1_p2_swap_rejects_the_clients_own_escape_to_their_own_address() {
  !run_withdraw_keys(
    client,
    bot,
    bot_addr,
    cancel_to(payout_addr, [Pair(own_cred, 0)], [client]),
  )
}

// ---------------------------------------------------------------------------
// The floors bound the SPREAD, never the LEVEL — the p6<->p7 transposition.
//
// Also irreducible here, and for the same reason: no parameter carries a unit,
// and 1/2_600_000 lovelace per base unit is a perfectly legitimate ask floor for
// a token that really is worth that little. The level can only be anchored from
// outside, which is why `verify_ceremony.py` now requires `--decimals` and an
// independently sourced `--expect-band-ada-per-display-unit`.
// ---------------------------------------------------------------------------

// The floors applied to the live preprod instance 3227e143…: bid ceiling
// 2.6 ADA, ask floor 2.7 ADA per whole ADAMMKT (0 decimals).
const live_a1: LegacyRational =
  LegacyRational { numerator: 1, denominator: 2_600_000 }

const live_a2: LegacyRational =
  LegacyRational { numerator: 2_700_000, denominator: 1 }

// Applied in the wrong slots, the same two values still satisfy `floors_ok`
// (2_700_000 * 1 >= 1 * 2_600_000) and the ask floor collapses to 1/2_600_000
// lovelace per base unit — the entire 100-token inventory for less than one
// lovelace, taken by anyone through the permissionless TakeAsset path.
test transposed_floors_are_accepted_on_chain_with_a_dust_ask() {
  run_withdraw_with(
    payout_addr,
    dapp,
    beacon,
    live_a2,
    live_a1,
    bot_reprice_at(2_700_000, 1, 1, 2_600_000),
  )
}

// The identical quote under the ceremony as it was actually applied is rejected,
// so the difference is the transposition and nothing else.
test the_same_dust_ask_under_the_applied_ceremony_is_rejected() {
  !run_withdraw_with(
    payout_addr,
    dapp,
    beacon,
    live_a1,
    live_a2,
    bot_reprice_at(2_700_000, 1, 1, 2_600_000),
  )
}

// ---------------------------------------------------------------------------
// B3: the conservation perimeter must be keyed on the credential the LEDGER
// supplies, not on a ceremony parameter
//
// `own_cred` is handed to `withdraw` by the ledger, so it cannot be
// mis-parameterised. `dapp_hash` can. Scoping the INPUT fold to the stake
// credential means every input the client's credential delegates to is guarded,
// whatever payment script it sits at — while the OUTPUT side still only blesses
// the sanctioned order form, so foreign-address value is drainable nowhere.
//
// The companion "and it stays rescuable" claim holds only for BEACON-FREE
// sibling value; a live sibling order is bot-unmovable, because its own beacons
// are guarded here and its own validator makes them unpayable to the client.
// Both halves are pinned below.
// ---------------------------------------------------------------------------

// Value at a DIFFERENT cardano-swaps payment script wearing this same stake
// credential — the live one-way order form is the real instance — is client
// value. The bot must not be able to route it to itself.
test foreign_payment_script_input_drained_to_bot_rejected() {
  let foreign_order = Address {
    payment_credential: Script(foreign_dapp),
    stake_credential: Some(Inline(own_cred)),
  }
  let t = tx(
    [input_at(0, foreign_order, inventory())],
    [
      out(
        bot_addr,
        assets.from_lovelace(2_000_000) |> assets.add(tkn, "TKN", 100),
      ),
    ],
    [Pair(own_cred, 0)],
    [bot],
  )
  !run_withdraw(t)
}

// Beacon-FREE value at that sibling address — plain ADA, or an order whose
// beacons have already been burned — is rescuable to `client_payout` by the bot.
test foreign_payment_script_input_without_beacons_rescued_to_payout_passes() {
  let foreign_order = Address {
    payment_credential: Script(foreign_dapp),
    stake_credential: Some(Inline(own_cred)),
  }
  let holding = assets.from_lovelace(2_000_000) |> assets.add(tkn, "TKN", 100)
  let t = tx(
    [input_at(0, foreign_order, holding)],
    [out(payout_addr, holding)],
    [Pair(own_cred, 0)],
    [bot],
  )
  run_withdraw(t)
}

// ...but a LIVE sibling order is NOT bot-rescuable, and this is the limit of the
// perimeter fix rather than a bug in it. The real sibling — a one-way
// cardano-swaps order under the same stake credential — carries beacons minted
// under ITS policy, not this ceremony's `beacon_id`, so they are guarded like
// any other asset. Closing that order burns them (the sibling's own validator
// refuses to let beacons leave to a non-order address), the burn shows up here
// as a per-asset deficit, and the whole transaction fails. The bot therefore
// cannot move a live sibling order at all: not to itself, and not to the client.
test foreign_payment_script_input_with_sibling_beacons_not_bot_rescuable() {
  let foreign_order = Address {
    payment_credential: Script(foreign_dapp),
    stake_credential: Some(Inline(own_cred)),
  }
  let t = tx(
    [input_at(0, foreign_order, sibling_inventory())],
    [
      out(
        payout_addr,
        assets.from_lovelace(2_000_000) |> assets.add(tkn, "TKN", 100),
      ),
    ],
    [Pair(own_cred, 0)],
    [bot],
  )
  !run_withdraw(t)
}

// The residual right that keeps it from being stranded value: the client's
// escape hatch reaches it, burned sibling beacons and all.
test foreign_payment_script_input_with_sibling_beacons_client_escape_passes() {
  let foreign_order = Address {
    payment_credential: Script(foreign_dapp),
    stake_credential: Some(Inline(own_cred)),
  }
  let t = tx(
    [input_at(0, foreign_order, sibling_inventory())],
    [
      out(
        payout_addr,
        assets.from_lovelace(2_000_000) |> assets.add(tkn, "TKN", 100),
      ),
    ],
    [Pair(own_cred, 0)],
    [client],
  )
  run_withdraw(t)
}

// The mirror image, which already held before the perimeter fix and must keep
// holding: correctly-placed value cannot be MIGRATED into that trap.
test probe_migration_sanctioned_to_foreign_rejected() {
  let foreign_order = Address {
    payment_credential: Script(foreign_dapp),
    stake_credential: Some(Inline(own_cred)),
  }
  let t = tx(
    [input_at(0, order_addr, inventory())],
    [
      Output {
        address: foreign_order,
        value: inventory(),
        datum: InlineDatum(valid_order_datum()),
        reference_script: None,
      },
    ],
    [Pair(own_cred, 0)],
    [bot],
  )
  !run_withdraw(t)
}

// The p4<->p5 mis-parameterisation (dapp_hash and beacon_id swapped over). With
// the input fold keyed on `dapp_hash`, NOTHING was guarded and conservation was
// vacuously true — a bot signature alone moved everything. Keyed on `own_cred`
// the same permutation fails closed instead.
test dapp_beacon_permutation_fails_closed() {
  !run_withdraw_with(
    payout_addr,
    beacon,
    dapp,
    min_a1,
    min_a2,
    clean_cancel([Pair(own_cred, 0)]),
  )
}

test dapp_beacon_permutation_client_escape_passes() {
  run_withdraw_with(
    payout_addr,
    beacon,
    dapp,
    min_a1,
    min_a2,
    theft_tx([client]),
  )
}

// ---------------------------------------------------------------------------
// Finding 4: anti-brick golden vector — a REAL two-way SwapDatum
//
// Live preprod UTxO at the two-way dApp address
// addr_test1zqge9z36cwm9akl3q04xhvek9cums7drdupgjl0nr3qfz7l9metxr7wcswjcrz0m09r7dezuh7rzqfw463ete5cqd7mqukxrmd
// (query utxo 164796d5…#1, ADA/ADAMMKT, beacon 8a199a17…), captured read-only.
// Its inlineDatumRaw is pinned below; the mirror type must decode it and
// re-encode to the identical bytes, or a bot continuation carrying the real
// dApp datum would brick the client's UTxO.
// ---------------------------------------------------------------------------

const golden_beacon: PolicyId =
  #"8a199a17ef4517215945aaf3c8c5204c60fd94d34c46d341e99c8fcf"

// The exact bytes cardano-cli returned for the live UTxO's inlineDatumRaw.
// Pinned as provenance; the wallet that wrote it encoded the `None` expiration
// as an indefinite-length empty constructor (`d87a9fff`).
const golden_cbor_onchain: ByteArray =
  #"d8799f581c8a199a17ef4517215945aaf3c8c5204c60fd94d34c46d341e99c8fcf58202c973472600b564e14ae330f49bbacf6865006fc316263b1bc5329b5973828cd40405820e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855581c0ff71ae2bdba25bb5e1805983c8e7924edfc77f808f4f8f6cc421ce4474144414d4d4b545820430c6a076c362473c648fd1b7c77c9d8cfc51a10be64f5d78fa34323cd80e573d8799f011a002625a0ffd8799f1a002625a001ffd8799fd8799fd8799f58206b679fe0c40401ca85f9c5d2b87e1ffbfde5a081dff7f2f96f5292501e4e6bb9ff05ffffd87a9fffff"

// The Plutus-canonical re-encoding of the SAME datum. Byte-identical to
// golden_cbor_onchain everywhere except the `None` expiration, which the
// canonical form writes as a definite-length empty constructor (`d87a80`).
// Both forms decode to the identical Data value Constr(1,[]), so the legacy
// dApp validator destructures either without bricking — the difference is
// purely the CBOR empty-list encoding, not the schema.
const golden_cbor_canonical: ByteArray =
  #"d8799f581c8a199a17ef4517215945aaf3c8c5204c60fd94d34c46d341e99c8fcf58202c973472600b564e14ae330f49bbacf6865006fc316263b1bc5329b5973828cd40405820e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855581c0ff71ae2bdba25bb5e1805983c8e7924edfc77f808f4f8f6cc421ce4474144414d4d4b545820430c6a076c362473c648fd1b7c77c9d8cfc51a10be64f5d78fa34323cd80e573d8799f011a002625a0ffd8799f1a002625a001ffd8799fd8799fd8799f58206b679fe0c40401ca85f9c5d2b87e1ffbfde5a081dff7f2f96f5292501e4e6bb9ff05ffffd87a80ff"

fn golden_two_way_datum() -> LegacySwapDatum {
  LegacySwapDatum {
    beacon_id: golden_beacon,
    pair_beacon: #"2c973472600b564e14ae330f49bbacf6865006fc316263b1bc5329b5973828cd",
    asset1_id: #"",
    asset1_name: #"",
    asset1_beacon: #"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    asset2_id: #"0ff71ae2bdba25bb5e1805983c8e7924edfc77f808f4f8f6cc421ce4",
    asset2_name: #"4144414d4d4b54",
    asset2_beacon: #"430c6a076c362473c648fd1b7c77c9d8cfc51a10be64f5d78fa34323cd80e573",
    asset1_price: LegacyRational { numerator: 1, denominator: 2_500_000 },
    asset2_price: LegacyRational { numerator: 2_500_000, denominator: 1 },
    prev_input: Some(
      LegacyOutputReference {
        transaction_id: LegacyTransactionId {
          hash: #"6b679fe0c40401ca85f9c5d2b87e1ffbfde5a081dff7f2f96f5292501e4e6bb9",
        },
        output_index: 5,
      },
    ),
    expiration: None,
  }
}

// Our mirror type re-encodes the real datum to the byte-identical Plutus-
// canonical CBOR (which equals the on-chain bytes but for the documented
// empty-constructor form of `None`). Since Plutus data encoding is bijective,
// this proves the on-chain datum decodes into `LegacySwapDatum` unchanged.
test golden_two_way_datum_reencodes_to_chain_bytes() {
  let d: Data = golden_two_way_datum()
  cbor.serialise(d) == golden_cbor_canonical
}

// The on-chain and canonical encodings agree everywhere except the trailing
// `None`: the shared prefix (all schema-bearing fields) is byte-identical, and
// they diverge only where the empty-constructor list encoding differs.
test golden_onchain_and_canonical_differ_only_in_none_encoding() {
  // Canonical tail is `d87a80ff` (4 bytes): the `None` expiration + the outer
  // constructor's closing byte. Everything before it is the shared prefix.
  let prefix_len = builtin.length_of_bytearray(golden_cbor_canonical) - 4
  builtin.slice_bytearray(0, prefix_len, golden_cbor_onchain) == builtin.slice_bytearray(
    0,
    prefix_len,
    golden_cbor_canonical,
  )
}

// And the real datum round-trips through Data as our mirror type.
test golden_two_way_datum_decodes_as_legacy() {
  let d: Data = golden_two_way_datum()
  expect parsed: LegacySwapDatum = d
  parsed == golden_two_way_datum()
}

// The continuation gate accepts the real datum shape (permissive floors), so a
// bot reprice carrying it is never rejected as a brick.
test golden_two_way_datum_accepted_by_continuation_gate() {
  let output = Output {
    address: order_addr,
    value: inventory(),
    datum: InlineDatum(golden_two_way_datum()),
    reference_script: None,
  }
  // The pair it declares is the pair it carries in, which is what a real reprice
  // does; the gate now refuses a continuation that names any other.
  let d = golden_two_way_datum()
  is_spendable_continuation_datum(
    output,
    golden_beacon,
    zero_floor,
    zero_floor,
    Some((d.asset1_id, d.asset1_name, d.asset2_id, d.asset2_name)),
  )
}

// ---------------------------------------------------------------------------
// Negative control: the guard is load-bearing.
// ---------------------------------------------------------------------------

// The legacy maker_stake predicate ("did the bot sign") accepts the theft tx
// this validator exists to prevent.
test negative_control_legacy_predicate_is_drainable() {
  let t = theft_tx([bot])
  let legacy_allows = list.has(t.extra_signatories, bot)
  legacy_allows && !run_withdraw(t)
}

// ---------------------------------------------------------------------------
// Multi-fill cost
// ---------------------------------------------------------------------------

// Every other test here spends one or two inputs, and `payout_bound` folds over
// `self.inputs` and `self.outputs` several times — so a suite maximum says
// nothing about the transaction the keeper actually submits, which harvests a
// whole batch of filled orders at once. These build that shape at a range of
// batch sizes so the execution units `aiken check` reports are the ones that
// have to fit under the protocol's per-transaction cap.

/// One filled order: its 2 ADA carve, its beacons, the unsold inventory, and the
/// 10 ADA the fill realized.
fn filled_order(ix: Int) -> Input {
  input_at(
    ix,
    order_addr,
    assets.merge(inventory(), assets.from_lovelace(10_000_000)),
  )
}

fn harvest_legs(
  n: Int,
  ins: List<Input>,
  outs: List<Output>,
) -> (List<Input>, List<Output>) {
  if n <= 0 {
    (ins, outs)
  } else {
    harvest_legs(
      n - 1,
      [filled_order(n), ..ins],
      [cont(inventory(), valid_order_datum()), ..outs],
    )
  }
}

/// `n` filled orders harvested in one transaction: each returns to the order
/// address repriced, the realized ADA lands at the payout leg, and the fee leg
/// takes the contracted 2% of what was realized. Conserved exactly, so the
/// measurement is of a transaction that PASSES — a rejected one short-circuits
/// and costs less than the real thing.
fn harvest(n: Int) -> Transaction {
  let (ins, outs) = harvest_legs(n, [], [])
  tx(
    ins,
    list.concat(
      outs,
      [
        out(payout_addr, assets.from_lovelace(n * 9_800_000)),
        out(fee_addr, assets.from_lovelace(n * 200_000)),
      ],
    ),
    [Pair(own_cred, 0)],
    [bot],
  )
}

// Building the fixture costs units too, and those are not the validator's. Each
// bench is paired with the same construction scored on a trivial predicate.
//
// The difference UNDERSTATES the validator: the fixture test's own
// `list.length` traversal is subtracted along with the construction, so what is
// left is `withdraw` MINUS that traversal — a LOWER bound, not an upper one. It
// is wrong by a factor of three on the escape pair, which these benches report
// at 7,456 mem where the same script measured 23,400 on chain against real
// preprod state. Treat these numbers as the SHAPE of the curve — linear in size,
// quadratic in ex-units, and which of the two binds — and take absolute figures
// from a built transaction. .fluxpoint-budget.json records the raw, unsubtracted
// number for exactly that reason: a budget that understates is worse than none.
test bench_fixture_1() {
  list.length(harvest(1).inputs) == 1
}

test bench_harvest_1() {
  run_withdraw_fee(harvest(1))
}

test bench_fixture_4() {
  list.length(harvest(4).inputs) == 4
}

test bench_harvest_4() {
  run_withdraw_fee(harvest(4))
}

test bench_fixture_8() {
  list.length(harvest(8).inputs) == 8
}

test bench_harvest_8() {
  run_withdraw_fee(harvest(8))
}

test bench_fixture_16() {
  list.length(harvest(16).inputs) == 16
}

test bench_harvest_16() {
  run_withdraw_fee(harvest(16))
}

test bench_fixture_32() {
  list.length(harvest(32).inputs) == 32
}

test bench_harvest_32() {
  run_withdraw_fee(harvest(32))
}

// The client's own recovery tooling spends a whole order address in one
// transaction with no cap on how many UTxOs that is, so the cost of the escape
// branch at scale is a self-custody question, not a performance one. `or`
// short-circuits on the client signature before `payout_bound` is reached, and
// these two measure that: same batch sizes as above, client-signed, and the cost
// is flat.
fn escape(n: Int) -> Transaction {
  let t = harvest(n)
  Transaction { ..t, extra_signatories: [client] }
}

test bench_escape_fixture_1() {
  list.length(escape(1).inputs) == 1
}

test bench_escape_1() {
  run_withdraw_fee(escape(1))
}

test bench_escape_fixture_32() {
  list.length(escape(32).inputs) == 32
}

test bench_escape_32() {
  run_withdraw_fee(escape(32))
}
