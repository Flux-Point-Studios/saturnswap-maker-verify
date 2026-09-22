//// SaturnSwap Option C — market-maker staking validator.
////
//// SaturnSwap's own inventory rests at the canonical cardano-swaps spend
//// script with THIS script as its stake credential:
////
////   Address(Script(dapp_hash), Some(Inline(Script(maker_stake_hash))))
////
//// Canonical owner-auth (`common/utils.ak: staking_credential_approves`)
//// approves a reprice (`SpendWithStake` + beacon `UpdateSwaps`) or a cancel
//// (`SpendWithMint` + beacon burn) of a script-staked order IFF this
//// credential appears as a key in `tx.withdrawals` — the withdraw-0 trick.
//// So every reprice/cancel of maker inventory MUST execute this validator as
//// a withdraw-0. This validator makes that withdrawal succeed only when the
//// ADAM maker-bot key signed the tx, turning a would-be permissionless drain
//// into a delegated authorization gate. The floor is "the bot signed";
//// notional-cap / re-binding / kill-switch hardening is deferred.

use aiken/collection/list
use aiken/crypto.{VerificationKeyHash}
use cardano/address.{Credential, Script}
use cardano/certificate.{
  Certificate, DelegateBlockProduction, DelegateCredential, RegisterCredential,
  UnregisterCredential,
}
use cardano/script_context.{ScriptContext}
use cardano/transaction.{Transaction, placeholder}

validator maker_stake(adam_bot_pkh: VerificationKeyHash) {
  // Register-only: lets the credential enter `withdrawals` so it can later be
  // executed as a withdraw-0. Registration confers no spending power on its
  // own. Every OTHER certificate (deregister, delegate, drep, ...) is gated on
  // the bot signature — never left open.
  publish(_redeemer: Data, certificate: Certificate, self: Transaction) {
    when certificate is {
      RegisterCredential { .. } -> True
      _ -> list.has(self.extra_signatories, adam_bot_pkh)
    }
  }

  // The SOLE reprice/cancel authorization path: the ADAM bot must have signed.
  withdraw(_redeemer: Data, _account: Credential, self: Transaction) {
    list.has(self.extra_signatories, adam_bot_pkh)
  }

  // Any other purpose this hash could be used for (mint/spend under this
  // credential, vote, propose) — never left open; still requires the bot sig.
  else(ctx: ScriptContext) {
    list.has(ctx.transaction.extra_signatories, adam_bot_pkh)
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const bot: VerificationKeyHash =
  #"01010101010101010101010101010101010101010101010101010101"

const other: VerificationKeyHash =
  #"02020202020202020202020202020202020202020202020202020202"

const acct: Credential =
  Script(#"03030303030303030303030303030303030303030303030303030303")

const pool: ByteArray =
  #"04040404040404040404040404040404040404040404040404040404"

fn tx_signed_by(signers: List<VerificationKeyHash>) -> Transaction {
  Transaction { ..placeholder, extra_signatories: signers }
}

// (1) bot-signed WithdrawFrom -> accepts.
test withdraw_bot_signed_passes() {
  maker_stake.withdraw(bot, Void, acct, tx_signed_by([bot]))
}

// (2) unsigned WithdrawFrom -> rejects. The core auth.
test withdraw_unsigned_rejected() {
  !maker_stake.withdraw(bot, Void, acct, tx_signed_by([]))
}

// (2b) a DIFFERENT signer (not the bot) -> rejects.
test withdraw_wrong_signer_rejected() {
  !maker_stake.withdraw(bot, Void, acct, tx_signed_by([other]))
}

// (3) credential registration without a signature -> accepts (register-only).
test registration_without_sig_passes() {
  maker_stake.publish(
    bot,
    Void,
    RegisterCredential(acct, Never),
    tx_signed_by([]),
  )
}

// (4a) deregistration without a signature -> rejects.
test deregistration_without_sig_rejected() {
  !maker_stake.publish(
    bot,
    Void,
    UnregisterCredential(acct, Never),
    tx_signed_by([]),
  )
}

// (4b) delegation-change without a signature -> rejects.
test delegation_change_without_sig_rejected() {
  !maker_stake.publish(
    bot,
    Void,
    DelegateCredential(acct, DelegateBlockProduction(pool)),
    tx_signed_by([]),
  )
}

// A cert change WITH the bot signature -> accepts (completeness of the gate).
test cert_change_with_sig_passes() {
  maker_stake.publish(
    bot,
    Void,
    DelegateCredential(acct, DelegateBlockProduction(pool)),
    tx_signed_by([bot]),
  )
}

// The permissionless `fn(_,_,_) -> True` baseline the guard replaces.
fn permissionless_withdraw(
  _redeemer: Data,
  _account: Credential,
  _self: Transaction,
) -> Bool {
  True
}

// (5) NEGATIVE CONTROL — the guard is load-bearing.
// On the SAME unsigned attacker tx: the permissionless variant accepts the
// withdrawal (drainable), while the real bot-sig validator rejects it.
test negative_control_guard_is_load_bearing() {
  let attacker_tx = tx_signed_by([])
  let drainable = permissionless_withdraw(Void, acct, attacker_tx)
  let guarded = maker_stake.withdraw(bot, Void, acct, attacker_tx)
  drainable && !guarded
}
