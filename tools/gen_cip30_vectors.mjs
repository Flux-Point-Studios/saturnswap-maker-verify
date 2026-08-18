// Mints AUTHENTIC CIP-30 signData vectors with @emurgo/cardano-message-signing
// (through lucid's signData) — the library every browser wallet signs with. A
// COSE_Sign1 hand-written from a reading of the spec would prove only that the
// verifier agrees with that reading.
//
// The canonical payload is built HERE, independently of verify_ceremony.py's
// canonical_possession_payload(). The suite asserts the two agree byte for byte,
// so this file is also the cross-implementation check the browser needs: the page
// signs what one implementation renders and the verifier demands what another does.
//
// Run from a checkout that has lucid (SaturnSwapWeb):
//   node --experimental-strip-types tools/gen_cip30_vectors.mjs > testdata/cip30-possession-vectors.json
// It needs no network and no chain.
import { generatePrivateKey, toPublicKey, credentialToAddress, signData } from '@lucid-evolution/lucid';
import { blake2b } from '@noble/hashes/blake2b';
import { bech32 } from '@scure/base';

const hex = (u8) => Buffer.from(u8).toString('hex');
const rawFromBech32 = (s) => Uint8Array.from(bech32.fromWords(bech32.decode(s, 200).words));

/** Mirrors verify_ceremony.py canonical_possession_payload(). Keep the two in step. */
function canonicalPayload({ network, wallet, feeBps, band, challengeHex }) {
    return (
        `SaturnSwap MMaaS — proof you hold the escape-hatch key\n` +
        `network: ${network}\n` +
        `your wallet: ${wallet}\n` +
        `our fee: ${feeBps} bps\n` +
        `your band: ${band}\n` +
        `challenge: ${challengeHex}\n`
    );
}

// Fixed so the committed vectors are stable. The order address and band are real
// shapes from the golden ceremony; nothing here needs to be on chain.
const CHALLENGE = '9c1f4a2b7e5d0c83a6f19b4472e8d05c3fa71620b9ce48d517a2036e8b4cf9d1';
const ORDER_ADDRESS =
    'addr1xyge9z36cwm9akl3q04xhvek9cums7drdupgjl0nr3qfz77c99dqtffjpcf6dp4f6nlzw3z4n5fhr6tayln7vtn5dryq5msy5z';
const BAND = '2.6 - 2.7 ADA per token';
const FEE_BPS = 20;

const CASES = [
    { name: 'mainnet-base', network: 'Mainnet', label: 'mainnet', withStake: true },
    { name: 'mainnet-enterprise', network: 'Mainnet', label: 'mainnet', withStake: false },
    { name: 'preprod-base', network: 'Preprod', label: 'testnet', withStake: true },
];

const out = { challenge_hex: CHALLENGE, order_address: ORDER_ADDRESS, band: BAND, fee_bps: FEE_BPS, vectors: [] };

for (const c of CASES) {
    const sk = generatePrivateKey();
    const pkRaw = rawFromBech32(toPublicKey(sk));
    const vkh = hex(blake2b(pkRaw, { dkLen: 28 }));
    const stakeVkh = hex(blake2b(rawFromBech32(toPublicKey(generatePrivateKey())), { dkLen: 28 }));

    const address = credentialToAddress(
        c.network,
        { type: 'Key', hash: vkh },
        c.withStake ? { type: 'Key', hash: stakeVkh } : undefined,
    );
    const payload = canonicalPayload({
        network: c.label,
        wallet: address,
        feeBps: FEE_BPS,
        band: BAND,
        challengeHex: CHALLENGE,
    });
    const signed = signData(hex(rawFromBech32(address)), Buffer.from(payload, 'utf8').toString('hex'), sk);

    out.vectors.push({
        name: c.name,
        network: c.label,
        address,
        client_owner_vkh: vkh,
        public_key_hex: hex(pkRaw),
        payload_text: payload,
        cose_sign1_hex: signed.signature,
        cose_key_hex: signed.key,
    });
}

console.log(JSON.stringify(out, null, 2));
