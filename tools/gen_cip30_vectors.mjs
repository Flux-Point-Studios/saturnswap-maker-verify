// Mints AUTHENTIC CIP-30 signData vectors over the v2 consent statement with
// @emurgo/cardano-message-signing (through lucid's signData), the library every browser wallet
// signs with. A COSE_Sign1 hand-written from a reading of the spec would prove only that the
// verifier agrees with that reading.
//
// The parameter encoding, the challenge and the statement are built HERE, independently of
// verify_ceremony.py: the parameters exactly as SaturnSwapWeb's orderedParams() hands them to
// lucid, the statement per D2 spec 2.1 with the section 11 daily-loss line. The suite asserts
// Python computes the same challenge and renders the same statement byte for byte, so this is
// also the cross-implementation check the page depends on.
//
// Run beside a node_modules holding SaturnSwapWeb's pins (@lucid-evolution/lucid 0.4.34,
// @noble/hashes 1.8.0, @scure/base 1.2.6):
//   node gen_cip30_vectors.mjs > testdata/cip30-consent-v2-vectors.json
// It needs no network and no chain. testdata/cip30-possession-vectors.json holds the v1
// vectors, frozen to audit v1 proofs; nothing regenerates them.
import { Constr, Data, credentialToAddress, generatePrivateKey, getAddressDetails, signData, toPublicKey } from '@lucid-evolution/lucid';
import { blake2b } from '@noble/hashes/blake2b';
import { bech32 } from '@scure/base';

const hex = (u8) => Buffer.from(u8).toString('hex');
const rawFromBech32 = (s) => Uint8Array.from(bech32.fromWords(bech32.decode(s, 200).words));
const vkhOf = (sk) => hex(blake2b(rawFromBech32(toPublicKey(sk)), { dkLen: 28 }));

const POSSESSION_DOMAIN = 'SaturnSwap-MMaaS-bound-ceremony-possession-v1';
// The generation new ceremonies are applied to (verify_project.sh EXPECTED_BOUND).
const UNAPPLIED_SCRIPT_HASH = '19cc10abe5dfedee65c53d82548a1e6e2997f52c52a70af4170321fe';

const credentialData = (kind, hash) => new Constr(kind === 'Script' ? 1 : 0, [hash]);

function addressData(address) {
    const d = getAddressDetails(address);
    const payment = credentialData(d.paymentCredential.type, d.paymentCredential.hash);
    const stake = d.stakeCredential
        ? new Constr(0, [new Constr(0, [credentialData(d.stakeCredential.type, d.stakeCredential.hash)])])
        : new Constr(1, []);
    return new Constr(0, [payment, stake]);
}

const rationalData = (r) => new Constr(0, [BigInt(r.numerator), BigInt(r.denominator)]);

const orderedParams = (p) => [
    p.adam_bot_pkh,
    p.client_owner_vkh,
    addressData(p.client_payout_address),
    p.dapp_hash,
    p.beacon_id,
    rationalData(p.min_asset1_price),
    rationalData(p.min_asset2_price),
    addressData(p.fee_address),
    BigInt(p.fee_bps),
];

function possessionChallenge(params, network) {
    const text = (s) => Buffer.from(s, 'utf8');
    const parts = [text(POSSESSION_DOMAIN), text('\n'), text(network), text('\n'), Buffer.from(UNAPPLIED_SCRIPT_HASH, 'hex')];
    for (const p of orderedParams(params)) parts.push(text('\n'), Buffer.from(Data.to(p), 'hex'));
    return hex(blake2b(Buffer.concat(parts), { dkLen: 32 }));
}

function gcd(a, b) {
    while (b) [a, b] = [b, a % b];
    return a;
}

/** num/den as its terminating decimal with trailing zeros stripped; there is no statement without one. */
function exactDecimal(num, den) {
    const g = gcd(num, den);
    [num, den] = [num / g, den / g];
    let rest = den;
    let places = 0n;
    for (const p of [2n, 5n]) {
        let k = 0n;
        while (rest % p === 0n) [rest, k] = [rest / p, k + 1n];
        if (k > places) places = k;
    }
    if (rest !== 1n) throw new Error(`${num}/${den} has no exact decimal, so no v2 statement exists`);
    const digits = ((num * 10n ** places) / den).toString().padStart(Number(places) + 1, '0');
    const cut = digits.length - Number(places);
    const frac = digits.slice(cut).replace(/0+$/, '');
    return digits.slice(0, cut) + (frac ? `.${frac}` : '');
}

const bps = (n) => `${n} bps (${exactDecimal(BigInt(n), 100n)}%)`;

function tokenLine({ policyId, assetNameHex }) {
    const name = Buffer.from(assetNameHex, 'hex');
    if (name.length === 0) return `policy ${policyId}, empty asset name`;
    if (name.length <= 32 && /^[0-9A-Za-z._-]+$/.test(name.toString('latin1')))
        return `${name.toString('latin1')} (policy ${policyId}, asset name hex ${assetNameHex})`;
    return `policy ${policyId}, asset name hex ${assetNameHex}`;
}

function consentStatement(network, params, challengeHex, consent) {
    const scale = 10n ** BigInt(consent.decimals);
    const a1 = params.min_asset1_price;
    const a2 = params.min_asset2_price;
    const low = exactDecimal(BigInt(a1.denominator) * scale, BigInt(a1.numerator) * 1_000_000n);
    const high = exactDecimal(BigInt(a2.numerator) * scale, BigInt(a2.denominator) * 1_000_000n);
    const t = consent.terms;
    return [
        'SaturnSwap MMaaS consent, version 2',
        'I consent to SaturnSwap making a market in my token with its bot key, on the terms below.',
        `network: ${network}`,
        `your wallet: ${params.client_payout_address}`,
        `our bot key: ${params.adam_bot_pkh}`,
        `our fee: at most ${bps(params.fee_bps)} of the ADA we pay out to your wallet, none when we close your order`,
        `your price limits: your book never buys above ${low} or sells below ${high} ADA per token`,
        `your token: ${tokenLine(consent.token)}`,
        `token decimals: ${consent.decimals}`,
        `spread: ${bps(t.spreadBps)} between your book's buying and selling prices`,
        `book value cap: ${t.maxDepthAda} ADA (your ADA plus your tokens at our price); above it we return the book to your wallet`,
        `daily loss limit: ${bps(t.dailyLossBps)} of your book's value at the start of each UTC day; past it we return the book to your wallet`,
        `reprice after our price moves: ${bps(t.minRepriceBps)}`,
        `signed at: ${consent.signedAt}`,
        `challenge: ${challengeHex}`,
        '',
    ].join('\n');
}

// The live NIGHT ceremony's operator constants and band (spec 2.2); each vector swaps in a
// fresh client key, so every vector is its own ceremony with its own challenge.
const NIGHT_POLICY = '0691b2fecca1ac4f53cb6dfb00b7013e561d1f34403b957cbb5af1fa';
const OPERATOR = {
    adam_bot_pkh: 'cea98dfce26e0ffbf5ab892edcb8f8ab8b794d5390f80ec0b9aafed3',
    dapp_hash: '11928a3ac3b65edbf103ea6bb3362e39b879a36f02897df31c40917b',
    beacon_id: '8a199a17ef4517215945aaf3c8c5204c60fd94d34c46d341e99c8fcf',
    min_asset1_price: { numerator: 1000, denominator: 97 },
    min_asset2_price: { numerator: 1, denominator: 10 },
    fee_bps: 20,
};
const FEE_ADDRESS = {
    mainnet: 'addr1v9wr69p2tx8dx2lat8rzznahxh4xhfl075yzm8uxmth4tvcf3lx47',
    testnet: 'addr_test1vru3jg02gk49p9t8vw345qr47w9czcaavja4mfh09zcch3guttqnu',
};
const SIGNED_AT = '2026-09-24T12:00:00Z';

const CASES = [
    {
        name: 'mainnet-base', network: 'Mainnet', label: 'mainnet', withStake: true,
        assetNameHex: '4e49474854',
        terms: { spreadBps: 800, maxDepthAda: 120, dailyLossBps: 500, minRepriceBps: 150 },
    },
    {
        name: 'mainnet-enterprise', network: 'Mainnet', label: 'mainnet', withStake: false,
        assetNameHex: '0014df104e49474854',
        terms: { spreadBps: 405, maxDepthAda: 60, dailyLossBps: 5000, minRepriceBps: 200 },
    },
    {
        name: 'preprod-base', network: 'Preprod', label: 'testnet', withStake: true,
        assetNameHex: '',
        terms: { spreadBps: 6000, maxDepthAda: 61, dailyLossBps: 100, minRepriceBps: 1000 },
    },
];

const out = { unapplied_script_hash: UNAPPLIED_SCRIPT_HASH, vectors: [] };

for (const c of CASES) {
    const sk = generatePrivateKey();
    const vkh = vkhOf(sk);
    const address = credentialToAddress(
        c.network,
        { type: 'Key', hash: vkh },
        c.withStake ? { type: 'Key', hash: vkhOf(generatePrivateKey()) } : undefined,
    );
    const params = {
        adam_bot_pkh: OPERATOR.adam_bot_pkh,
        client_owner_vkh: vkh,
        client_payout_address: address,
        dapp_hash: OPERATOR.dapp_hash,
        beacon_id: OPERATOR.beacon_id,
        min_asset1_price: OPERATOR.min_asset1_price,
        min_asset2_price: OPERATOR.min_asset2_price,
        fee_address: FEE_ADDRESS[c.label],
        fee_bps: OPERATOR.fee_bps,
    };
    const consent = {
        token: { policyId: NIGHT_POLICY, assetNameHex: c.assetNameHex },
        decimals: 6,
        terms: c.terms,
        signedAt: SIGNED_AT,
    };
    const challengeHex = possessionChallenge(params, c.label);
    const payload = consentStatement(c.label, params, challengeHex, consent);
    const signed = signData(hex(rawFromBech32(address)), Buffer.from(payload, 'utf8').toString('hex'), sk);

    out.vectors.push({
        name: c.name,
        network: c.label,
        params,
        challenge_hex: challengeHex,
        address,
        client_owner_vkh: vkh,
        public_key_hex: hex(rawFromBech32(toPublicKey(sk))),
        consent_terms: consent,
        payload_text: payload,
        cose_sign1_hex: signed.signature,
        cose_key_hex: signed.key,
    });
}

console.log(JSON.stringify(out, null, 2));
