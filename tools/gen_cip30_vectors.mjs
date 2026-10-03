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
// @noble/hashes 1.8.0, @scure/base 1.2.6, and lucid's own @emurgo/cardano-message-signing-nodejs
// 1.1.0):
//   node gen_cip30_vectors.mjs > testdata/cip30-consent-v2-vectors.json
//   node gen_cip30_vectors.mjs alert > testdata/cip30-alert-vectors.json
// It needs no network and no chain. testdata/cip30-possession-vectors.json holds the v1
// vectors, frozen to audit v1 proofs; nothing regenerates them.
import * as M from '@emurgo/cardano-message-signing-nodejs';
import { CML, Constr, Data, credentialToAddress, generatePrivateKey, getAddressDetails, signData, toPublicKey } from '@lucid-evolution/lucid';
import { blake2b } from '@noble/hashes/blake2b';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
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

function consentVectors() {
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
    return out;
}

// ---------------------------------------------------------------------------------------------
// MMaaS alert bindings: contract C3 payloads, each with the verdict contract C4 demands of
// verify_cip30_envelope, which the Python suite holds it to. Unlike the consent vectors these are
// reproducible byte for byte: the client is the published fixture key of
// testdata/cip30-lace-kid-vectors.json (test only, never funded) and ed25519 is deterministic.
// ---------------------------------------------------------------------------------------------
const utf8 = (s) => new TextEncoder().encode(s);
const FIXTURE_SEEDS = {
    payment: 'saturnswap-mmaas consent-governing golden: client payment key, test fixture only, never funded',
    stake: 'saturnswap-mmaas consent-governing golden: client stake key, test fixture only, never funded',
};
const fixtureKey = (seed) => CML.PrivateKey.from_normal_bytes(sha256(utf8(seed)));
const fixtureBytes = (what) => sha256(utf8(`saturnswap-mmaas alert vectors: ${what}, test fixture only`));
const DEST_HMAC_KEY = fixtureBytes('destination HMAC key');
const BOOK_CREDENTIAL = hex(fixtureBytes('book credential').slice(0, 28));
const TELEGRAM_CHAT_ID = '7000000001';
const DISCORD_WEBHOOK_ID = '1290000000000000001';
const CONFIRMATION_CODE = 'K7QF2MXR';
const EXPIRES = '2026-10-03T12:05:00Z';
// The identity point: a key with no private half, which a cofactorless reader lets R = identity,
// s = 0 "sign" anything for.
const SMALL_ORDER_KEY = Uint8Array.from([1, ...new Array(31).fill(0)]);

const cborHead = (major, n) =>
    Uint8Array.from(n < 24 ? [major << 5 | n] : n < 256 ? [major << 5 | 24, n] : [major << 5 | 25, n >> 8, n & 255]);
const bstr = (b) => Buffer.concat([cborHead(2, b.length), b]);
const keyHash = (vkey) => blake2b(vkey, { dkLen: 28 });

/** The C3 v1 payload: ASCII, LF separated, no trailing LF. */
function alertPayload(f) {
    const book = f.credential.slice(0, 8);
    const sentence = f.purpose === 'bind-alerts'
        ? `Send alerts for book ${book} to the ${f.platform === 'telegram' ? 'Telegram chat' : 'Discord channel'} you confirmed with code ${f.code}.`
        : `Stop alerts for book ${book} to destination ${f.destination_digest.slice(0, 8)}.`;
    return [
        'SaturnSwap MMaaS alerts v1',
        sentence,
        `purpose=${f.purpose}`,
        `network=${f.network}`,
        `credential=${f.credential}`,
        `payout=${f.payout}`,
        `destination=${f.platform}:${f.destination_digest}`,
        ...(f.purpose === 'bind-alerts' ? [`code=${f.code}`] : []),
        `nonce=${f.nonce}`,
        `expires=${f.expires}`,
    ].join('\n');
}

function c3(purpose, network, payout, platform, nonceLabel) {
    const destinationId = platform === 'telegram' ? TELEGRAM_CHAT_ID : DISCORD_WEBHOOK_ID;
    return {
        purpose,
        network,
        credential: BOOK_CREDENTIAL,
        payout,
        platform,
        destination_id: destinationId,
        destination_digest: hex(hmac(sha256, DEST_HMAC_KEY, utf8(`${platform}:${destinationId}`))),
        ...(purpose === 'bind-alerts' ? { code: CONFIRMATION_CODE } : {}),
        nonce: hex(fixtureBytes(`nonce ${nonceLabel}`)).slice(0, 48),
        expires: EXPIRES,
    };
}

/** What lucid's signData returns, and so Eternl and every lucid page: protected {alg, address}. */
function lucidShape(address, payload, sk) {
    const signed = signData(hex(address), hex(payload), sk.to_bech32());
    return { cose_sign1_hex: signed.signature, cose_key_hex: signed.key };
}

/** cardano-js-sdk's cip30signData, and so Lace: the address again as kid, label 4 of the
 * protected header (createSigStructureHeaders) and label 2 of the COSE_Key (createCoseKey). */
function laceShape(address, payload, sk) {
    const eddsa = M.Label.from_algorithm_id(M.AlgorithmId.EdDSA);
    const protectedMap = M.HeaderMap.new();
    protectedMap.set_key_id(address);
    protectedMap.set_header(M.Label.new_text('address'), M.CBORValue.new_bytes(address));
    protectedMap.set_algorithm_id(eddsa);
    const builder = M.COSESign1Builder.new(
        M.Headers.new(M.ProtectedHeaderMap.new(protectedMap), M.HeaderMap.new()), payload, false);
    const sign1 = builder.build(sk.sign(builder.make_data_to_sign().to_bytes()).to_raw_bytes());
    const key = M.COSEKey.new(M.Label.from_key_type(M.KeyType.OKP));
    key.set_key_id(address);
    key.set_algorithm_id(eddsa);
    key.set_header(M.Label.new_int(M.Int.new_negative(M.BigNum.from_str('1'))), M.CBORValue.new_int(M.Int.new_i32(6)));
    key.set_header(M.Label.new_int(M.Int.new_negative(M.BigNum.from_str('2'))), M.CBORValue.new_bytes(sk.to_public().to_raw_bytes()));
    return { cose_sign1_hex: hex(sign1.to_bytes()), cose_key_hex: hex(key.to_bytes()) };
}

/** Hand-assembled: no wallet can sign for a key with no private half. */
function smallOrderForgery(address, payload) {
    const protectedHeader = Buffer.concat([Uint8Array.from([0xa2, 0x01, 0x27, 0x67]), utf8('address'), bstr(address)]);
    const sign1 = Buffer.concat([
        Uint8Array.from([0x84]), bstr(protectedHeader), Buffer.from('a166686173686564f4', 'hex'), bstr(payload),
        bstr(Buffer.concat([SMALL_ORDER_KEY, new Uint8Array(32)])),
    ]);
    const key = Buffer.concat([Buffer.from('a401010327200621', 'hex'), bstr(SMALL_ORDER_KEY)]);
    return { cose_sign1_hex: hex(sign1), cose_key_hex: hex(key) };
}

function alertVectors() {
    const payment = fixtureKey(FIXTURE_SEEDS.payment);
    const vkh = hex(keyHash(payment.to_public().to_raw_bytes()));
    const stakeVkh = hex(keyHash(fixtureKey(FIXTURE_SEEDS.stake).to_public().to_raw_bytes()));
    const otherStake = hex(fixtureBytes('another stake key').slice(0, 28));
    const base = (network, stake) => credentialToAddress(network, { type: 'Key', hash: vkh }, { type: 'Key', hash: stake });
    const mainnet = base('Mainnet', stakeVkh);
    const preprod = base('Preprod', stakeVkh);
    const restaked = base('Mainnet', otherStake);
    const smallOrder = credentialToAddress('Mainnet', { type: 'Key', hash: hex(keyHash(SMALL_ORDER_KEY)) });

    const vector = (name, why, fields, address, proof, expect) => ({
        name,
        why,
        network: fields.network,
        c3: fields,
        expected_payload_text: alertPayload(fields),
        expected_address: fields.payout,
        expected_address_hex: hex(rawFromBech32(fields.payout)),
        signed_by_address: address,
        ...proof,
        expect,
    });
    const accepted = (key) => ({ accepted: true, vkey_hex: hex(key.to_public().to_raw_bytes()) });
    const refused = (code) => ({ accepted: false, code });
    const sign = (shape, address, fields) => shape(rawFromBech32(address), utf8(alertPayload(fields)), payment);

    const bindPreprod = c3('bind-alerts', 'preprod', preprod, 'telegram', 'bind-preprod-telegram');
    const bindMainnet = c3('bind-alerts', 'mainnet', mainnet, 'discord', 'bind-mainnet-discord');
    const unbindPreprod = c3('unbind-alerts', 'preprod', preprod, 'telegram', 'unbind-preprod-telegram');
    const laceBind = c3('bind-alerts', 'mainnet', mainnet, 'telegram', 'lace-kid-bind-mainnet-telegram');
    const restakedBind = c3('bind-alerts', 'mainnet', restaked, 'telegram', 'wrong-address-restaked');
    const smallOrderBind = c3('bind-alerts', 'mainnet', smallOrder, 'telegram', 'small-order');

    const bindPreprodProof = sign(lucidShape, preprod, bindPreprod);
    const unbindPreprodProof = sign(lucidShape, preprod, unbindPreprod);

    return {
        note: 'MMaaS alert binding vectors: CIP-30 signData proofs over contract C3 payloads, each with the '
            + 'verdict contract C4 demands of verify_cip30_envelope(cose_sign1_hex, cose_key_hex, '
            + 'expected_payload, expected_address): the 32-byte vkey, or CoseRejected with `code`. '
            + 'expected_payload is expected_payload_text as UTF-8 and expected_address is '
            + 'expected_address_hex. The signer is the fixture client key of cip30-lace-kid-vectors.json, '
            + 'test only and never funded; the destination HMAC key, chat and webhook ids, credential and '
            + 'nonces are fixtures too. GENERATED by tools/gen_cip30_vectors.mjs alert; do not edit by hand.',
        provenance: {
            generator: 'tools/gen_cip30_vectors.mjs alert',
            libraries: '@lucid-evolution/lucid 0.4.34 signData (lucid shape), '
                + '@emurgo/cardano-message-signing-nodejs 1.1.0 with set_key_id (Lace shape)',
            fixtureClientKey: 'testdata/cip30-lace-kid-vectors.json provenance.fixtureClientKey',
        },
        destination_hmac_key_hex: hex(DEST_HMAC_KEY),
        vectors: [
            vector('bind-preprod-telegram', 'A genuine bind from the payout wallet.',
                bindPreprod, preprod, bindPreprodProof, accepted(payment)),
            vector('bind-mainnet-discord', 'A genuine bind into a Discord channel, on mainnet.',
                bindMainnet, mainnet, sign(lucidShape, mainnet, bindMainnet), accepted(payment)),
            vector('unbind-preprod-telegram', 'A genuine signed unbind.',
                unbindPreprod, preprod, unbindPreprodProof, accepted(payment)),
            vector('lace-kid-bind-mainnet-telegram', 'A genuine bind as Lace signs it: kid = the address.',
                laceBind, mainnet, sign(laceShape, mainnet, laceBind), accepted(payment)),
            vector('relayed-purpose-unbind-as-bind',
                'The genuine unbind signature presented where its book\'s bind is expected.',
                bindPreprod, preprod, unbindPreprodProof, refused('payload_mismatch')),
            vector('relayed-purpose-bind-as-unbind',
                'The genuine bind signature presented where its book\'s unbind is expected.',
                unbindPreprod, preprod, bindPreprodProof, refused('payload_mismatch')),
            vector('wrong-address-restaked',
                'The payout key signs the expected payload from its own account, whose stake key is '
                + 'not the payout address\'s: the key hash matches, the address does not.',
                restakedBind, mainnet, sign(lucidShape, mainnet, restakedBind), refused('address_mismatch')),
            vector('small-order',
                'A payout address whose key is the identity point, "signed" with R = identity, s = 0.',
                smallOrderBind, smallOrder, smallOrderForgery(rawFromBech32(smallOrder), utf8(alertPayload(smallOrderBind))),
                refused('small_order_key')),
            vector('trailing-bytes', 'The genuine preprod bind with one byte appended.',
                bindPreprod, preprod,
                { ...bindPreprodProof, cose_sign1_hex: `${bindPreprodProof.cose_sign1_hex}00` },
                refused('trailing_bytes')),
        ],
    };
}

const MINT = { consent: consentVectors, alert: alertVectors };
const mode = process.argv[2] ?? 'consent';
if (!Object.hasOwn(MINT, mode)) throw new Error(`unknown mode ${mode}: expected consent or alert`);
console.log(JSON.stringify(MINT[mode](), null, 2));
