const SALT_V1 = new Uint8Array([
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
    0x4d, 0x17, 0x39, 0xc9, 0xcc, 0xe4, 0x89, 0x55,
    0x34, 0x56, 0x04, 0x01
]);

async function hkdfExpandLabel(prk, label, length) {
    const encoder = new TextEncoder();
    const labelBytes = encoder.encode("quic " + label);
    const info = new Uint8Array(2 + 1 + labelBytes.length + 1);
    const view = new DataView(info.buffer);
    view.setUint16(0, length, false);
    view.setUint8(2, labelBytes.length);
    info.set(labelBytes, 3);
    return crypto.subtle.deriveBits(
        { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(), info },
        prk, length * 8
    );
}

export async function deriveInitialSecrets(clientCID) {
    const saltKey = await crypto.subtle.importKey("raw", SALT_V1, "HKDF", false, ["deriveBits"]);
    const initialBits = await crypto.subtle.deriveBits(
        { name: "HKDF", hash: "SHA-256", salt: SALT_V1, info: clientCID },
        saltKey, 256
    );
    const initialSecret = await crypto.subtle.importKey("raw", initialBits, "HKDF", false, ["deriveBits"]);
    const cBits = await hkdfExpandLabel(initialSecret, "client in", 32);
    const sBits = await hkdfExpandLabel(initialSecret, "server in", 32);

    const derive = async (bits) => {
        const keyRaw = await crypto.subtle.importKey("raw", bits, "HKDF", false, ["deriveBits"]);
        const [kB, iB, hB] = await Promise.all([
            hkdfExpandLabel(keyRaw, "key", 16),
            hkdfExpandLabel(keyRaw, "iv", 12),
            hkdfExpandLabel(keyRaw, "hp", 16)
        ]);
        return {
            key: await crypto.subtle.importKey("raw", kB, "AES-GCM", false, ["decrypt", "encrypt"]),
            iv: new Uint8Array(iB),
            hp: await crypto.subtle.importKey("raw", hB, "AES-CTR", false, ["encrypt"])
        };
    };
    return { client: await derive(cBits), server: await derive(sBits) };
}

export function constructNonce(iv, pn) {
    const nonce = new Uint8Array(iv);
    const pnBig = BigInt(pn);
    for (let i = 0; i < 8; i++) {
        nonce[11 - i] ^= Number((pnBig >> BigInt(8 * i)) & 0xffn);
    }
    return nonce;
}

export async function generateHeaderProtectionMask(hpKey, sample) {
    const mask = await crypto.subtle.encrypt(
        { name: "AES-CTR", counter: sample, length: 128 },
        hpKey, new Uint8Array(16)
    );
    return new Uint8Array(mask);
}