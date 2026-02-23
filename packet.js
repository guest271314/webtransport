import { encodeVarInt, concatBytes } from './byte-buffer.js';
import { constructNonce, generateHeaderProtectionMask } from './tls-crypto.js';

export const isLongHeader = (b) => (b & 0x80) !== 0;

export async function unprotectPacket(data, keys) {
    const dcidLen = data[5];
    const scidLenOffset = 6 + dcidLen;
    const scidLen = data[scidLenOffset];
    let offset = scidLenOffset + 1 + scidLen;

    const getVarInt = () => {
        const first = data[offset++];
        const len = 1 << (first >> 6);
        let val = first & 0x3f;
        for (let i = 1; i < len; i++) { val = (val << 8) | data[offset++]; }
        return val;
    };

    const tokenLen = getVarInt();
    offset += tokenLen;
    const lengthField = getVarInt();
    const pnOffset = offset;

    const sample = data.slice(pnOffset + 4, pnOffset + 20);
    const mask = await generateHeaderProtectionMask(keys.hp, sample);
    const firstByte = data[0] ^ (mask[0] & 0x0f);
    const pnLen = (firstByte & 0x03) + 1;
    
    let pn = 0n;
    const pnBytes = new Uint8Array(pnLen);
    for (let i = 0; i < pnLen; i++) {
        pnBytes[i] = data[pnOffset + i] ^ mask[i + 1];
        pn = (pn << 8n) | BigInt(pnBytes[i]);
    }

    const aad = concatBytes(new Uint8Array([firstByte]), data.slice(1, pnOffset), pnBytes);
    const ciphertext = data.slice(pnOffset + pnLen, pnOffset + lengthField);

    const plaintext = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: constructNonce(keys.iv, Number(pn)), additionalData: aad },
        keys.key, ciphertext
    );
    return { pn: Number(pn), plaintext: new Uint8Array(plaintext) };
}

export async function protectPacket(headerBase, pn, payload, keys) {
    const pnBytes = new Uint8Array([pn & 0xff]); // Using 1-byte PN for simplicity
    const payloadLen = pnBytes.length + payload.length + 16; // +16 for GCM tag
    const fullHeader = concatBytes(headerBase, encodeVarInt(payloadLen), pnBytes);
    
    const ciphertext = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: constructNonce(keys.iv, pn), additionalData: fullHeader },
        keys.key, payload
    );

    const res = concatBytes(fullHeader, new Uint8Array(ciphertext));
    const pnOffset = fullHeader.length - pnBytes.length;
    const sample = res.slice(pnOffset + 4, pnOffset + 20);
    const mask = await generateHeaderProtectionMask(keys.hp, sample);

    res[0] ^= (mask[0] & 0x0f);
    for (let i = 0; i < pnBytes.length; i++) {
        res[pnOffset + i] ^= mask[i + 1];
    }
    return res;
}

export const createAckFrame = (pn) => concatBytes(new Uint8Array([0x02, 0x00, 0x00, 0x00]), encodeVarInt(pn));
export const createWebTransportSettings = () => concatBytes(new Uint8Array([0x06, 0x00, 0x04, 0x20, 0x01, 0x00]));