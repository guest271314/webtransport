var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __commonJS = (cb, mod) =>
  function __require() {
    return mod ||
      (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod),
      mod.exports;
  };
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from)) {
      if (!__hasOwnProp.call(to, key) && key !== except) {
        __defProp(to, key, {
          get: () => from[key],
          enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable,
        });
      }
    }
  }
  return to;
};
var __toESM = (
  mod,
  isNodeMode,
  target,
) => (target = mod != null ? __create(__getProtoOf(mod)) : {},
  __copyProps(
    // If the importer is in node compatibility mode or this is not an ESM
    // file that has been converted to a CommonJS file using a Babel-
    // compatible transform (i.e. "__esModule" has not been set), then set
    // "default" to the CommonJS "module.exports" for node compatibility.
    isNodeMode || !mod || !mod.__esModule
      ? __defProp(target, "default", { value: mod, enumerable: true })
      : target,
    mod,
  ));

// cert.json
var require_cert = __commonJS({
  "cert.json"(exports, module) {
    module.exports = [
      {
        privateKey:
          "-----BEGIN PRIVATE KEY-----\r\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQglSjilJTaXM3VOHFs\r\nhEnV1j3oLy/RMW4J/nRsam8EaeChRANCAAQMwMcKtBRdGq6onlL0bX30fQGLJGpA\r\nMkwR14QDB/Gt4Vyk3AzU8U2KWfTAUa0ShMWbW/Sxm4MwUFcom5tvoz7K\r\n-----END PRIVATE KEY-----\r\n",
        pem:
          "-----BEGIN CERTIFICATE-----\r\nMIIB7TCCAcSgAwIBAgIJeG5fUB6K8SSbMAwGCCqGSM49BAMCBQAwcDELMAkGA1UE\r\nBhMCVVMxFDASBgNVBAgTC0xvcyBBbmdlbGVzMRQwEgYDVQQHEwtMb3MgQW5nZWxl\r\nczEhMB8GA1UEChMYV2ViVHJhbnNwb3J0IFRlc3QgU2VydmVyMRIwEAYDVQQDEwkx\r\nMjcuMC4wLjEwHhcNMjYwMjE1MjExMjQyWhcNMjYwMjI4MjExMjQyWjBwMQswCQYD\r\nVQQGEwJVUzEUMBIGA1UECBMLTG9zIEFuZ2VsZXMxFDASBgNVBAcTC0xvcyBBbmdl\r\nbGVzMSEwHwYDVQQKExhXZWJUcmFuc3BvcnQgVGVzdCBTZXJ2ZXIxEjAQBgNVBAMT\r\nCTEyNy4wLjAuMTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABAzAxwq0FF0arqie\r\nUvRtffR9AYskakAyTBHXhAMH8a3hXKTcDNTxTYpZ9MBRrRKExZtb9LGbgzBQVyib\r\nm2+jPsqjRTBDMAwGA1UdEwQFMAMBAf8wCwYDVR0PBAQDAgL0MCYGA1UdEQQfMB2G\r\nG2h0dHA6Ly9leGFtcGxlLm9yZy93ZWJpZCNtZTAMBggqhkjOPQQDAgUAAxUAW29i\r\namVjdCBBcnJheUJ1ZmZlcl0=\r\n-----END CERTIFICATE-----\r\n",
        hash: {
          code: 18,
          size: 32,
          digest: [
            96,
            156,
            247,
            5,
            195,
            162,
            29,
            202,
            116,
            13,
            103,
            97,
            103,
            103,
            94,
            47,
            171,
            93,
            152,
            110,
            37,
            82,
            239,
            214,
            231,
            106,
            202,
            11,
            61,
            140,
            183,
            144,
          ],
          bytes: [
            18,
            32,
            96,
            156,
            247,
            5,
            195,
            162,
            29,
            202,
            116,
            13,
            103,
            97,
            103,
            103,
            94,
            47,
            171,
            93,
            152,
            110,
            37,
            82,
            239,
            214,
            231,
            106,
            202,
            11,
            61,
            140,
            183,
            144,
          ],
        },
        secret: "super-secret-shhhhhh",
      },
    ];
  },
});

// tls-crypto.js
var SALT_V1 = new Uint8Array([
  56,
  118,
  44,
  247,
  245,
  89,
  52,
  179,
  77,
  23,
  57,
  201,
  204,
  228,
  137,
  85,
  52,
  86,
  4,
  1,
]);
function toHex(u8) {
  return Array.from(u8).map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function hkdfExpandLabel(prkKey, label, length) {
  const encoder = new TextEncoder();
  const labelBytes = encoder.encode("quic " + label);
  const info = new Uint8Array(2 + 1 + labelBytes.length + 1);
  const view = new DataView(info.buffer);
  view.setUint16(0, length, false);
  view.setUint8(2, labelBytes.length);
  info.set(labelBytes, 3);
  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(),
      info,
    },
    prkKey,
    length * 8,
  );
  return new Uint8Array(bits);
}
async function hkdfExtract(salt, ikm) {
  const hmacKey = await crypto.subtle.importKey(
    "raw",
    salt,
    {
      name: "HMAC",
      hash: "SHA-256",
    },
    false,
    [
      "sign",
    ],
  );
  const prkBuf = await crypto.subtle.sign("HMAC", hmacKey, ikm);
  const prkKey = await crypto.subtle.importKey("raw", prkBuf, "HKDF", false, [
    "deriveBits",
  ]);
  return prkKey;
}
async function deriveInitialSecrets(clientCID) {
  if (!(clientCID instanceof Uint8Array)) clientCID = new Uint8Array(clientCID);
  const prkKey = await hkdfExtract(SALT_V1, clientCID);
  const cBits = await hkdfExpandLabel(prkKey, "client in", 32);
  const sBits = await hkdfExpandLabel(prkKey, "server in", 32);
  async function derive(bits) {
    const keyRaw = await crypto.subtle.importKey("raw", bits, "HKDF", false, [
      "deriveBits",
    ]);
    const [kB, iB, hB] = await Promise.all([
      hkdfExpandLabel(keyRaw, "key", 16),
      hkdfExpandLabel(keyRaw, "iv", 12),
      hkdfExpandLabel(keyRaw, "hp", 16),
    ]);
    // javascript
    // immediately after obtaining kB, iB, hB (Uint8Array)
    console.log("[derive] derived key (hex):", toHex(kB));
    console.log("[derive] derived iv  (hex):", toHex(iB));
    console.log("[derive] derived hp  (hex):", toHex(hB));
    const key = await crypto.subtle.importKey("raw", kB, "AES-GCM", false, [
      "encrypt",
      "decrypt",
    ]);
    const hp = await crypto.subtle.importKey("raw", hB, "AES-CTR", false, [
      "encrypt",
    ]);
    try {
      console.log("[derive] label-derived key (hex):", toHex(kB));
      console.log("[derive] label-derived iv  (hex):", toHex(iB));
      console.log("[derive] label-derived hp  (hex):", toHex(hB));
    } catch (e) {
    }
    return {
      key,
      iv: new Uint8Array(iB),
      hp,
    };
  }
  return {
    client: await derive(cBits),
    server: await derive(sBits),
  };
}
function constructNonce(iv, pn) {
  const nonce = new Uint8Array(iv);
  const pnBig = BigInt(pn);
  for (let i = 0; i < 8; i++) {
    nonce[11 - i] ^= Number(pnBig >> BigInt(8 * i) & 0xffn);
  }
  return nonce;
}
async function generateHeaderProtectionMask(hpKey, sample) {
  if (!(sample instanceof Uint8Array)) sample = new Uint8Array(sample);
  if (sample.length !== 16) throw new Error("hp sample must be 16 bytes");
  const zero = new Uint8Array(16);
  const maskBuf = await crypto.subtle.encrypt(
    {
      name: "AES-CTR",
      counter: sample,
      length: 128,
    },
    hpKey,
    zero,
  );
  return new Uint8Array(maskBuf);
}

// byte-buffer.js
function encodeVarInt(v) {
  if (v < 64) {
    return new Uint8Array([
      v,
    ]);
  } else if (v < 16384) {
    return new Uint8Array([
      64 | v >> 8,
      v & 255,
    ]);
  } else if (v < 1073741824) {
    return new Uint8Array([
      128 | v >> 24,
      v >> 16 & 255,
      v >> 8 & 255,
      v & 255,
    ]);
  } else {
    const res = new Uint8Array(8);
    res[0] = 192;
    const b = BigInt(v);
    for (let i = 0; i < 7; i++) {
      res[7 - i] = Number(b >> BigInt(i * 8) & 0xffn);
    }
    return res;
  }
}
function concatBytes(...arrays) {
  const total = arrays.reduce((acc, arr) => acc + arr.length, 0);
  const res = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) {
    res.set(a, off);
    off += a.length;
  }
  return res;
}

// packet.js
var isLongHeader = (b) => (b & 128) !== 0;
async function unprotectPacket(data, keys, logger = console) {
  if (!(data instanceof Uint8Array)) data = new Uint8Array(data);
  logger.log("[unprotect] packet length:", data.length);
  console.log(
    "packet first20:",
    Array.from(data.slice(0, 20)).map((b) => b.toString(16).padStart(2, "0"))
      .join(" "),
  );

  if (data.length < 7) throw new Error("packet too short");
  const dcidLen = data[5];
  const scidLenOffset = 6 + dcidLen;
  if (data.length <= scidLenOffset) {
    throw new Error("packet too short for scid length");
  }
  const scidLen = data[scidLenOffset];
  let offset = scidLenOffset + 1 + scidLen;
  if (offset >= data.length) throw new Error("packet too short after scid");
  const getVarInt = () => {
    if (offset >= data.length) throw new Error("varint index OOB");
    const first = data[offset++];
    const len = 1 << (first >> 6);
    let val = BigInt(first & 63);
    for (let i = 1; i < len; i++) {
      if (offset >= data.length) throw new Error("varint overflow");
      val = val << 8n | BigInt(data[offset++]);
    }
    return Number(val);
  };
  const tokenLen = getVarInt();
  if (offset + tokenLen > data.length) throw new Error("token length OOB");
  offset += tokenLen;
  const lengthField = getVarInt();
  if (offset + lengthField > data.length) throw new Error("length field OOB");
  const pnOffset = offset;
  logger.log("[unprotect] pnOffset:", pnOffset, "lengthField:", lengthField);
  const sampleStart = pnOffset + 4;
  const sampleEnd = sampleStart + 16;
  if (sampleEnd > data.length) {
    throw new Error("not enough bytes for header protection sample");
  }
  const sample = data.slice(sampleStart, sampleEnd);
  logger.log(
    "[unprotect] sample (hex):",
    Array.from(sample).map((b) => b.toString(16).padStart(2, "0")).join(" "),
  );
  const mask = await generateHeaderProtectionMask(keys.hp, sample);
  logger.log(
    "[unprotect] mask (hex):",
    Array.from(mask).map((b) => b.toString(16).padStart(2, "0")).join(" "),
  );
  const firstByteMasked = data[0];
  const firstByteUnmasked = firstByteMasked ^ mask[0] & 15;
  logger.log(
    "[unprotect] firstByteMasked:",
    firstByteMasked.toString(16),
    "firstByteUnmasked:",
    firstByteUnmasked.toString(16),
  );
  const pnLen = (firstByteUnmasked & 3) + 1;
  if (pnLen < 1 || pnLen > 4) throw new Error("invalid pn length");
  logger.log("[unprotect] pnLen:", pnLen);
  if (pnOffset + pnLen > data.length) throw new Error("pn bytes OOB");
  const pnBytes = new Uint8Array(pnLen);
  for (let i = 0; i < pnLen; i++) {
    pnBytes[i] = data[pnOffset + i] ^ mask[i + 1];
  }
  logger.log(
    "[unprotect] pnBytes (hex):",
    Array.from(pnBytes).map((b) => b.toString(16).padStart(2, "0")).join(" "),
  );
  let pn = 0n;
  for (let i = 0; i < pnLen; i++) {
    pn = pn << 8n | BigInt(pnBytes[i]);
  }
  logger.log("[unprotect] pn numeric:", pn.toString());
  const aad = concatBytes(
    new Uint8Array([
      firstByteUnmasked,
    ]),
    data.slice(1, pnOffset),
    pnBytes,
  );
  logger.log("[unprotect] aad length:", aad.length);
  const ciphertextStart = pnOffset + pnLen;
  const ciphertextEnd = pnOffset + lengthField;
  if (ciphertextEnd > data.length) throw new Error("ciphertext end OOB");
  const ciphertext = data.slice(ciphertextStart, ciphertextEnd);
  logger.log("[unprotect] ciphertext length:", ciphertext.length);
  try {
    const plaintextBuf = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: constructNonce(keys.iv, Number(pn)),
        additionalData: aad,
      },
      keys.key,
      ciphertext,
    );
    const plaintext = new Uint8Array(plaintextBuf);
    logger.log(
      "[unprotect] decrypt succeeded, plaintext len:",
      plaintext.length,
    );
    return {
      pn: Number(pn),
      plaintext,
    };
  } catch (err) {
    logger.error("[unprotect] decrypt failed:", err);
    logger.error("[unprotect] debug context:", {
      firstByteMasked: firstByteMasked.toString(16),
      firstByteUnmasked: firstByteUnmasked.toString(16),
      pnLen,
      pnBytes: Array.from(pnBytes),
      sample: Array.from(sample),
      mask: Array.from(mask),
      ciphertextHex: Array.from(ciphertext).slice(0, 64).map((b) =>
        b.toString(16).padStart(2, "0")
      ).join(" "),
      ciphertextLen: ciphertext.length,
    });
    throw err;
  }
}
async function protectPacket(headerBase, pn, payload, keys) {
  if (!(headerBase instanceof Uint8Array)) {
    headerBase = new Uint8Array(headerBase);
  }
  if (!(payload instanceof Uint8Array)) payload = new Uint8Array(payload);
  const pnLen = (headerBase[0] & 3) + 1;
  if (pnLen < 1 || pnLen > 4) throw new Error("invalid pnLen in headerBase");
  const pnBytes = new Uint8Array(pnLen);
  for (let i = pnLen - 1; i >= 0; i--) {
    pnBytes[i] = pn & 255;
    pn = pn >> 8;
  }
  const payloadLen = pnBytes.length + payload.length + 16;
  const lenVarInt = encodeVarInt(payloadLen);
  const fullHeader = concatBytes(headerBase, lenVarInt, pnBytes);
  const ciphertextBuf = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: constructNonce(keys.iv, pn),
      additionalData: fullHeader,
    },
    keys.key,
    payload,
  );
  const ciphertext = new Uint8Array(ciphertextBuf);
  const packet = concatBytes(fullHeader, ciphertext);
  const pnOffset = fullHeader.length - pnBytes.length;
  const sampleStart = pnOffset + 4;
  const sampleEnd = sampleStart + 16;
  if (sampleEnd > packet.length) {
    throw new Error("not enough bytes to take header protection sample");
  }
  const sample = packet.slice(sampleStart, sampleEnd);
  const mask = await generateHeaderProtectionMask(keys.hp, sample);
  const res = new Uint8Array(packet);
  res[0] ^= mask[0] & 15;
  for (let i = 0; i < pnBytes.length; i++) {
    res[pnOffset + i] ^= mask[i + 1];
  }
  return res;
}
var createAckFrame = (pn) =>
  concatBytes(
    new Uint8Array([
      2,
      0,
      0,
      0,
    ]),
    encodeVarInt(pn),
  );
var createWebTransportSettings = () =>
  concatBytes(
    new Uint8Array([
      6,
      0,
      4,
      32,
      1,
      0,
    ]),
  );

// server.js
var WebTransportEchoServer = class {
  constructor(certConfigArray) {
    const config = certConfigArray[0];
    this.certDer = Uint8Array.from(
      atob(
        config.pem.replace(/-----(BEGIN|END) CERTIFICATE-----/g, "").replace(
          /\s+/g,
          "",
        ),
      ),
      (c) => c.charCodeAt(0),
    );
    this.socket = null;
    this.writer = null;
    this.keys = null;
    this.nextPn = 0;
  }
  async start(address = "127.0.0.1", port = 4433) {
    this.socket = new UDPSocket({ localAddress: address, localPort: port });
    const { readable, writable } = await this.socket.opened;
    this.writer = writable.getWriter();
    console.log(`\u{1F680} UDPSocket Server listening on ${address}:${port}`);
    this._listen(readable);
  }
  async _listen(readable) {
    const reader = readable.getReader();
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      const packetData = new Uint8Array(value.data);
      if (!isLongHeader(packetData[0])) continue;
      const dcid = packetData.slice(6, 6 + packetData[5]);
      if (!this.keys) this.keys = await deriveInitialSecrets(dcid);
      try {
        const { pn, plaintext } = await unprotectPacket(
          packetData,
          this.keys.client,
        );
        console.log(`\u{1F680} Decrypted PN: ${pn}`);
        const payload = concatBytes(
          createAckFrame(pn),
          createWebTransportSettings(),
        );
        await this.sendResponse(
          payload,
          packetData,
          value.remoteAddress,
          value.remotePort,
        );
      } catch (e) {
        console.error("Decryption failed. Check SALT or HP Mask.");
        this.keys = null;
      }
    }
  }
  async sendResponse(payload, rawData, remoteAddress, remotePort) {
    const dcidLen = rawData[5];
    const dcid = rawData.slice(6, 6 + dcidLen);
    const scidLen = rawData[6 + dcidLen];
    const scid = rawData.slice(7 + dcidLen, 7 + dcidLen + scidLen);
    const resHeaderBase = concatBytes(
      new Uint8Array([195]),
      rawData.slice(1, 5),
      new Uint8Array([scidLen]),
      scid,
      new Uint8Array([dcidLen]),
      dcid,
      new Uint8Array([0]),
    );
    const protectedPacket = await protectPacket(
      resHeaderBase,
      this.nextPn++,
      payload,
      this.keys.server,
    );
    const hex = Array.from(protectedPacket).map((b) =>
      b.toString(16).padStart(2, "0")
    ).join(" ");
    console.log(
      `\u{1F4E4} Sending PN ${this.nextPn - 1}: ${hex.substring(0, 50)}...`,
    );
    await this.writer.write({
      data: protectedPacket.buffer,
      remoteAddress,
      remotePort,
    });
  }
};
var certData =
  (await Promise.resolve().then(() => __toESM(require_cert()))).default;
var server = new WebTransportEchoServer(certData);
server.start("127.0.0.1", 4433);
export { WebTransportEchoServer };
