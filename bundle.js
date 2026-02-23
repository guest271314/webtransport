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
// Helpers
function hex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join(
    " ",
  );
}
function toU8(x) {
  if (typeof x === "string") {
    const s = x.replace(/[^0-9a-f]/gi, "");
    const out = new Uint8Array(s.length / 2);
    for (let i = 0; i < out.length; i++) {
      out[i] = parseInt(s.substr(i * 2, 2), 16);
    }
    return out;
  }
  return x;
}

// Emulate AES-ECB on one block using AES-CBC with zero IV
async function hpMaskFromSampleRaw(hpKeyRawU8, sample16) {
  if (sample16.byteLength !== 16) throw new Error("sample must be 16 bytes");
  const key = await crypto.subtle.importKey(
    "raw",
    hpKeyRawU8,
    { name: "AES-CBC" },
    false,
    ["encrypt"],
  );
  const zeroIv = new Uint8Array(16);
  const ct = await crypto.subtle.encrypt(
    { name: "AES-CBC", iv: zeroIv },
    key,
    sample16,
  );
  const ctU8 = new Uint8Array(ct);
  return ctU8.subarray(0, 5);
}

// RFC9000 PN reconstruction
function expandPacketNumber(truncated, pnLen, expectedNext) {
  const pnWindow = 1 << (pnLen * 8);
  const pnHalf = pnWindow >>> 1;
  let candidate = Math.floor(expectedNext / pnWindow) * pnWindow + truncated;
  if (candidate + pnHalf <= expectedNext) candidate += pnWindow;
  else if (candidate > expectedNext + pnHalf) candidate -= pnWindow;
  return candidate;
}

// Build per-packet IV: baseIV XOR packetNumber (big-endian, right-aligned)
function buildPerPacketIV(baseIVU8, packetNumber) {
  const iv = new Uint8Array(baseIVU8); // copy
  for (let i = 0; i < iv.length; i++) {
    const shift = 8 * (iv.length - 1 - i);
    const pnByte = (packetNumber >>> shift) & 0xff;
    iv[i] = iv[i] ^ pnByte;
  }
  return iv;
}

// Main unprotect function
// - packetBytesU8: Uint8Array of the received packet
// - hpKeyRawU8: Uint8Array raw header-protection key
// - expectedNextPacketNumber: number (highest seen + 1 or similar)
async function unprotectPacket(
  packetBytesU8,
  hpKeyRawU8,
  expectedNextPacketNumber,
) {
  if (!(packetBytesU8 instanceof Uint8Array)) {
    packetBytesU8 = new Uint8Array(packetBytesU8);
  }
  const firstByteMasked = packetBytesU8[0];

  // --------- IMPORTANT: compute pnOffset for your header form here ----------
  // If packet is short-header and you have no extra fields: pnOffset = 1
  // If packet is long-header you MUST parse Version, DCID length, DCID, SCID length, SCID, Length fields etc.
  // Replace the following according to how your code parses headers:
  const pnOffset = 1; // <-- ADAPT for long-header / connection IDs in your implementation
  // ------------------------------------------------------------------------

  const pnLen = (firstByteMasked & 0x03) + 1;
  const sampleOffset = pnOffset + pnLen;
  if (sampleOffset + 16 > packetBytesU8.length) {
    throw new Error("not enough bytes for sample");
  }

  const sample = packetBytesU8.subarray(sampleOffset, sampleOffset + 16);
  const mask = await hpMaskFromSampleRaw(hpKeyRawU8, sample);

  // Unmask
  const firstByteUnmasked = firstByteMasked ^ (mask[0] & 0x0f);
  const pnBytesMasked = packetBytesU8.subarray(pnOffset, pnOffset + pnLen);
  const pnBytesUnmasked = new Uint8Array(pnLen);
  for (let i = 0; i < pnLen; i++) {
    pnBytesUnmasked[i] = pnBytesMasked[i] ^ mask[1 + i];
  }

  // truncated -> number
  let truncated = 0;
  for (let i = 0; i < pnLen; i++) {
    truncated = (truncated << 8) + pnBytesUnmasked[i];
  }
  const fullPn = expandPacketNumber(truncated, pnLen, expectedNextPacketNumber);

  // AAD: header bytes up to and including unmasked PN bytes
  const aad = new Uint8Array(pnOffset + pnLen);
  aad[0] = firstByteUnmasked;
  if (pnOffset > 1) {
    for (let i = 1; i < pnOffset; i++) aad[i] = packetBytesU8[i];
  }
  for (let i = 0; i < pnLen; i++) aad[pnOffset + i] = pnBytesUnmasked[i];

  const ciphertext = packetBytesU8.subarray(pnOffset + pnLen);

  // Debug logs (copy these into your console and paste them here if it still fails)
  console.log(
    "[unprotect] pnOffset",
    pnOffset,
    "pnLen",
    pnLen,
    "sampleOffset",
    sampleOffset,
  );
  console.log("[unprotect] sample", hex(sample), "mask", hex(mask));
  console.log(
    "[unprotect] firstByteMasked",
    hex(new Uint8Array([firstByteMasked])),
  );
  console.log(
    "[unprotect] firstByteUnmasked",
    hex(new Uint8Array([firstByteUnmasked])),
  );
  console.log("[unprotect] pnBytesMasked", hex(pnBytesMasked));
  console.log("[unprotect] pnBytesUnmasked", hex(pnBytesUnmasked));
  console.log("[unprotect] truncated", truncated, "fullPn", fullPn);
  console.log(
    "[unprotect] aad len",
    aad.length,
    "ciphertext len",
    ciphertext.length,
  );

  return { aad, ciphertext, fullPn };
}

// AEAD decrypt wrapper (AES-GCM example)
async function decryptAead(
  aeadKeyRawU8,
  baseIVU8,
  aadU8,
  ciphertextU8,
  packetNumber,
) {
  const aeadKey = await crypto.subtle.importKey(
    "raw",
    aeadKeyRawU8,
    { name: "AES-GCM" },
    false,
    ["decrypt"],
  );
  const iv = buildPerPacketIV(baseIVU8, packetNumber);
  console.log("[decrypt] baseIV", hex(baseIVU8), "perPacketIV", hex(iv));
  try {
    const plainBuf = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv, additionalData: aadU8 },
      aeadKey,
      ciphertextU8,
    );
    return new Uint8Array(plainBuf);
  } catch (e) {
    console.error("AEAD decrypt error:", e);
    throw e;
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

// export { WebTransportEchoServer };
var json = (await import("./export/cert.json", {
  with: {
    type: "json",
  },
})).default;

async function testEcho(config) {
  const url = "https://127.0.0.1:4433";
  console.log(`⏳ Connecting to WebTransport server at ${url}...`);

  try {
    const transport = new WebTransport(url, {
      serverCertificateHashes: [
        {
          algorithm: "sha-256",
          value: new Uint8Array(config.hash.digest),
        },
      ],
    });

    await transport.ready;
    console.log("✅ WebTransport is ready!");

    // Test Datagrams
    const writer = transport.datagrams.writable.getWriter();
    const data = new TextEncoder().encode("Hello WebTransport Echo!");
    await writer.write(data);
    console.log("📤 Sent Datagram:", new TextDecoder().decode(data));

    const reader = transport.datagrams.readable.getReader();
    const { value } = await reader.read();
    console.log("📥 Received Echo:", new TextDecoder().decode(value));
  } catch (e) {
    console.error("❌ Test Failed:", e);
  }
}

// Usage:
// testEcho(json[0]);

testEcho(json[0]).catch(console.log);
// https://gemini.google.com/share/a34176ee9792
