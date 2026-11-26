// Generate self-signed certificate, create/write to cert.json
// guest271314 11-26-2026
import { writeFileSync } from "node:fs";
const enc = new TextEncoder();

// Minimal ASN.1 DER helpers
function derLen(len) {
  if (len < 0x80) return Uint8Array.of(len);
  if (len < 0x100) return Uint8Array.of(0x81, len);
  return Uint8Array.of(0x82, len >> 8, len & 0xff);
}

function concat(...arrays) {
  const out = new Uint8Array(arrays.reduce((n, a) => n + a.length, 0));
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

function tlv(tag, ...parts) {
  const body = concat(...parts);
  return concat(Uint8Array.of(tag), derLen(body.length), body);
}

function derInt(bytes) {
  let start = 0;
  while (
    start < bytes.length - 1 && bytes[start] === 0 &&
    (bytes[start + 1] & 0x80) === 0
  ) {
    start++;
  }
  const sliced = bytes.slice(start);
  return sliced[0] & 0x80
    ? tlv(0x02, Uint8Array.of(0x00), sliced)
    : tlv(0x02, sliced);
}

function derUtcTime(date) {
  const p = (n) => String(n).padStart(2, "0");
  const str = String(date.getUTCFullYear()).slice(-2) +
    p(date.getUTCMonth() + 1) +
    p(date.getUTCDate()) +
    p(date.getUTCHours()) +
    p(date.getUTCMinutes()) +
    p(date.getUTCSeconds()) +
    "Z";
  return tlv(0x17, enc.encode(str));
}

function toPem(der, label) {
  const b64 = btoa(String.fromCharCode(...der));
  return `-----BEGIN ${label}-----\n${
    b64.match(/.{1,64}/g).join("\n")
  }\n-----END ${label}-----\n`;
}

// Standard X.509 / ECDSA OIDs
const OID_ECDSA_SHA256 = Uint8Array.of(
  0x06,
  0x08,
  0x2a,
  0x86,
  0x48,
  0xce,
  0x3d,
  0x04,
  0x03,
  0x02,
); // 1.2.840.10045.4.3.2
const OID_COMMON_NAME = Uint8Array.of(0x06, 0x03, 0x55, 0x04, 0x03); // 2.5.4.3
const OID_SAN = Uint8Array.of(0x06, 0x03, 0x55, 0x1d, 0x11); // 2.5.29.17

export async function generateWebTransportCert(
  { commonName = "127.0.0.1", days = 13 } = {},
) {
  // 1. Generate ECDSA P-256 keypair via Web Crypto
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );

  const spki = new Uint8Array(
    await crypto.subtle.exportKey("spki", keyPair.publicKey),
  );
  const pkcs8 = new Uint8Array(
    await crypto.subtle.exportKey("pkcs8", keyPair.privateKey),
  );

  // 2. Build TBSCertificate (X.509 v3)
  const serial = crypto.getRandomValues(new Uint8Array(16));
  serial[0] = (serial[0] & 0x7f) | 0x01; // positive non-zero integer

  const now = Date.now();
  const notBefore = new Date(now - 60_000);
  const notAfter = new Date(now + days * 86_400_000); // must be <= 14 days for serverCertificateHashes

  const name = tlv(
    0x30,
    tlv(0x31, tlv(0x30, OID_COMMON_NAME, tlv(0x0c, enc.encode(commonName)))),
  );
  const sigAlg = tlv(0x30, OID_ECDSA_SHA256);

  // SubjectAltName: DNS:localhost + IP:127.0.0.1
  const sanValue = tlv(
    0x30,
    tlv(0x82, enc.encode("localhost")),
    tlv(0x87, Uint8Array.of(127, 0, 0, 1)),
  );
  const extensions = tlv(
    0xa3,
    tlv(0x30, tlv(0x30, OID_SAN, tlv(0x04, sanValue))),
  );

  const tbs = tlv(
    0x30,
    tlv(0xa0, derInt(Uint8Array.of(2))), // version: v3 (2)
    derInt(serial),
    sigAlg,
    name, // issuer
    tlv(0x30, derUtcTime(notBefore), derUtcTime(notAfter)),
    name, // subject
    spki,
    extensions,
  );

  // 3. Sign TBSCertificate and convert Web Crypto's IEEE P1363 (r||s) to ASN.1 DER
  const rawSig = new Uint8Array(
    await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      keyPair.privateKey,
      tbs,
    ),
  );
  const derSig = tlv(
    0x30,
    derInt(rawSig.slice(0, 32)),
    derInt(rawSig.slice(32, 64)),
  );

  // 4. Assemble final DER certificate & compute SHA-256 hash
  const certDer = tlv(
    0x30,
    tbs,
    sigAlg,
    tlv(0x03, Uint8Array.of(0x00), derSig),
  );
  const certHash = new Uint8Array(
    await crypto.subtle.digest("SHA-256", certDer),
  );

  return {
    cert: toPem(certDer, "CERTIFICATE"),
    key: toPem(pkcs8, "PRIVATE KEY"),
    certHash: [...certHash],
  };
}

const certs = await generateWebTransportCert();

writeFileSync("cert.json", JSON.stringify(certs, null, 2));
