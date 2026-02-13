/**
 * TLS 1.3 Cryptographic operations for QUIC.
 * Uses the WebCrypto API for all cryptographic operations.
 *
 * QUIC uses TLS 1.3 but integrates it differently than TCP:
 * - QUIC handles its own packet protection (header + payload encryption)
 * - TLS handshake messages are carried in QUIC CRYPTO frames
 * - QUIC derives its own packet protection keys from TLS secrets
 *
 * Cipher suites supported:
 * - TLS_AES_128_GCM_SHA256 (0x1301) - primary
 * - TLS_AES_256_GCM_SHA384 (0x1302)
 * - TLS_CHACHA20_POLY1305_SHA256 (0x1303)
 */

import { concatBytes, hexToBytes, bytesToHex } from './byte-buffer.js';

// QUIC v1 salt for Initial secrets (RFC 9001 Section 5.2)
const QUIC_V1_INITIAL_SALT = hexToBytes('38762cf7f55934b34d179ae6a4c80cadccbb7f0a');

// Labels for HKDF-Expand-Label (TLS 1.3 / QUIC)
const LABEL_CLIENT_IN = 'client in';
const LABEL_SERVER_IN = 'server in';
const LABEL_QUIC_KEY = 'quic key';
const LABEL_QUIC_IV = 'quic iv';
const LABEL_QUIC_HP = 'quic hp';
const LABEL_QUIC_KU = 'quic ku';

export const CipherSuite = {
  TLS_AES_128_GCM_SHA256: 0x1301,
  TLS_AES_256_GCM_SHA384: 0x1302,
  TLS_CHACHA20_POLY1305_SHA256: 0x1303,
};

/**
 * Get cipher suite parameters.
 */
export function getCipherParams(suite) {
  switch (suite) {
    case CipherSuite.TLS_AES_128_GCM_SHA256:
      return { hash: 'SHA-256', keyLen: 16, ivLen: 12, tagLen: 16, aead: 'AES-GCM' };
    case CipherSuite.TLS_AES_256_GCM_SHA384:
      return { hash: 'SHA-384', keyLen: 32, ivLen: 12, tagLen: 16, aead: 'AES-GCM' };
    case CipherSuite.TLS_CHACHA20_POLY1305_SHA256:
      return { hash: 'SHA-256', keyLen: 32, ivLen: 12, tagLen: 16, aead: 'CHACHA20-POLY1305' };
    default:
      throw new Error(`Unsupported cipher suite: 0x${suite.toString(16)}`);
  }
}

/**
 * HKDF-Extract: Extract a pseudorandom key from input keying material.
 */
export async function hkdfExtract(hash, salt, ikm) {
  const key = await crypto.subtle.importKey(
    'raw', salt.length > 0 ? salt : new Uint8Array(hash === 'SHA-256' ? 32 : 48),
    { name: 'HMAC', hash },
    false, ['sign']
  );
  const prk = await crypto.subtle.sign('HMAC', key, ikm);
  return new Uint8Array(prk);
}

/**
 * HKDF-Expand: Expand a pseudorandom key to the desired length.
 */
export async function hkdfExpand(hash, prk, info, length) {
  const hashLen = hash === 'SHA-256' ? 32 : 48;
  const n = Math.ceil(length / hashLen);
  const okm = new Uint8Array(n * hashLen);

  const key = await crypto.subtle.importKey(
    'raw', prk, { name: 'HMAC', hash }, false, ['sign']
  );

  let prev = new Uint8Array(0);
  for (let i = 1; i <= n; i++) {
    const input = concatBytes(prev, info, new Uint8Array([i]));
    const block = new Uint8Array(await crypto.subtle.sign('HMAC', key, input));
    okm.set(block, (i - 1) * hashLen);
    prev = block;
  }

  return okm.slice(0, length);
}

/**
 * HKDF-Expand-Label as defined in TLS 1.3 (RFC 8446 Section 7.1).
 * Used for deriving QUIC keys.
 *
 * struct {
 *   uint16 length;
 *   opaque label<7..255>;    // "tls13 " + label
 *   opaque context<0..255>;
 * } HkdfLabel;
 */
export async function hkdfExpandLabel(hash, secret, label, context, length) {
  const fullLabel = new TextEncoder().encode('tls13 ' + label);

  // Build HkdfLabel structure
  const hkdfLabel = new Uint8Array(2 + 1 + fullLabel.length + 1 + context.length);
  let offset = 0;

  // length (uint16)
  hkdfLabel[offset++] = (length >> 8) & 0xff;
  hkdfLabel[offset++] = length & 0xff;

  // label length + label
  hkdfLabel[offset++] = fullLabel.length;
  hkdfLabel.set(fullLabel, offset);
  offset += fullLabel.length;

  // context length + context
  hkdfLabel[offset++] = context.length;
  if (context.length > 0) {
    hkdfLabel.set(context, offset);
  }

  return hkdfExpand(hash, secret, hkdfLabel, length);
}

/**
 * Derive QUIC Initial secrets from a connection ID.
 * Used for the Initial packet encryption before the TLS handshake completes.
 * (RFC 9001 Section 5.2)
 */
export async function deriveInitialSecrets(destConnId) {
  const hash = 'SHA-256';

  // initial_secret = HKDF-Extract(initial_salt, client_dst_connection_id)
  const initialSecret = await hkdfExtract(hash, QUIC_V1_INITIAL_SALT, destConnId);

  // client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)
  const clientSecret = await hkdfExpandLabel(hash, initialSecret, LABEL_CLIENT_IN, new Uint8Array(0), 32);

  // server_initial_secret = HKDF-Expand-Label(initial_secret, "server in", "", 32)
  const serverSecret = await hkdfExpandLabel(hash, initialSecret, LABEL_SERVER_IN, new Uint8Array(0), 32);

  return { clientSecret, serverSecret };
}

/**
 * Derive QUIC packet protection keys from a traffic secret.
 * (RFC 9001 Section 5.1)
 */
export async function derivePacketKeys(secret, suite = CipherSuite.TLS_AES_128_GCM_SHA256) {
  const params = getCipherParams(suite);
  const hash = params.hash;

  const key = await hkdfExpandLabel(hash, secret, LABEL_QUIC_KEY, new Uint8Array(0), params.keyLen);
  const iv = await hkdfExpandLabel(hash, secret, LABEL_QUIC_IV, new Uint8Array(0), params.ivLen);
  const hp = await hkdfExpandLabel(hash, secret, LABEL_QUIC_HP, new Uint8Array(0), params.keyLen);

  return { key, iv, hp };
}

/**
 * Construct the nonce for AEAD encryption.
 * nonce = iv XOR packet_number (left-padded to iv length)
 */
export function constructNonce(iv, packetNumber) {
  const nonce = new Uint8Array(iv.length);
  nonce.set(iv);

  // XOR the packet number into the rightmost bytes of the IV
  let pn = packetNumber;
  for (let i = nonce.length - 1; i >= 0 && pn > 0; i--) {
    nonce[i] ^= pn & 0xff;
    pn = Math.floor(pn / 256);
  }

  return nonce;
}

/**
 * AEAD encryption (AES-128-GCM or AES-256-GCM).
 * Returns ciphertext + authentication tag.
 */
export async function aeadEncrypt(keyBytes, nonce, plaintext, aad) {
  const key = await crypto.subtle.importKey(
    'raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt']
  );

  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 },
    key, plaintext
  );

  return new Uint8Array(ciphertext);
}

/**
 * AEAD decryption (AES-128-GCM or AES-256-GCM).
 * Input is ciphertext + authentication tag.
 */
export async function aeadDecrypt(keyBytes, nonce, ciphertext, aad) {
  const key = await crypto.subtle.importKey(
    'raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']
  );

  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 },
      key, ciphertext
    );
    return new Uint8Array(plaintext);
  } catch (e) {
    throw new Error('AEAD decryption failed: ' + e.message);
  }
}

/**
 * Header protection mask generation using AES-ECB.
 * (RFC 9001 Section 5.4.3)
 *
 * For AES-based ciphers, the mask is generated by:
 *   mask = AES-ECB(hp_key, sample)
 * where sample is 16 bytes from the packet payload.
 */
export async function generateHeaderProtectionMask(hpKey, sample) {
  // AES-ECB via AES-CTR with zero IV (single block, no counter increment matters)
  const key = await crypto.subtle.importKey(
    'raw', hpKey,
    { name: 'AES-CTR' },
    false, ['encrypt']
  );

  // Use CTR mode with counter = 0 to effectively get ECB for a single block
  const counter = new Uint8Array(16);
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-CTR', counter, length: 128 },
    key, sample
  );

  return new Uint8Array(encrypted).slice(0, 5);
}

/**
 * Apply or remove header protection from a QUIC packet.
 * (RFC 9001 Section 5.4)
 */
export function applyHeaderProtection(header, mask, isLongHeader) {
  const result = new Uint8Array(header);

  if (isLongHeader) {
    // Long header: mask lower 4 bits of first byte
    result[0] ^= mask[0] & 0x0f;
  } else {
    // Short header: mask lower 5 bits of first byte
    result[0] ^= mask[0] & 0x1f;
  }

  // Determine packet number length from (now-unmasked) first byte
  const pnLength = (result[0] & 0x03) + 1;
  const pnOffset = header.length - pnLength;

  // Unmask the packet number bytes
  for (let i = 0; i < pnLength; i++) {
    result[pnOffset + i] ^= mask[1 + i];
  }

  return result;
}

/**
 * SHA-256 hash.
 */
export async function sha256(data) {
  const hash = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(hash);
}

/**
 * SHA-384 hash.
 */
export async function sha384(data) {
  const hash = await crypto.subtle.digest('SHA-384', data);
  return new Uint8Array(hash);
}

/**
 * Generate an ECDHE key pair for key exchange (using P-256).
 */
export async function generateECDHKeyPair() {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true, ['deriveBits']
  );
  return keyPair;
}

/**
 * Perform ECDH key exchange.
 */
export async function ecdhDeriveBits(privateKey, publicKeyBytes) {
  // Import the raw public key
  const publicKey = await crypto.subtle.importKey(
    'raw', publicKeyBytes,
    { name: 'ECDH', namedCurve: 'P-256' },
    false, []
  );

  const bits = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: publicKey },
    privateKey, 256
  );

  return new Uint8Array(bits);
}

/**
 * Export a public key to raw format (uncompressed point).
 */
export async function exportPublicKey(keyPair) {
  const raw = await crypto.subtle.exportKey('raw', keyPair.publicKey);
  return new Uint8Array(raw);
}

/**
 * Generate a self-signed ECDSA P-256 certificate valid for 14 days.
 * Returns { certificate, privateKey, hash } where hash is for serverCertificateHashes.
 */
export async function generateSelfSignedCert() {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true, ['sign', 'verify']
  );

  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', keyPair.publicKey));

  // Build TBS (To Be Signed) certificate
  const now = new Date();
  const notAfter = new Date(now.getTime() + 14 * 24 * 60 * 60 * 1000); // 14 days

  const serialNumber = await crypto.getRandomValues(new Uint8Array(16));
  serialNumber[0] &= 0x7f; // ensure positive

  const tbs = buildTbsCertificate({
    serialNumber,
    notBefore: now,
    notAfter,
    spki,
  });

  // Sign the TBS
  const signature = new Uint8Array(await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    keyPair.privateKey, tbs
  ));

  // The signature from WebCrypto is in IEEE P1363 format (r || s, each 32 bytes)
  // X.509 needs DER-encoded ASN.1 (SEQUENCE { INTEGER r, INTEGER s })
  const derSignature = p1363ToDer(signature);

  // Build the full certificate
  const certificate = buildX509Certificate(tbs, derSignature);

  // Compute hash for serverCertificateHashes
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', certificate));

  return {
    certificate,
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
    publicKeySpki: spki,
    hash,
  };
}

/**
 * Get the hash ArrayBuffer for use with serverCertificateHashes.
 */
export function getCertificateHash(cert) {
  return {
    algorithm: 'sha-256',
    value: cert.hash.buffer,
  };
}

// ---- ASN.1 / DER helpers ----

function derLength(len) {
  if (len < 0x80) return new Uint8Array([len]);
  if (len < 0x100) return new Uint8Array([0x81, len]);
  return new Uint8Array([0x82, (len >> 8) & 0xff, len & 0xff]);
}

function derSequence(...items) {
  const content = concatBytes(...items);
  return concatBytes(new Uint8Array([0x30]), derLength(content.length), content);
}

function derSet(...items) {
  const content = concatBytes(...items);
  return concatBytes(new Uint8Array([0x31]), derLength(content.length), content);
}

function derInteger(bytes) {
  // Ensure positive (prepend 0x00 if high bit set)
  let data = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  if (data[0] & 0x80) {
    data = concatBytes(new Uint8Array([0x00]), data);
  }
  return concatBytes(new Uint8Array([0x02]), derLength(data.length), data);
}

function derSmallInteger(val) {
  if (val < 0x80) return new Uint8Array([0x02, 0x01, val]);
  return new Uint8Array([0x02, 0x02, (val >> 8) & 0xff, val & 0xff]);
}

function derBitString(data, unusedBits = 0) {
  return concatBytes(
    new Uint8Array([0x03]),
    derLength(data.length + 1),
    new Uint8Array([unusedBits]),
    data
  );
}

function derOctetString(data) {
  return concatBytes(new Uint8Array([0x04]), derLength(data.length), data);
}

function derOid(oidBytes) {
  return concatBytes(new Uint8Array([0x06]), derLength(oidBytes.length), oidBytes);
}

function derUtf8String(str) {
  const bytes = new TextEncoder().encode(str);
  return concatBytes(new Uint8Array([0x0c]), derLength(bytes.length), bytes);
}

function derGeneralizedTime(date) {
  const s = date.toISOString().replace(/[-:T]/g, '').replace(/\.\d+/, '').replace('Z', '') + 'Z';
  const bytes = new TextEncoder().encode(s);
  return concatBytes(new Uint8Array([0x18]), derLength(bytes.length), bytes);
}

function derExplicit(tag, content) {
  return concatBytes(new Uint8Array([0xa0 | tag]), derLength(content.length), content);
}

// OIDs
const OID_ECDSA_SHA256 = new Uint8Array([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]); // 1.2.840.10045.4.3.2
const OID_EC_PUBLIC_KEY = new Uint8Array([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);       // 1.2.840.10045.2.1
const OID_P256 = new Uint8Array([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]);          // 1.2.840.10045.3.1.7
const OID_COMMON_NAME = new Uint8Array([0x55, 0x04, 0x03]);                                   // 2.5.4.3

function buildAlgorithmIdentifier() {
  return derSequence(derOid(OID_ECDSA_SHA256));
}

function buildName(cn) {
  const atv = derSequence(derOid(OID_COMMON_NAME), derUtf8String(cn));
  return derSequence(derSet(atv));
}

function buildValidity(notBefore, notAfter) {
  return derSequence(derGeneralizedTime(notBefore), derGeneralizedTime(notAfter));
}

function buildTbsCertificate({ serialNumber, notBefore, notAfter, spki }) {
  const version = derExplicit(0, derSmallInteger(2)); // v3
  const serial = derInteger(serialNumber);
  const sigAlg = buildAlgorithmIdentifier();
  const issuer = buildName('WebTransport Dev');
  const validity = buildValidity(notBefore, notAfter);
  const subject = buildName('WebTransport Dev');

  // SPKI is already DER-encoded from WebCrypto exportKey('spki')
  return derSequence(version, serial, sigAlg, issuer, validity, subject, spki);
}

function buildX509Certificate(tbs, derSignature) {
  const sigAlg = buildAlgorithmIdentifier();
  const sigBitString = derBitString(derSignature);
  return derSequence(tbs, sigAlg, sigBitString);
}

/**
 * Convert ECDSA signature from IEEE P1363 (r||s) to DER format.
 */
function p1363ToDer(sig) {
  const half = sig.length / 2;
  const r = sig.slice(0, half);
  const s = sig.slice(half);
  return derSequence(derInteger(r), derInteger(s));
}

/**
 * Build a minimal DER-encoded X.509 certificate.
 * This is a simplified certificate for development/testing.
 */
function buildMinimalCertificate(spkiBytes, keyPair) {
  // For a minimal implementation, we create a simplified cert structure.
  // A production implementation would use a proper ASN.1 library.

  // This returns the SPKI as a "certificate" placeholder.
  // In a real implementation, you would use a library like pkijs or asn1js
  // to build a proper X.509 certificate.

  // For QUIC/WebTransport, the certificate needs to be valid and signed.
  // Self-signed certs work for testing but browsers require proper cert validation.
  return spkiBytes;
}

/**
 * Sign data using ECDSA with SHA-256.
 */
export async function ecdsaSign(privateKey, data) {
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey, data
  );
  return new Uint8Array(signature);
}

/**
 * Verify ECDSA signature.
 */
export async function ecdsaVerify(publicKey, signature, data) {
  return crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    publicKey, signature, data
  );
}

/**
 * Transcript hash - maintains a running hash of all handshake messages.
 */
export class TranscriptHash {
  constructor(hashAlgorithm = 'SHA-256') {
    this.algorithm = hashAlgorithm;
    this.messages = [];
  }

  addMessage(data) {
    this.messages.push(new Uint8Array(data));
  }

  async digest() {
    const allData = concatBytes(...this.messages);
    const hash = await crypto.subtle.digest(this.algorithm, allData);
    return new Uint8Array(hash);
  }

  async emptyHash() {
    const hash = await crypto.subtle.digest(this.algorithm, new Uint8Array(0));
    return new Uint8Array(hash);
  }

  clone() {
    const copy = new TranscriptHash(this.algorithm);
    copy.messages = this.messages.map(m => new Uint8Array(m));
    return copy;
  }
}

export async function importCertFromPem(jsonCert) {
  const certDer = pemToDer(jsonCert.pem);
  const keyDer = pemToDer(jsonCert.privateKey);

  const privateKey = await crypto.subtle.importKey(
    'pkcs8', keyDer,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false, ['sign']
  );

  return {
    certificate: certDer,
    privateKey,
    publicKeySpki: certDer,
  };
}

function pemToDer(pem) {
  const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s/g, '');
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}