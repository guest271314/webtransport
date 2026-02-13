/**
 * QUIC Packet Parser and Serializer (RFC 9000 Section 17)
 *
 * QUIC has two header forms:
 * - Long Header: Used for Initial, Handshake, 0-RTT, and Retry packets
 * - Short Header: Used for 1-RTT packets after handshake completion
 */

import { ByteBuffer, concatBytes } from './byte-buffer.js';
import { PacketType, QUIC_VERSION_1 } from './constants.js';
import {
  deriveInitialSecrets,
  derivePacketKeys,
  constructNonce,
  aeadDecrypt,
  aeadEncrypt,
  generateHeaderProtectionMask,
  applyHeaderProtection,
  CipherSuite,
} from './tls-crypto.js';

/**
 * Parse the first byte to determine if this is a long or short header packet.
 */
export function isLongHeader(firstByte) {
  return (firstByte & 0x80) !== 0;
}

/**
 * Determine the long header packet type from the first byte.
 */
export function getLongHeaderType(firstByte) {
  return (firstByte & 0x30) >> 4;
}

/**
 * Parse a QUIC long header packet (without decryption).
 * Returns the parsed header fields and the raw payload.
 */
export function parseLongHeader(data) {
  const buf = new ByteBuffer(data);

  const firstByte = buf.readUint8();
  if (!(firstByte & 0x80)) throw new Error('Not a long header packet');

  // Fixed bit must be 1
  if (!(firstByte & 0x40)) throw new Error('Fixed bit not set');

  const packetType = (firstByte & 0x30) >> 4;
  const version = buf.readUint32();

  // Destination Connection ID
  const dcidLen = buf.readUint8();
  const dcid = buf.readBytes(dcidLen);

  // Source Connection ID
  const scidLen = buf.readUint8();
  const scid = buf.readBytes(scidLen);

  let tokenLength = 0;
  let token = new Uint8Array(0);

  // Token field only in Initial packets
  if (packetType === PacketType.INITIAL) {
    tokenLength = buf.readVarInt();
    if (tokenLength > 0) {
      token = buf.readBytes(tokenLength);
    }
  }

  // Payload length (for all long header types except Retry)
  let payloadLength = 0;
  let headerLength = 0;
  let payload = new Uint8Array(0);

  if (packetType !== PacketType.RETRY) {
    payloadLength = buf.readVarInt();
    headerLength = buf.offset;
    payload = buf.readBytes(payloadLength);
  } else {
    headerLength = buf.offset;
    payload = buf.readRemainingBytes();
  }

  return {
    firstByte,
    packetType,
    version,
    dcid,
    scid,
    token,
    tokenLength,
    payloadLength,
    headerLength,
    header: data.slice(0, headerLength),
    payload,
    raw: data,
  };
}

/**
 * Parse a QUIC short header (1-RTT) packet.
 * The short header has a variable structure that depends on connection state.
 */
export function parseShortHeader(data, dcidLength) {
  const buf = new ByteBuffer(data);

  const firstByte = buf.readUint8();
  if (firstByte & 0x80) throw new Error('Not a short header packet');

  // Fixed bit must be 1
  if (!(firstByte & 0x40)) throw new Error('Fixed bit not set');

  const spinBit = (firstByte & 0x20) >> 5;
  const keyPhase = (firstByte & 0x04) >> 2;

  const dcid = buf.readBytes(dcidLength);
  const headerLength = buf.offset;
  const payload = buf.readRemainingBytes();

  return {
    firstByte,
    spinBit,
    keyPhase,
    dcid,
    headerLength,
    header: data.slice(0, headerLength),
    payload,
    raw: data,
  };
}

/**
 * Remove header protection and decrypt a QUIC packet.
 * This implements the packet unprotection process from RFC 9001 Section 5.4.
 */
export async function unprotectPacket(parsed, keys, isLongHdr) {
  const { header, payload } = parsed;

  // The sample starts 4 bytes after the start of the packet number field
  // For long headers, the PN starts at the header offset
  // Sample offset = pnOffset + 4 (we need to find the sample in the payload)
  const sampleOffset = 4; // 4 bytes into the payload (past the max PN length)

  if (payload.length < sampleOffset + 16) {
    throw new Error('Packet too short for header protection sample');
  }

  const sample = payload.slice(sampleOffset, sampleOffset + 16);
  const mask = await generateHeaderProtectionMask(keys.hp, sample);

  // Unmask the first byte
  const unmaskedFirstByte = isLongHdr
    ? header[0] ^ (mask[0] & 0x0f)
    : header[0] ^ (mask[0] & 0x1f);

  // Determine PN length from the unmasked first byte
  const pnLength = (unmaskedFirstByte & 0x03) + 1;

  // Unmask packet number bytes (they are the first bytes of the payload area)
  const pnBytes = new Uint8Array(pnLength);
  for (let i = 0; i < pnLength; i++) {
    pnBytes[i] = payload[i] ^ mask[1 + i];
  }

  // Decode packet number
  let packetNumber = 0;
  for (let i = 0; i < pnLength; i++) {
    packetNumber = (packetNumber << 8) | pnBytes[i];
  }

  // Build the AAD (associated data) = the unprotected header + unmasked PN
  const aad = new Uint8Array(header.length + pnLength);
  aad.set(header);
  aad[0] = unmaskedFirstByte;
  aad.set(pnBytes, header.length);

  // Wait, the header already includes everything up to the PN field
  // For long headers: the header is everything before the payload
  // The PN is the first pnLength bytes of what we called "payload"
  // The actual encrypted payload starts after the PN

  // Rebuild AAD properly
  const actualAad = new Uint8Array(header.length);
  actualAad.set(header);
  actualAad[0] = unmaskedFirstByte;
  // The packet number is part of the "payload" in our parsing
  // We need to include it in the AAD
  const aadWithPn = concatBytes(actualAad, pnBytes);

  // The actual ciphertext is everything after the PN
  const ciphertext = payload.slice(pnLength);

  // Construct nonce
  const nonce = constructNonce(keys.iv, packetNumber);

  // Decrypt
  const plaintext = await aeadDecrypt(keys.key, nonce, ciphertext, aadWithPn);

  return {
    packetNumber,
    pnLength,
    plaintext,
    unmaskedFirstByte,
  };
}

/**
 * Protect (encrypt) a QUIC packet.
 * Takes the header, packet number, and plaintext payload, returns the full protected packet.
 */
export async function protectPacket(header, packetNumber, pnLength, plaintext, keys, isLongHdr) {
  // Encode packet number
  const pnBytes = new Uint8Array(pnLength);
  let pn = packetNumber;
  for (let i = pnLength - 1; i >= 0; i--) {
    pnBytes[i] = pn & 0xff;
    pn >>= 8;
  }

  // Build AAD = header + pn_bytes
  const aad = concatBytes(header, pnBytes);

  // Construct nonce
  const nonce = constructNonce(keys.iv, packetNumber);

  // Encrypt
  const ciphertext = await aeadEncrypt(keys.key, nonce, plaintext, aad);

  // Now apply header protection
  // The sample starts 4 bytes after the PN field in the ciphertext
  // Since pnLength can be 1-4 bytes, and we always want sample at offset 4
  // from where PN starts, we need: sampleOffset = 4 - pnLength in the ciphertext
  const sampleStart = 4 - pnLength;
  if (ciphertext.length < sampleStart + 16) {
    throw new Error('Ciphertext too short for header protection');
  }
  const sample = ciphertext.slice(sampleStart, sampleStart + 16);
  const mask = await generateHeaderProtectionMask(keys.hp, sample);

  // Mask the first byte of the header
  const protectedHeader = new Uint8Array(header);
  if (isLongHdr) {
    protectedHeader[0] ^= mask[0] & 0x0f;
  } else {
    protectedHeader[0] ^= mask[0] & 0x1f;
  }

  // Mask the PN bytes
  const protectedPn = new Uint8Array(pnLength);
  for (let i = 0; i < pnLength; i++) {
    protectedPn[i] = pnBytes[i] ^ mask[1 + i];
  }

  // Combine: protected_header + protected_pn + ciphertext
  return concatBytes(protectedHeader, protectedPn, ciphertext);
}

/**
 * Build a QUIC long header (without PN and payload).
 */
export function buildLongHeader(packetType, version, dcid, scid, pnLength, payloadLength, token = null) {
  const buf = new ByteBuffer(128);

  // First byte: 1 (long) | 1 (fixed) | type (2) | reserved (2) | pn_length (2)
  const firstByte = 0xc0 | (packetType << 4) | (pnLength - 1);
  buf.writeUint8(firstByte);

  // Version
  buf.writeUint32(version);

  // DCID
  buf.writeUint8(dcid.length);
  buf.writeBytes(dcid);

  // SCID
  buf.writeUint8(scid.length);
  buf.writeBytes(scid);

  // Token (Initial packets only)
  if (packetType === PacketType.INITIAL) {
    if (token && token.length > 0) {
      buf.writeVarInt(token.length);
      buf.writeBytes(token);
    } else {
      buf.writeVarInt(0);
    }
  }

  // Payload length (includes PN length + ciphertext + tag)
  // This will be pnLength + plaintext.length + 16 (AEAD tag)
  buf.writeVarInt(payloadLength);

  return buf.toUint8Array();
}

/**
 * Build a QUIC short header (1-RTT, without PN).
 */
export function buildShortHeader(dcid, pnLength, spinBit = 0, keyPhase = 0) {
  const buf = new ByteBuffer(1 + dcid.length);

  // First byte: 0 (short) | 1 (fixed) | spin (1) | reserved (2) | key_phase (1) | pn_len (2)
  const firstByte = 0x40 | (spinBit << 5) | (keyPhase << 2) | (pnLength - 1);
  buf.writeUint8(firstByte);

  buf.writeBytes(dcid);

  return buf.toUint8Array();
}

/**
 * Parse a received UDP datagram into one or more QUIC packets.
 * A single UDP datagram can contain multiple QUIC packets (coalesced).
 */
export function parseUdpDatagram(data) {
  const packets = [];
  let offset = 0;

  while (offset < data.length) {
    const remaining = data.slice(offset);
    if (remaining.length === 0) break;

    const firstByte = remaining[0];

    if (isLongHeader(firstByte)) {
      try {
        const parsed = parseLongHeader(remaining);
        packets.push(parsed);
        // For long headers, we can calculate the total size
        if (parsed.packetType !== PacketType.RETRY) {
          offset += parsed.headerLength + parsed.payloadLength;
        } else {
          // Retry packets consume the rest
          offset = data.length;
        }
      } catch (e) {
        // If parsing fails, stop
        break;
      }
    } else {
      // Short header - consumes the rest of the datagram
      // (we can't determine length without decryption)
      packets.push({
        isShort: true,
        raw: remaining,
        firstByte,
      });
      offset = data.length;
    }
  }

  return packets;
}