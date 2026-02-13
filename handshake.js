/**
 * TLS 1.3 Handshake Messages for QUIC (RFC 8446 + RFC 9001)
 *
 * In QUIC, TLS handshake messages are carried in CRYPTO frames
 * (not in TLS records). The TLS record layer is NOT used with QUIC.
 *
 * Handshake message types:
 * - ClientHello (0x01)
 * - ServerHello (0x02)
 * - EncryptedExtensions (0x08)
 * - Certificate (0x0b)
 * - CertificateVerify (0x0f)
 * - Finished (0x14)
 */

import { ByteBuffer, concatBytes } from './byte-buffer.js';
import { CipherSuite } from './tls-crypto.js';

// TLS 1.3 handshake message types
export const HandshakeType = {
  CLIENT_HELLO:          0x01,
  SERVER_HELLO:          0x02,
  ENCRYPTED_EXTENSIONS:  0x08,
  CERTIFICATE:           0x0b,
  CERTIFICATE_VERIFY:    0x0f,
  FINISHED:              0x14,
};

// TLS extension types
export const ExtensionType = {
  SERVER_NAME:             0x0000,
  SUPPORTED_GROUPS:        0x000a,
  SIGNATURE_ALGORITHMS:    0x000d,
  ALPN:                    0x0010,
  SUPPORTED_VERSIONS:      0x002b,
  KEY_SHARE:               0x0033,
  QUIC_TRANSPORT_PARAMS:   0x0039,
};

// Named groups
export const NamedGroup = {
  SECP256R1: 0x0017,
  SECP384R1: 0x0018,
  X25519:    0x001d,
};

// Signature algorithms
export const SignatureScheme = {
  ECDSA_SECP256R1_SHA256: 0x0403,
  ECDSA_SECP384R1_SHA384: 0x0503,
  RSA_PSS_RSAE_SHA256:    0x0804,
};

// TLS 1.3 version
const TLS_VERSION_12 = 0x0303; // Legacy version in ClientHello
const TLS_VERSION_13 = 0x0304;

/**
 * Parse a TLS handshake message from CRYPTO frame data.
 * Returns { type, length, data, raw }
 */
export function parseHandshakeMessage(data) {
  if (data.length < 4) return null;

  const buf = new ByteBuffer(data);
  const type = buf.readUint8();
  const length = buf.readUint24();

  if (buf.remaining < length) {
    return null; // Incomplete message
  }

  const messageData = buf.readBytes(length);
  const raw = data.slice(0, 4 + length);

  return { type, length, data: messageData, raw };
}

/**
 * Parse multiple handshake messages from a buffer (CRYPTO frames can contain multiple).
 */
export function parseHandshakeMessages(data) {
  const messages = [];
  let offset = 0;

  while (offset < data.length) {
    const msg = parseHandshakeMessage(data.slice(offset));
    if (!msg) break;
    messages.push(msg);
    offset += 4 + msg.length;
  }

  return messages;
}

/**
 * Parse a ClientHello message.
 */
export function parseClientHello(data) {
  const buf = new ByteBuffer(data);

  // Legacy version (0x0303 for TLS 1.3 compatibility)
  const legacyVersion = buf.readUint16();

  // Random (32 bytes)
  const random = buf.readBytes(32);

  // Legacy session ID
  const sessionIdLength = buf.readUint8();
  const sessionId = buf.readBytes(sessionIdLength);

  // Cipher suites
  const cipherSuitesLength = buf.readUint16();
  const cipherSuites = [];
  for (let i = 0; i < cipherSuitesLength; i += 2) {
    cipherSuites.push(buf.readUint16());
  }

  // Legacy compression methods
  const compressionMethodsLength = buf.readUint8();
  const compressionMethods = buf.readBytes(compressionMethodsLength);

  // Extensions
  const extensions = parseExtensions(buf);

  return {
    legacyVersion,
    random,
    sessionId,
    cipherSuites,
    compressionMethods,
    extensions,
  };
}

/**
 * Parse TLS extensions from a buffer.
 */
function parseExtensions(buf) {
  const extensions = {};

  if (buf.remaining < 2) return extensions;
  const extensionsLength = buf.readUint16();
  const extensionsEnd = buf.offset + extensionsLength;

  while (buf.offset < extensionsEnd) {
    const extType = buf.readUint16();
    const extLength = buf.readUint16();
    const extData = buf.readBytes(extLength);

    switch (extType) {
      case ExtensionType.SUPPORTED_VERSIONS:
        extensions.supportedVersions = parseSupportedVersionsClient(extData);
        break;

      case ExtensionType.KEY_SHARE:
        extensions.keyShare = parseKeyShareClient(extData);
        break;

      case ExtensionType.SUPPORTED_GROUPS:
        extensions.supportedGroups = parseSupportedGroups(extData);
        break;

      case ExtensionType.SIGNATURE_ALGORITHMS:
        extensions.signatureAlgorithms = parseSignatureAlgorithms(extData);
        break;

      case ExtensionType.ALPN:
        extensions.alpn = parseAlpn(extData);
        break;

      case ExtensionType.SERVER_NAME:
        extensions.serverName = parseServerName(extData);
        break;

      case ExtensionType.QUIC_TRANSPORT_PARAMS:
        extensions.quicTransportParams = parseQuicTransportParams(extData);
        break;

      default:
        // Store raw data for unknown extensions
        if (!extensions.unknown) extensions.unknown = [];
        extensions.unknown.push({ type: extType, data: extData });
        break;
    }
  }

  return extensions;
}

function parseSupportedVersionsClient(data) {
  const buf = new ByteBuffer(data);
  const length = buf.readUint8();
  const versions = [];
  for (let i = 0; i < length; i += 2) {
    versions.push(buf.readUint16());
  }
  return versions;
}

function parseKeyShareClient(data) {
  const buf = new ByteBuffer(data);
  const length = buf.readUint16();
  const entries = [];
  const end = buf.offset + length;

  while (buf.offset < end) {
    const group = buf.readUint16();
    const keyLength = buf.readUint16();
    const keyData = buf.readBytes(keyLength);
    entries.push({ group, keyData });
  }

  return entries;
}

function parseSupportedGroups(data) {
  const buf = new ByteBuffer(data);
  const length = buf.readUint16();
  const groups = [];
  for (let i = 0; i < length; i += 2) {
    groups.push(buf.readUint16());
  }
  return groups;
}

function parseSignatureAlgorithms(data) {
  const buf = new ByteBuffer(data);
  const length = buf.readUint16();
  const algorithms = [];
  for (let i = 0; i < length; i += 2) {
    algorithms.push(buf.readUint16());
  }
  return algorithms;
}

function parseAlpn(data) {
  const buf = new ByteBuffer(data);
  const totalLength = buf.readUint16();
  const protocols = [];

  while (buf.remaining > 0) {
    const len = buf.readUint8();
    const name = new TextDecoder().decode(buf.readBytes(len));
    protocols.push(name);
  }

  return protocols;
}

function parseServerName(data) {
  const buf = new ByteBuffer(data);
  const listLength = buf.readUint16();
  const names = [];

  while (buf.remaining > 0) {
    const nameType = buf.readUint8();
    const nameLength = buf.readUint16();
    const nameData = new TextDecoder().decode(buf.readBytes(nameLength));
    names.push({ type: nameType, name: nameData });
  }

  return names;
}

function parseQuicTransportParams(data) {
  const buf = new ByteBuffer(data);
  const params = {};

  while (buf.remaining > 0) {
    const paramId = buf.readVarInt();
    const paramLength = buf.readVarInt();
    const paramData = buf.readBytes(paramLength);
    params[paramId] = paramData;
  }

  return params;
}

// ===== Serializers =====

/**
 * Build a ServerHello message.
 */
export function buildServerHello(serverRandom, sessionId, cipherSuite, serverKeyShare) {
  const buf = new ByteBuffer(512);

  // Legacy version (TLS 1.2)
  buf.writeUint16(TLS_VERSION_12);

  // Server random
  buf.writeBytes(serverRandom);

  // Session ID (echo client's session ID)
  buf.writeUint8(sessionId.length);
  buf.writeBytes(sessionId);

  // Cipher suite
  buf.writeUint16(cipherSuite);

  // Compression method (null)
  buf.writeUint8(0x00);

  // Extensions
  const extensions = buildServerHelloExtensions(serverKeyShare);
  buf.writeUint16(extensions.length);
  buf.writeBytes(extensions);

  const body = buf.toUint8Array();
  return buildHandshakeMessage(HandshakeType.SERVER_HELLO, body);
}

function buildServerHelloExtensions(serverKeyShare) {
  const buf = new ByteBuffer(256);

  // Supported version extension (TLS 1.3)
  buf.writeUint16(ExtensionType.SUPPORTED_VERSIONS);
  buf.writeUint16(2); // length
  buf.writeUint16(TLS_VERSION_13);

  // Key share extension
  buf.writeUint16(ExtensionType.KEY_SHARE);
  const keyShareData = new ByteBuffer(128);
  keyShareData.writeUint16(NamedGroup.SECP256R1);
  keyShareData.writeUint16(serverKeyShare.length);
  keyShareData.writeBytes(serverKeyShare);
  const keyShareBytes = keyShareData.toUint8Array();
  buf.writeUint16(keyShareBytes.length);
  buf.writeBytes(keyShareBytes);

  return buf.toUint8Array();
}

/**
 * Build an EncryptedExtensions message.
 */
export function buildEncryptedExtensions(alpnProtocol = 'h3', transportParams = null) {
  const buf = new ByteBuffer(512);

  // Build extensions list
  const extBuf = new ByteBuffer(512);

  // ALPN extension
  extBuf.writeUint16(ExtensionType.ALPN);
  const alpnBuf = new ByteBuffer(64);
  const alpnBytes = new TextEncoder().encode(alpnProtocol);
  const alpnListLen = 1 + alpnBytes.length;
  alpnBuf.writeUint16(alpnListLen);
  alpnBuf.writeUint8(alpnBytes.length);
  alpnBuf.writeBytes(alpnBytes);
  const alpnData = alpnBuf.toUint8Array();
  extBuf.writeUint16(alpnData.length);
  extBuf.writeBytes(alpnData);

  // QUIC transport parameters
  if (transportParams) {
    extBuf.writeUint16(ExtensionType.QUIC_TRANSPORT_PARAMS);
    extBuf.writeUint16(transportParams.length);
    extBuf.writeBytes(transportParams);
  }

  const extensions = extBuf.toUint8Array();
  buf.writeUint16(extensions.length);
  buf.writeBytes(extensions);

  const body = buf.toUint8Array();
  return buildHandshakeMessage(HandshakeType.ENCRYPTED_EXTENSIONS, body);
}

/**
 * Build a Certificate message.
 */
export function buildCertificateMessage(certificates, requestContext = new Uint8Array(0)) {
  const buf = new ByteBuffer(4096);

  // Certificate request context
  buf.writeUint8(requestContext.length);
  if (requestContext.length > 0) {
    buf.writeBytes(requestContext);
  }

  // Certificate list
  const certListBuf = new ByteBuffer(4096);
  for (const cert of certificates) {
    // CertificateEntry
    certListBuf.writeUint24(cert.length);
    certListBuf.writeBytes(cert);
    // Extensions (empty)
    certListBuf.writeUint16(0);
  }
  const certList = certListBuf.toUint8Array();

  buf.writeUint24(certList.length);
  buf.writeBytes(certList);

  const body = buf.toUint8Array();
  return buildHandshakeMessage(HandshakeType.CERTIFICATE, body);
}

/**
 * Build a CertificateVerify message.
 */
export function buildCertificateVerify(signatureScheme, signature) {
  const buf = new ByteBuffer(signature.length + 4);

  buf.writeUint16(signatureScheme);
  buf.writeUint16(signature.length);
  buf.writeBytes(signature);

  const body = buf.toUint8Array();
  return buildHandshakeMessage(HandshakeType.CERTIFICATE_VERIFY, body);
}

/**
 * Build a Finished message.
 */
export function buildFinished(verifyData) {
  return buildHandshakeMessage(HandshakeType.FINISHED, verifyData);
}

/**
 * Wrap handshake data in a handshake message header.
 */
function buildHandshakeMessage(type, body) {
  const msg = new Uint8Array(4 + body.length);
  msg[0] = type;
  msg[1] = (body.length >> 16) & 0xff;
  msg[2] = (body.length >> 8) & 0xff;
  msg[3] = body.length & 0xff;
  msg.set(body, 4);
  return msg;
}

/**
 * Encode QUIC transport parameters for use in TLS extensions.
 */
export function encodeQuicTransportParams(params) {
  const buf = new ByteBuffer(256);

  function writeParam(id, value) {
    buf.writeVarInt(id);
    const encodedValue = ByteBuffer.encodeVarInt(value);
    buf.writeVarInt(encodedValue.length);
    buf.writeBytes(encodedValue);
  }

  function writeParamRaw(id, data) {
    buf.writeVarInt(id);
    buf.writeVarInt(data.length);
    buf.writeBytes(data);
  }

  const { TransportParamId } = require('./constants.js'); // Avoid circular

  if (params.originalDestinationConnectionId) {
    writeParamRaw(0x00, params.originalDestinationConnectionId);
  }
  if (params.maxIdleTimeout !== undefined) {
    writeParam(0x01, params.maxIdleTimeout);
  }
  if (params.statelessResetToken) {
    writeParamRaw(0x02, params.statelessResetToken);
  }
  if (params.maxUdpPayloadSize !== undefined) {
    writeParam(0x03, params.maxUdpPayloadSize);
  }
  if (params.initialMaxData !== undefined) {
    writeParam(0x04, params.initialMaxData);
  }
  if (params.initialMaxStreamDataBidiLocal !== undefined) {
    writeParam(0x05, params.initialMaxStreamDataBidiLocal);
  }
  if (params.initialMaxStreamDataBidiRemote !== undefined) {
    writeParam(0x06, params.initialMaxStreamDataBidiRemote);
  }
  if (params.initialMaxStreamDataUni !== undefined) {
    writeParam(0x07, params.initialMaxStreamDataUni);
  }
  if (params.initialMaxStreamsBidi !== undefined) {
    writeParam(0x08, params.initialMaxStreamsBidi);
  }
  if (params.initialMaxStreamsUni !== undefined) {
    writeParam(0x09, params.initialMaxStreamsUni);
  }
  if (params.activeConnectionIdLimit !== undefined) {
    writeParam(0x0e, params.activeConnectionIdLimit);
  }
  if (params.initialSourceConnectionId) {
    writeParamRaw(0x0f, params.initialSourceConnectionId);
  }
  if (params.maxDatagramFrameSize !== undefined) {
    writeParam(0x0020, params.maxDatagramFrameSize);
  }

  return buf.toUint8Array();
}

/**
 * Encode transport params without require() - using inline IDs.
 */
export function encodeTransportParams(params) {
  const buf = new ByteBuffer(512);

  function writeVarIntParam(id, value) {
    const encoded = ByteBuffer.encodeVarInt(value);
    buf.writeVarInt(id);
    buf.writeVarInt(encoded.length);
    buf.writeBytes(encoded);
  }

  function writeRawParam(id, data) {
    buf.writeVarInt(id);
    buf.writeVarInt(data.length);
    buf.writeBytes(data);
  }

  function writeEmptyParam(id) {
    buf.writeVarInt(id);
    buf.writeVarInt(0);
  }

  if (params.originalDestinationConnectionId) writeRawParam(0x00, params.originalDestinationConnectionId);
  if (params.maxIdleTimeout !== undefined) writeVarIntParam(0x01, params.maxIdleTimeout);
  if (params.statelessResetToken) writeRawParam(0x02, params.statelessResetToken);
  if (params.maxUdpPayloadSize !== undefined) writeVarIntParam(0x03, params.maxUdpPayloadSize);
  if (params.initialMaxData !== undefined) writeVarIntParam(0x04, params.initialMaxData);
  if (params.initialMaxStreamDataBidiLocal !== undefined) writeVarIntParam(0x05, params.initialMaxStreamDataBidiLocal);
  if (params.initialMaxStreamDataBidiRemote !== undefined) writeVarIntParam(0x06, params.initialMaxStreamDataBidiRemote);
  if (params.initialMaxStreamDataUni !== undefined) writeVarIntParam(0x07, params.initialMaxStreamDataUni);
  if (params.initialMaxStreamsBidi !== undefined) writeVarIntParam(0x08, params.initialMaxStreamsBidi);
  if (params.initialMaxStreamsUni !== undefined) writeVarIntParam(0x09, params.initialMaxStreamsUni);
  if (params.disableActiveMigration) writeEmptyParam(0x0c);
  if (params.activeConnectionIdLimit !== undefined) writeVarIntParam(0x0e, params.activeConnectionIdLimit);
  if (params.initialSourceConnectionId) writeRawParam(0x0f, params.initialSourceConnectionId);
  if (params.maxDatagramFrameSize !== undefined) writeVarIntParam(0x0020, params.maxDatagramFrameSize);

  return buf.toUint8Array();
}