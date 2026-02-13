/**
 * QUIC Frame Parser and Serializer (RFC 9000 Section 19)
 *
 * QUIC packets contain one or more frames. Each frame has a type-specific format.
 */

import { ByteBuffer } from './byte-buffer.js';
import { FrameType } from './constants.js';

/**
 * Parse all frames from a decrypted QUIC packet payload.
 */
export function parseFrames(data) {
  const buf = new ByteBuffer(data);
  const frames = [];

  while (buf.remaining > 0) {
    const frameType = buf.readVarInt();

    switch (frameType) {
      case FrameType.PADDING:
        // Padding frames are single zero bytes; skip consecutive padding
        while (buf.remaining > 0 && buf.buffer[buf.offset] === 0) {
          buf.offset++;
        }
        frames.push({ type: FrameType.PADDING });
        break;

      case FrameType.PING:
        frames.push({ type: FrameType.PING });
        break;

      case FrameType.ACK:
      case FrameType.ACK_ECN:
        frames.push(parseAckFrame(buf, frameType));
        break;

      case FrameType.CRYPTO:
        frames.push(parseCryptoFrame(buf));
        break;

      case FrameType.NEW_TOKEN:
        frames.push(parseNewTokenFrame(buf));
        break;

      case FrameType.RESET_STREAM:
        frames.push(parseResetStreamFrame(buf));
        break;

      case FrameType.STOP_SENDING:
        frames.push(parseStopSendingFrame(buf));
        break;

      case FrameType.MAX_DATA:
        frames.push({ type: FrameType.MAX_DATA, maxData: buf.readVarInt() });
        break;

      case FrameType.MAX_STREAM_DATA:
        frames.push({
          type: FrameType.MAX_STREAM_DATA,
          streamId: buf.readVarInt(),
          maxStreamData: buf.readVarInt(),
        });
        break;

      case FrameType.MAX_STREAMS_BIDI:
        frames.push({ type: FrameType.MAX_STREAMS_BIDI, maxStreams: buf.readVarInt() });
        break;

      case FrameType.MAX_STREAMS_UNI:
        frames.push({ type: FrameType.MAX_STREAMS_UNI, maxStreams: buf.readVarInt() });
        break;

      case FrameType.DATA_BLOCKED:
        frames.push({ type: FrameType.DATA_BLOCKED, limit: buf.readVarInt() });
        break;

      case FrameType.STREAM_DATA_BLOCKED:
        frames.push({
          type: FrameType.STREAM_DATA_BLOCKED,
          streamId: buf.readVarInt(),
          limit: buf.readVarInt(),
        });
        break;

      case FrameType.STREAMS_BLOCKED_BIDI:
        frames.push({ type: FrameType.STREAMS_BLOCKED_BIDI, limit: buf.readVarInt() });
        break;

      case FrameType.STREAMS_BLOCKED_UNI:
        frames.push({ type: FrameType.STREAMS_BLOCKED_UNI, limit: buf.readVarInt() });
        break;

      case FrameType.NEW_CONNECTION_ID:
        frames.push(parseNewConnectionIdFrame(buf));
        break;

      case FrameType.RETIRE_CONNECTION_ID:
        frames.push({ type: FrameType.RETIRE_CONNECTION_ID, sequenceNumber: buf.readVarInt() });
        break;

      case FrameType.PATH_CHALLENGE:
        frames.push({ type: FrameType.PATH_CHALLENGE, data: buf.readBytes(8) });
        break;

      case FrameType.PATH_RESPONSE:
        frames.push({ type: FrameType.PATH_RESPONSE, data: buf.readBytes(8) });
        break;

      case FrameType.CONNECTION_CLOSE:
      case FrameType.CONNECTION_CLOSE_APP:
        frames.push(parseConnectionCloseFrame(buf, frameType));
        break;

      case FrameType.HANDSHAKE_DONE:
        frames.push({ type: FrameType.HANDSHAKE_DONE });
        break;

      case FrameType.DATAGRAM:
      case FrameType.DATAGRAM_LEN:
        frames.push(parseDatagramFrame(buf, frameType));
        break;

      default:
        // Check if it's a STREAM frame (0x08 - 0x0f)
        if (frameType >= 0x08 && frameType <= 0x0f) {
          frames.push(parseStreamFrame(buf, frameType));
        } else {
          // Unknown frame type - skip based on remaining data
          // In a production implementation, we should handle this more carefully
          console.warn(`Unknown frame type: 0x${frameType.toString(16)}`);
          return frames; // Stop parsing
        }
        break;
    }
  }

  return frames;
}

function parseAckFrame(buf, type) {
  const largestAcked = buf.readVarInt();
  const ackDelay = buf.readVarInt();
  const ackRangeCount = buf.readVarInt();
  const firstAckRange = buf.readVarInt();

  const ackRanges = [];
  let smallest = largestAcked - firstAckRange;

  for (let i = 0; i < ackRangeCount; i++) {
    const gap = buf.readVarInt();
    const rangeLength = buf.readVarInt();
    smallest = smallest - gap - 2;
    ackRanges.push({ gap, rangeLength });
  }

  const frame = {
    type,
    largestAcked,
    ackDelay,
    ackRangeCount,
    firstAckRange,
    ackRanges,
  };

  if (type === FrameType.ACK_ECN) {
    frame.ect0Count = buf.readVarInt();
    frame.ect1Count = buf.readVarInt();
    frame.ecnCeCount = buf.readVarInt();
  }

  return frame;
}

function parseCryptoFrame(buf) {
  const offset = buf.readVarInt();
  const length = buf.readVarInt();
  const data = buf.readBytes(length);

  return {
    type: FrameType.CRYPTO,
    offset,
    length,
    data,
  };
}

function parseNewTokenFrame(buf) {
  const length = buf.readVarInt();
  const token = buf.readBytes(length);
  return { type: FrameType.NEW_TOKEN, token };
}

function parseResetStreamFrame(buf) {
  return {
    type: FrameType.RESET_STREAM,
    streamId: buf.readVarInt(),
    errorCode: buf.readVarInt(),
    finalSize: buf.readVarInt(),
  };
}

function parseStopSendingFrame(buf) {
  return {
    type: FrameType.STOP_SENDING,
    streamId: buf.readVarInt(),
    errorCode: buf.readVarInt(),
  };
}

function parseStreamFrame(buf, frameType) {
  const hasOffset = (frameType & 0x04) !== 0;
  const hasLength = (frameType & 0x02) !== 0;
  const isFin = (frameType & 0x01) !== 0;

  const streamId = buf.readVarInt();
  const offset = hasOffset ? buf.readVarInt() : 0;

  let data;
  if (hasLength) {
    const length = buf.readVarInt();
    data = buf.readBytes(length);
  } else {
    data = buf.readRemainingBytes();
  }

  return {
    type: FrameType.STREAM,
    streamId,
    offset,
    data,
    fin: isFin,
  };
}

function parseNewConnectionIdFrame(buf) {
  const sequenceNumber = buf.readVarInt();
  const retirePriorTo = buf.readVarInt();
  const cidLength = buf.readUint8();
  const connectionId = buf.readBytes(cidLength);
  const statelessResetToken = buf.readBytes(16);

  return {
    type: FrameType.NEW_CONNECTION_ID,
    sequenceNumber,
    retirePriorTo,
    connectionId,
    statelessResetToken,
  };
}

function parseConnectionCloseFrame(buf, type) {
  const errorCode = buf.readVarInt();
  let triggerFrameType;

  if (type === FrameType.CONNECTION_CLOSE) {
    triggerFrameType = buf.readVarInt();
  }

  const reasonPhraseLength = buf.readVarInt();
  const reasonPhrase = reasonPhraseLength > 0
    ? new TextDecoder().decode(buf.readBytes(reasonPhraseLength))
    : '';

  return {
    type,
    errorCode,
    triggerFrameType,
    reasonPhrase,
  };
}

function parseDatagramFrame(buf, type) {
  let data;
  if (type === FrameType.DATAGRAM_LEN) {
    const length = buf.readVarInt();
    data = buf.readBytes(length);
  } else {
    data = buf.readRemainingBytes();
  }

  return { type, data };
}

// ===== Frame Serializers =====

/**
 * Serialize a CRYPTO frame.
 */
export function serializeCryptoFrame(offset, data) {
  const buf = new ByteBuffer(
    ByteBuffer.varIntSize(FrameType.CRYPTO) +
    ByteBuffer.varIntSize(offset) +
    ByteBuffer.varIntSize(data.length) +
    data.length
  );
  buf.writeVarInt(FrameType.CRYPTO);
  buf.writeVarInt(offset);
  buf.writeVarInt(data.length);
  buf.writeBytes(data);
  return buf.toUint8Array();
}

/**
 * Serialize an ACK frame.
 */
export function serializeAckFrame(largestAcked, ackDelay, ranges = []) {
  const firstRange = ranges.length > 0 ? ranges[0] : largestAcked;
  const additionalRanges = ranges.length > 1 ? ranges.slice(1) : [];

  const buf = new ByteBuffer(128);
  buf.writeVarInt(FrameType.ACK);
  buf.writeVarInt(largestAcked);
  buf.writeVarInt(ackDelay);
  buf.writeVarInt(additionalRanges.length);
  buf.writeVarInt(firstRange);

  for (const range of additionalRanges) {
    buf.writeVarInt(range.gap);
    buf.writeVarInt(range.rangeLength);
  }

  return buf.toUint8Array();
}

/**
 * Serialize a STREAM frame.
 */
export function serializeStreamFrame(streamId, offset, data, fin = false) {
  let flags = 0x08; // Base STREAM type
  if (offset > 0) flags |= 0x04; // OFF bit
  flags |= 0x02; // LEN bit (always include length)
  if (fin) flags |= 0x01; // FIN bit

  const buf = new ByteBuffer(
    ByteBuffer.varIntSize(flags) +
    ByteBuffer.varIntSize(streamId) +
    (offset > 0 ? ByteBuffer.varIntSize(offset) : 0) +
    ByteBuffer.varIntSize(data.length) +
    data.length
  );

  buf.writeVarInt(flags);
  buf.writeVarInt(streamId);
  if (offset > 0) buf.writeVarInt(offset);
  buf.writeVarInt(data.length);
  buf.writeBytes(data);

  return buf.toUint8Array();
}

/**
 * Serialize a CONNECTION_CLOSE frame.
 */
export function serializeConnectionCloseFrame(errorCode, reasonPhrase = '', isApp = false) {
  const reasonBytes = new TextEncoder().encode(reasonPhrase);
  const type = isApp ? FrameType.CONNECTION_CLOSE_APP : FrameType.CONNECTION_CLOSE;

  const buf = new ByteBuffer(128);
  buf.writeVarInt(type);
  buf.writeVarInt(errorCode);
  if (!isApp) {
    buf.writeVarInt(0); // trigger frame type
  }
  buf.writeVarInt(reasonBytes.length);
  if (reasonBytes.length > 0) {
    buf.writeBytes(reasonBytes);
  }

  return buf.toUint8Array();
}

/**
 * Serialize a HANDSHAKE_DONE frame.
 */
export function serializeHandshakeDoneFrame() {
  const buf = new ByteBuffer(1);
  buf.writeVarInt(FrameType.HANDSHAKE_DONE);
  return buf.toUint8Array();
}

/**
 * Serialize a PING frame.
 */
export function serializePingFrame() {
  return ByteBuffer.encodeVarInt(FrameType.PING);
}

/**
 * Serialize a DATAGRAM frame.
 */
export function serializeDatagramFrame(data) {
  const buf = new ByteBuffer(
    ByteBuffer.varIntSize(FrameType.DATAGRAM_LEN) +
    ByteBuffer.varIntSize(data.length) +
    data.length
  );
  buf.writeVarInt(FrameType.DATAGRAM_LEN);
  buf.writeVarInt(data.length);
  buf.writeBytes(data);
  return buf.toUint8Array();
}

/**
 * Serialize a MAX_DATA frame.
 */
export function serializeMaxDataFrame(maxData) {
  const buf = new ByteBuffer(16);
  buf.writeVarInt(FrameType.MAX_DATA);
  buf.writeVarInt(maxData);
  return buf.toUint8Array();
}

/**
 * Serialize a MAX_STREAM_DATA frame.
 */
export function serializeMaxStreamDataFrame(streamId, maxStreamData) {
  const buf = new ByteBuffer(24);
  buf.writeVarInt(FrameType.MAX_STREAM_DATA);
  buf.writeVarInt(streamId);
  buf.writeVarInt(maxStreamData);
  return buf.toUint8Array();
}

/**
 * Serialize a NEW_CONNECTION_ID frame.
 */
export function serializeNewConnectionIdFrame(seqNum, retirePriorTo, connId, resetToken) {
  const buf = new ByteBuffer(64);
  buf.writeVarInt(FrameType.NEW_CONNECTION_ID);
  buf.writeVarInt(seqNum);
  buf.writeVarInt(retirePriorTo);
  buf.writeUint8(connId.length);
  buf.writeBytes(connId);
  buf.writeBytes(resetToken);
  return buf.toUint8Array();
}

/**
 * Create PADDING frames to fill a packet to a certain size.
 */
export function createPadding(size) {
  return new Uint8Array(size); // All zeros = PADDING frames
}