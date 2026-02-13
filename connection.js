/**
 * QUIC Connection (RFC 9000)
 *
 * Manages the full lifecycle of a QUIC connection including:
 * - Handshake via TLS 1.3
 * - Packet encryption/decryption at all levels
 * - Stream multiplexing
 * - Flow control
 * - Loss detection and recovery (simplified)
 * - Connection close
 */

import { EventEmitter } from './event-emitter.js';
import { ByteBuffer, concatBytes, randomBytes, bytesToHex } from './byte-buffer.js';
import {
  ConnectionState,
  EncryptionLevel,
  PacketType,
  FrameType,
  TransportError,
  QUIC_VERSION_1,
  DEFAULT_SERVER_TRANSPORT_PARAMS,
} from './constants.js';
import {
  parseLongHeader,
  parseShortHeader,
  unprotectPacket,
  protectPacket,
  buildLongHeader,
  buildShortHeader,
  isLongHeader,
  getLongHeaderType,
} from './packet.js';
import {
  parseFrames,
  serializeCryptoFrame,
  serializeAckFrame,
  serializeStreamFrame,
  serializeConnectionCloseFrame,
  serializeHandshakeDoneFrame,
  serializeDatagramFrame,
  serializePingFrame,
  createPadding,
} from './frames.js';
import {
  deriveInitialSecrets,
  derivePacketKeys,
  CipherSuite,
} from './tls-crypto.js';
import { TlsServer } from './tls-server.js';
import { StreamManager, QuicStream } from './streams.js';

/**
 * Represents a single QUIC connection.
 */
export class QuicConnection extends EventEmitter {
  constructor(options) {
    super();

    // Connection IDs
    this.localConnId = options.localConnId || randomBytes(8);
    this.remoteConnId = options.remoteConnId;
    this.originalDestConnId = options.originalDestConnId;

    // Remote address
    this.remoteAddr = options.remoteAddr;
    this.remotePort = options.remotePort;

    // Send callback
    this._sendPacket = options.sendPacket;

    // State
    this.state = ConnectionState.IDLE;
    this.version = QUIC_VERSION_1;

    // TLS
    this.tls = null;

    // Keys at each encryption level
    this.keys = {
      initial: null,
      handshake: null,
      '1-rtt': null,
    };

    // Packet numbers (per encryption level)
    this.sendPacketNumber = {
      initial: 0,
      handshake: 0,
      '1-rtt': 0,
    };
    this.largestRecvPacketNumber = {
      initial: -1,
      handshake: -1,
      '1-rtt': -1,
    };

    // ACK tracking
    this.packetsToAck = {
      initial: [],
      handshake: [],
      '1-rtt': [],
    };

    // Streams
    this.streamManager = new StreamManager(this);

    // Transport parameters
    this.localParams = { ...DEFAULT_SERVER_TRANSPORT_PARAMS };
    this.peerParams = {};

    // CRYPTO frame buffer per level
    this.cryptoRecvBuffer = {
      initial: { offset: 0, data: new Uint8Array(0) },
      handshake: { offset: 0, data: new Uint8Array(0) },
    };
    this.cryptoSendOffset = {
      initial: 0,
      handshake: 0,
    };

    // Idle timeout
    this.lastActivity = Date.now();
    this.idleTimer = null;

    // Close info
    this.closeError = null;
    this.closeReason = '';
  }

  /**
   * Initialize the connection (derive initial keys, set up TLS).
   */
  async init() {
    this.state = ConnectionState.HANDSHAKE;

    // Derive Initial encryption keys
    const { clientSecret, serverSecret } = await deriveInitialSecrets(this.originalDestConnId);
    this.keys.initial = {
      client: await derivePacketKeys(clientSecret),
      server: await derivePacketKeys(serverSecret),
    };

    // Set up TLS server
    this.tls = new TlsServer({
      transportParams: {
        ...this.localParams,
        originalDestinationConnectionId: this.originalDestConnId,
        initialSourceConnectionId: this.localConnId,
      },
    });
    await this.tls.init();

    // Start idle timeout
    this._resetIdleTimer();

    // Set up stream events
    this.streamManager.on('stream', (stream) => {
      this.emit('stream', stream);
    });
  }

  /**
   * Process a received UDP datagram.
   */
  async processPacket(data) {
    this.lastActivity = Date.now();
    this._resetIdleTimer();

    try {
      const firstByte = data[0];

      if (isLongHeader(firstByte)) {
        await this._processLongHeaderPacket(data);
      } else {
        await this._processShortHeaderPacket(data);
      }
    } catch (err) {
      console.error('Error processing packet:', err);
      this.emit('error', err);
    }
  }

  /**
   * Process a long header QUIC packet.
   */
  async _processLongHeaderPacket(data) {
    const parsed = parseLongHeader(data);

    if (parsed.version !== QUIC_VERSION_1) {
      console.warn(`Unsupported QUIC version: 0x${parsed.version.toString(16)}`);
      return;
    }

    let level, keys;
    switch (parsed.packetType) {
      case PacketType.INITIAL:
        level = EncryptionLevel.INITIAL;
        keys = this.keys.initial;
        break;
      case PacketType.HANDSHAKE:
        level = EncryptionLevel.HANDSHAKE;
        keys = this.keys.handshake;
        break;
      case PacketType.ZERO_RTT:
        level = EncryptionLevel.ZERO_RTT;
        console.warn('0-RTT packets not supported');
        return;
      default:
        console.warn(`Unknown packet type: ${parsed.packetType}`);
        return;
    }

    if (!keys) {
      console.warn(`No keys for level ${level}, dropping packet`);
      return;
    }

    // Decrypt the packet
    const decrypted = await unprotectPacket(parsed, keys.client, true);

    // Track for ACK
    if (decrypted.packetNumber > this.largestRecvPacketNumber[level]) {
      this.largestRecvPacketNumber[level] = decrypted.packetNumber;
    }
    this.packetsToAck[level].push(decrypted.packetNumber);

    // Parse and process frames
    const frames = parseFrames(decrypted.plaintext);
    await this._processFrames(frames, level);
  }

  /**
   * Process a short header (1-RTT) QUIC packet.
   */
  async _processShortHeaderPacket(data) {
    const level = '1-rtt';
    const keys = this.keys['1-rtt'];

    if (!keys) {
      console.warn('No 1-RTT keys, dropping packet');
      return;
    }

    const parsed = parseShortHeader(data, this.localConnId.length);
    const decrypted = await unprotectPacket(parsed, keys.client, false);

    if (decrypted.packetNumber > this.largestRecvPacketNumber[level]) {
      this.largestRecvPacketNumber[level] = decrypted.packetNumber;
    }
    this.packetsToAck[level].push(decrypted.packetNumber);

    const frames = parseFrames(decrypted.plaintext);
    await this._processFrames(frames, level);
  }

  /**
   * Process parsed QUIC frames.
   */
  async _processFrames(frames, level) {
    for (const frame of frames) {
      switch (frame.type) {
        case FrameType.PADDING:
        case FrameType.PING:
          break;

        case FrameType.ACK:
        case FrameType.ACK_ECN:
          this._processAck(frame, level);
          break;

        case FrameType.CRYPTO:
          await this._processCryptoFrame(frame, level);
          break;

        case FrameType.STREAM:
          this._processStreamFrame(frame);
          break;

        case FrameType.MAX_DATA:
          // Update connection-level flow control
          break;

        case FrameType.MAX_STREAM_DATA:
          this._processMaxStreamData(frame);
          break;

        case FrameType.MAX_STREAMS_BIDI:
        case FrameType.MAX_STREAMS_UNI:
          // Update stream limits
          break;

        case FrameType.CONNECTION_CLOSE:
        case FrameType.CONNECTION_CLOSE_APP:
          this._processConnectionClose(frame);
          break;

        case FrameType.HANDSHAKE_DONE:
          // Server doesn't receive this (it sends it)
          break;

        case FrameType.DATAGRAM:
        case FrameType.DATAGRAM_LEN:
          this.emit('datagram', frame.data);
          break;

        case FrameType.NEW_CONNECTION_ID:
          // Store the peer's new connection ID
          break;

        case FrameType.PATH_CHALLENGE:
          // Respond with PATH_RESPONSE
          await this._sendPathResponse(frame.data);
          break;

        default:
          console.warn(`Unhandled frame type: 0x${frame.type.toString(16)}`);
      }
    }

    // Send any pending ACKs
    await this._sendPendingAcks(level);
  }

  /**
   * Process a CRYPTO frame and advance the TLS handshake.
   */
  async _processCryptoFrame(frame, level) {
    const buf = this.cryptoRecvBuffer[level];
    if (!buf) return;

    // For simplicity, assume in-order delivery for now
    // A production impl would handle out-of-order CRYPTO frames
    const cryptoData = frame.data;

    // Feed to TLS
    const tlsOutput = await this.tls.processCryptoData(cryptoData, level);

    for (const msg of tlsOutput) {
      if (msg.level === 'initial') {
        await this._sendCryptoData(msg.data, 'initial');
      } else if (msg.level === 'handshake') {
        // We need handshake keys before sending at handshake level
        if (!this.keys.handshake && this.tls.handshakeKeys) {
          this.keys.handshake = this.tls.handshakeKeys;
        }
        await this._sendCryptoData(msg.data, 'handshake');
      }
    }

    // Check if handshake is complete
    if (this.tls.isConnected && this.state === ConnectionState.HANDSHAKE) {
      // Set 1-RTT keys
      if (this.tls.applicationKeys) {
        this.keys['1-rtt'] = this.tls.applicationKeys;
      }

      this.state = ConnectionState.CONNECTED;

      // Send HANDSHAKE_DONE frame
      await this._sendHandshakeDone();

      this.emit('connected');
    }
  }

  /**
   * Process a STREAM frame.
   */
  _processStreamFrame(frame) {
    const stream = this.streamManager.getOrCreateStream(frame.streamId);
    stream._receiveData(frame.offset, frame.data, frame.fin);
  }

  /**
   * Process a MAX_STREAM_DATA frame.
   */
  _processMaxStreamData(frame) {
    const stream = this.streamManager.streams.get(frame.streamId);
    if (stream) {
      stream.maxSendData = Math.max(stream.maxSendData, frame.maxStreamData);
    }
  }

  /**
   * Process ACK frame.
   */
  _processAck(frame, level) {
    // Simplified: just note that packets were acknowledged
    // A production implementation would handle retransmission, congestion control, etc.
  }

  /**
   * Process CONNECTION_CLOSE.
   */
  _processConnectionClose(frame) {
    this.state = ConnectionState.DRAINING;
    this.closeError = frame.errorCode;
    this.closeReason = frame.reasonPhrase;
    this.emit('close', { errorCode: frame.errorCode, reason: frame.reasonPhrase });

    // Enter draining period, then fully close
    setTimeout(() => {
      this.state = ConnectionState.CLOSED;
      this._cleanup();
    }, 3000);
  }

  // ===== Sending =====

  /**
   * Send CRYPTO frame data at a specific encryption level.
   */
  async _sendCryptoData(data, level) {
    const cryptoFrame = serializeCryptoFrame(this.cryptoSendOffset[level] || 0, data);
    if (this.cryptoSendOffset[level] !== undefined) {
      this.cryptoSendOffset[level] += data.length;
    }

    // Build the ACK frame if we have packets to acknowledge
    const ackFrame = this._buildAckFrame(level);
    const payload = ackFrame ? concatBytes(ackFrame, cryptoFrame) : cryptoFrame;

    await this._sendAtLevel(payload, level);
  }

  /**
   * Send data at a specific encryption level.
   */
  async _sendAtLevel(payload, level) {
    const keys = this.keys[level];
    if (!keys) {
      console.error(`No keys for level: ${level}`);
      return;
    }

    const pnLength = 2; // Use 2-byte packet numbers
    const packetNumber = this.sendPacketNumber[level]++;

    let packet;
    if (level === 'initial' || level === 'handshake') {
      const packetType = level === 'initial' ? PacketType.INITIAL : PacketType.HANDSHAKE;

      // Calculate the payload length for the header
      // payloadLength = pnLength + payload.length + AEAD_TAG_LENGTH(16)
      const payloadLength = pnLength + payload.length + 16;

      // Build long header
      const header = buildLongHeader(
        packetType, this.version,
        this.remoteConnId, this.localConnId,
        pnLength, payloadLength,
        level === 'initial' ? null : undefined
      );

      // For Initial packets, pad to at least 1200 bytes
      let paddedPayload = payload;
      if (level === 'initial') {
        const minSize = 1200;
        const currentSize = header.length + payloadLength;
        if (currentSize < minSize) {
          const paddingNeeded = minSize - currentSize;
          paddedPayload = concatBytes(payload, createPadding(paddingNeeded));
          // Recalculate payload length with padding
          const newPayloadLength = pnLength + paddedPayload.length + 16;
          const newHeader = buildLongHeader(
            packetType, this.version,
            this.remoteConnId, this.localConnId,
            pnLength, newPayloadLength,
            null
          );
          packet = await protectPacket(newHeader, packetNumber, pnLength, paddedPayload, keys.server, true);
          await this._send(packet);
          return;
        }
      }

      packet = await protectPacket(header, packetNumber, pnLength, paddedPayload, keys.server, true);
    } else {
      // Short header (1-RTT)
      const header = buildShortHeader(this.remoteConnId, pnLength);
      packet = await protectPacket(header, packetNumber, pnLength, payload, keys.server, false);
    }

    await this._send(packet);
  }

  /**
   * Send a HANDSHAKE_DONE frame.
   */
  async _sendHandshakeDone() {
    const frame = serializeHandshakeDoneFrame();
    await this._sendAtLevel(frame, '1-rtt');
  }

  /**
   * Send a PATH_RESPONSE.
   */
  async _sendPathResponse(challengeData) {
    const buf = new ByteBuffer(16);
    buf.writeVarInt(FrameType.PATH_RESPONSE);
    buf.writeBytes(challengeData);
    await this._sendAtLevel(buf.toUint8Array(), '1-rtt');
  }

  /**
   * Send pending ACKs for a level.
   */
  async _sendPendingAcks(level) {
    const ackFrame = this._buildAckFrame(level);
    if (ackFrame && level !== 'initial') {
      // For non-initial levels, send a standalone ACK if we didn't already
      // (Initial ACKs are piggybacked on other packets)
    }
  }

  /**
   * Build an ACK frame from pending packet numbers.
   */
  _buildAckFrame(level) {
    const packets = this.packetsToAck[level];
    if (!packets || packets.length === 0) return null;

    const largest = Math.max(...packets);
    const ackFrame = serializeAckFrame(largest, 0, [largest]); // Simplified: single range

    // Clear pending ACKs
    this.packetsToAck[level] = [];

    return ackFrame;
  }

  /**
   * Send a datagram (WebTransport DATAGRAM frame).
   */
  async sendDatagram(data) {
    if (this.state !== ConnectionState.CONNECTED) {
      throw new Error('Connection not ready');
    }
    const frame = serializeDatagramFrame(data);
    await this._sendAtLevel(frame, '1-rtt');
  }

  /**
   * Send stream data.
   */
  async sendStreamData(streamId, offset, data, fin) {
    if (this.state !== ConnectionState.CONNECTED) {
      throw new Error('Connection not ready');
    }
    const frame = serializeStreamFrame(streamId, offset, data, fin);
    await this._sendAtLevel(frame, '1-rtt');
  }

  /**
   * Called when a stream has data ready to send.
   */
  async _onStreamDataReady(streamId) {
    const stream = this.streamManager.streams.get(streamId);
    if (!stream) return;

    const pending = stream._getPendingData(1200 - 100); // Leave room for headers
    if (pending) {
      await this.sendStreamData(streamId, pending.offset, pending.data, pending.fin);
    }
  }

  /**
   * Called when a stream is reset.
   */
  _onStreamReset(streamId, errorCode) {
    // Send RESET_STREAM frame
    // TODO: implement
  }

  /**
   * Close the connection.
   */
  async close(errorCode = 0, reason = '') {
    if (this.state === ConnectionState.CLOSED || this.state === ConnectionState.CLOSING) {
      return;
    }

    this.state = ConnectionState.CLOSING;
    const level = this.keys['1-rtt'] ? '1-rtt' : 'initial';
    const frame = serializeConnectionCloseFrame(errorCode, reason);

    try {
      await this._sendAtLevel(frame, level);
    } catch (e) {
      // Best effort
    }

    // Enter closing period
    setTimeout(() => {
      this.state = ConnectionState.CLOSED;
      this._cleanup();
    }, 3000);
  }

  /**
   * Send a raw UDP packet.
   */
  async _send(data) {
    if (this._sendPacket) {
      await this._sendPacket(data, this.remoteAddr, this.remotePort);
    }
  }

  /**
   * Reset the idle timeout timer.
   */
  _resetIdleTimer() {
    if (this.idleTimer) clearTimeout(this.idleTimer);
    this.idleTimer = setTimeout(() => {
      this.close(0, 'idle timeout');
    }, this.localParams.maxIdleTimeout);
  }

  /**
   * Clean up connection resources.
   */
  _cleanup() {
    if (this.idleTimer) clearTimeout(this.idleTimer);
    this.streamManager.closeAll();
    this.emit('closed');
  }

  /**
   * Get connection info.
   */
  getInfo() {
    return {
      localConnId: bytesToHex(this.localConnId),
      remoteConnId: this.remoteConnId ? bytesToHex(this.remoteConnId) : null,
      state: this.state,
      remoteAddr: this.remoteAddr,
      remotePort: this.remotePort,
      streamCount: this.streamManager.streams.size,
    };
  }
}