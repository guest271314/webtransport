/**
 * HTTP/3 Layer for WebTransport (RFC 9114 + RFC 9220)
 *
 * HTTP/3 runs on top of QUIC and uses QUIC streams for multiplexing.
 * WebTransport is established via an HTTP/3 CONNECT request.
 *
 * HTTP/3 stream types:
 * - Control stream (type 0x00): Carries SETTINGS, GOAWAY
 * - Push stream (type 0x01): Server push (not used for WebTransport)
 * - QPACK encoder/decoder (types 0x02, 0x03)
 * - WebTransport stream (type 0x54): WebTransport-specific
 *
 * HTTP/3 frame types:
 * - DATA (0x00)
 * - HEADERS (0x01)
 * - SETTINGS (0x04)
 * - GOAWAY (0x07)
 * - WEBTRANSPORT_STREAM (0x41)
 */

import { ByteBuffer, concatBytes } from './byte-buffer.js';
import { EventEmitter } from './event-emitter.js';

// HTTP/3 frame types
export const H3FrameType = {
  DATA:     0x00,
  HEADERS:  0x01,
  SETTINGS: 0x04,
  GOAWAY:   0x07,
};

// HTTP/3 settings
export const H3Settings = {
  QPACK_MAX_TABLE_CAPACITY: 0x01,
  MAX_FIELD_SECTION_SIZE:   0x06,
  QPACK_BLOCKED_STREAMS:    0x07,
  ENABLE_CONNECT_PROTOCOL:  0x08,    // Required for WebTransport
  H3_DATAGRAM:              0x33,    // RFC 9297 - HTTP Datagrams
  ENABLE_WEBTRANSPORT:      0x2b603742,
  WEBTRANSPORT_MAX_SESSIONS: 0x2b603743,
};

// HTTP/3 unidirectional stream types
export const H3StreamType = {
  CONTROL:          0x00,
  PUSH:             0x01,
  QPACK_ENCODER:    0x02,
  QPACK_DECODER:    0x03,
  WEBTRANSPORT_UNI: 0x54,
};

// HTTP/3 error codes
export const H3Error = {
  NO_ERROR:               0x100,
  GENERAL_PROTOCOL_ERROR: 0x101,
  INTERNAL_ERROR:         0x102,
  STREAM_CREATION_ERROR:  0x103,
  CLOSED_CRITICAL_STREAM: 0x104,
  FRAME_UNEXPECTED:       0x105,
  FRAME_ERROR:            0x106,
  EXCESSIVE_LOAD:         0x107,
  ID_ERROR:               0x108,
  SETTINGS_ERROR:         0x109,
  MISSING_SETTINGS:       0x10a,
  REQUEST_REJECTED:       0x10b,
  REQUEST_CANCELLED:      0x10c,
  REQUEST_INCOMPLETE:     0x10d,
  CONNECT_ERROR:          0x10f,
  VERSION_FALLBACK:       0x110,
};

/**
 * HTTP/3 Connection handler.
 *
 * Manages HTTP/3 protocol on top of a QUIC connection,
 * including WebTransport session establishment.
 */
export class Http3Connection extends EventEmitter {
  constructor(quicConnection) {
    super();
    this.quic = quicConnection;

    // Server-initiated control streams
    this.controlStreamId = null;
    this.qpackEncoderStreamId = null;
    this.qpackDecoderStreamId = null;

    // Client's control stream
    this.peerControlStreamId = null;
    this.peerSettings = null;

    // Settings
    this.localSettings = {
      [H3Settings.QPACK_MAX_TABLE_CAPACITY]: 0,
      [H3Settings.QPACK_BLOCKED_STREAMS]: 0,
      [H3Settings.ENABLE_CONNECT_PROTOCOL]: 1,
      [H3Settings.H3_DATAGRAM]: 1,
      [H3Settings.ENABLE_WEBTRANSPORT]: 1,
      [H3Settings.WEBTRANSPORT_MAX_SESSIONS]: 16,
    };

    // Active WebTransport sessions
    this.sessions = new Map(); // streamId -> WebTransportSession

    // Track uni stream types
    this.uniStreamTypes = new Map();

    // Request handler
    this._requestHandler = null;

    // Set up QUIC event handlers
    this._setupQuicHandlers();
  }

  /**
   * Initialize HTTP/3 connection (send control stream, SETTINGS, etc.)
   */
  async init() {
    // Create server control stream (unidirectional)
    const controlStream = this.quic.streamManager.openUniStream();
    this.controlStreamId = controlStream.streamId;

    // Send stream type + SETTINGS frame
    const streamTypeData = ByteBuffer.encodeVarInt(H3StreamType.CONTROL);
    const settingsFrame = this._buildSettingsFrame();
    controlStream.write(concatBytes(streamTypeData, settingsFrame));

    // Create QPACK encoder stream
    const encoderStream = this.quic.streamManager.openUniStream();
    this.qpackEncoderStreamId = encoderStream.streamId;
    encoderStream.write(ByteBuffer.encodeVarInt(H3StreamType.QPACK_ENCODER));

    // Create QPACK decoder stream
    const decoderStream = this.quic.streamManager.openUniStream();
    this.qpackDecoderStreamId = decoderStream.streamId;
    decoderStream.write(ByteBuffer.encodeVarInt(H3StreamType.QPACK_DECODER));
  }

  /**
   * Set up handlers for QUIC events.
   */
  _setupQuicHandlers() {
    this.quic.on('stream', (stream) => {
      this._handleNewStream(stream);
    });

    this.quic.on('datagram', (data) => {
      this._handleDatagram(data);
    });
  }

  /**
   * Handle a new QUIC stream.
   */
  _handleNewStream(stream) {
    const isUni = (stream.streamId & 0x02) !== 0;
    const isClientInitiated = (stream.streamId & 0x01) === 0;

    if (isUni && isClientInitiated) {
      // Client-initiated unidirectional stream
      // First varint is the stream type
      let buffer = new Uint8Array(0);

      stream.on('data', (data) => {
        buffer = concatBytes(buffer, data);

        if (!this.uniStreamTypes.has(stream.streamId)) {
          // Try to read stream type
          try {
            const typeBuf = new ByteBuffer(buffer);
            const streamType = typeBuf.readVarInt();
            this.uniStreamTypes.set(stream.streamId, streamType);
            buffer = buffer.slice(typeBuf.offset);

            this._handleUniStream(stream, streamType, buffer);
          } catch (e) {
            // Not enough data yet
          }
        } else {
          this._handleUniStreamData(stream, this.uniStreamTypes.get(stream.streamId), data);
        }
      });
    } else if (!isUni && isClientInitiated) {
      // Client-initiated bidirectional stream (HTTP/3 request stream)
      let buffer = new Uint8Array(0);

      stream.on('data', (data) => {
        buffer = concatBytes(buffer, data);
        this._tryProcessRequestStream(stream, buffer);
      });
    }
  }

  /**
   * Handle a client-initiated unidirectional stream once we know its type.
   */
  _handleUniStream(stream, streamType, initialData) {
    switch (streamType) {
      case H3StreamType.CONTROL:
        this.peerControlStreamId = stream.streamId;
        if (initialData.length > 0) {
          this._processControlStreamData(initialData);
        }
        break;

      case H3StreamType.QPACK_ENCODER:
        // QPACK encoder stream from client (we use static-only, so mostly ignore)
        break;

      case H3StreamType.QPACK_DECODER:
        // QPACK decoder stream from client
        break;

      case H3StreamType.WEBTRANSPORT_UNI:
        // WebTransport unidirectional stream
        if (initialData.length > 0) {
          this._handleWebTransportUniStream(stream, initialData);
        }
        break;

      default:
        // Unknown stream type - ignore (QUIC allows this)
        console.log(`Unknown uni stream type: 0x${streamType.toString(16)}`);
        break;
    }
  }

  _handleUniStreamData(stream, streamType, data) {
    switch (streamType) {
      case H3StreamType.CONTROL:
        this._processControlStreamData(data);
        break;
      case H3StreamType.WEBTRANSPORT_UNI:
        this._handleWebTransportUniStreamData(stream, data);
        break;
    }
  }

  /**
   * Process data from the peer's control stream.
   */
  _processControlStreamData(data) {
    const buf = new ByteBuffer(data);

    while (buf.remaining > 0) {
      try {
        const frameType = buf.readVarInt();
        const frameLength = buf.readVarInt();
        const frameData = buf.readBytes(frameLength);

        switch (frameType) {
          case H3FrameType.SETTINGS:
            this._processSettings(frameData);
            break;
          case H3FrameType.GOAWAY:
            this._processGoaway(frameData);
            break;
          default:
            // Unknown frame on control stream - ignore
            break;
        }
      } catch (e) {
        break; // Incomplete frame
      }
    }
  }

  /**
   * Process HTTP/3 SETTINGS frame.
   */
  _processSettings(data) {
    const buf = new ByteBuffer(data);
    this.peerSettings = {};

    while (buf.remaining > 0) {
      const settingId = buf.readVarInt();
      const settingValue = buf.readVarInt();
      this.peerSettings[settingId] = settingValue;
    }

    this.emit('settings', this.peerSettings);
  }

  /**
   * Process GOAWAY frame.
   */
  _processGoaway(data) {
    const buf = new ByteBuffer(data);
    const streamId = buf.readVarInt();
    this.emit('goaway', streamId);
  }

  /**
   * Try to process a request stream (bidirectional).
   */
  _tryProcessRequestStream(stream, buffer) {
    const buf = new ByteBuffer(buffer);

    try {
      const frameType = buf.readVarInt();
      const frameLength = buf.readVarInt();

      if (buf.remaining < frameLength) return; // Not enough data

      const frameData = buf.readBytes(frameLength);

      if (frameType === H3FrameType.HEADERS) {
        const headers = this._decodeHeaders(frameData);

        // Check if this is a WebTransport CONNECT request
        if (headers[':method'] === 'CONNECT' && headers[':protocol'] === 'webtransport') {
          this._handleWebTransportConnect(stream, headers);
        } else {
          // Regular HTTP/3 request
          this.emit('request', { stream, headers });
        }
      }
    } catch (e) {
      // Not enough data or parse error
    }
  }

  /**
   * Handle a WebTransport CONNECT request.
   * (RFC 9220)
   */
  _handleWebTransportConnect(stream, headers) {
    const path = headers[':path'] || '/';
    const origin = headers[':authority'] || headers['origin'] || '';

    // Create a WebTransport session
    const session = new WebTransportSession(stream.streamId, this, path, origin);
    this.sessions.set(stream.streamId, session);

    // Send 200 OK response
    const responseHeaders = {
      ':status': '200',
      'sec-webtransport-http3-draft': 'draft02',
    };
    this._sendHeaders(stream, responseHeaders);

    // Emit session event
    this.emit('webtransport-session', session);
  }

  /**
   * Handle WebTransport unidirectional stream.
   */
  _handleWebTransportUniStream(stream, data) {
    // The first varint after the stream type is the session ID
    const buf = new ByteBuffer(data);
    try {
      const sessionId = buf.readVarInt();
      const session = this.sessions.get(sessionId);
      if (session) {
        const remaining = data.slice(buf.offset);
        session._handleIncomingUniStream(stream, remaining);
      }
    } catch (e) {
      // Not enough data
    }
  }

  _handleWebTransportUniStreamData(stream, data) {
    // Route to appropriate session
    // (In a full implementation, we'd track which session owns which stream)
  }

  /**
   * Handle incoming datagram.
   */
  _handleDatagram(data) {
    // WebTransport datagrams are prefixed with a quarter-stream ID
    const buf = new ByteBuffer(data);
    try {
      const quarterStreamId = buf.readVarInt();
      const sessionId = quarterStreamId * 4; // Convert to stream ID
      const session = this.sessions.get(sessionId);
      if (session) {
        const payload = data.slice(buf.offset);
        session._handleDatagram(payload);
      }
    } catch (e) {
      // Parse error
    }
  }

  /**
   * Decode QPACK-encoded headers.
   * We use static-table-only QPACK (no dynamic table) for simplicity.
   */
  _decodeHeaders(data) {
    const buf = new ByteBuffer(data);
    const headers = {};

    // Required Insert Count (should be 0 for static-only)
    const requiredInsertCount = buf.readVarInt();
    // Delta Base
    const deltaBase = buf.readVarInt();

    while (buf.remaining > 0) {
      const firstByte = buf.buffer[buf.offset];

      if (firstByte & 0x80) {
        // Indexed Header Field (static table reference)
        buf.offset++;
        const index = firstByte & 0x3f;
        const entry = QPACK_STATIC_TABLE[index];
        if (entry) {
          headers[entry[0]] = entry[1];
        }
      } else if (firstByte & 0x40) {
        // Literal Header Field With Name Reference
        buf.offset++;
        const nameIndex = firstByte & 0x0f;
        const entry = QPACK_STATIC_TABLE[nameIndex];
        const valueLenPrefix = buf.readVarInt();
        const valueLen = valueLenPrefix; // Simplified
        const value = new TextDecoder().decode(buf.readBytes(valueLen));
        if (entry) {
          headers[entry[0]] = value;
        }
      } else if (firstByte & 0x20) {
        // Literal Header Field With Literal Name
        buf.offset++;
        const nameLen = buf.readVarInt();
        const name = new TextDecoder().decode(buf.readBytes(nameLen));
        const valueLen = buf.readVarInt();
        const value = new TextDecoder().decode(buf.readBytes(valueLen));
        headers[name] = value;
      } else {
        // Skip unknown prefix
        buf.offset++;
        break;
      }
    }

    return headers;
  }

  /**
   * Encode headers using QPACK (static-table-only).
   */
  _encodeHeaders(headers) {
    const buf = new ByteBuffer(512);

    // Required Insert Count = 0 (no dynamic table)
    buf.writeVarInt(0);
    // Delta Base = 0
    buf.writeVarInt(0);

    for (const [name, value] of Object.entries(headers)) {
      // Find in static table
      const staticIndex = QPACK_STATIC_TABLE.findIndex(
        e => e[0] === name && e[1] === value
      );

      if (staticIndex >= 0) {
        // Indexed Header Field
        buf.writeUint8(0x80 | (staticIndex & 0x3f));
      } else {
        // Literal Header Field With Literal Name
        buf.writeUint8(0x20);
        const nameBytes = new TextEncoder().encode(name);
        buf.writeVarInt(nameBytes.length);
        buf.writeBytes(nameBytes);
        const valueBytes = new TextEncoder().encode(value);
        buf.writeVarInt(valueBytes.length);
        buf.writeBytes(valueBytes);
      }
    }

    return buf.toUint8Array();
  }

  /**
   * Send HEADERS frame on a stream.
   */
  _sendHeaders(stream, headers) {
    const encoded = this._encodeHeaders(headers);
    const buf = new ByteBuffer(encoded.length + 16);
    buf.writeVarInt(H3FrameType.HEADERS);
    buf.writeVarInt(encoded.length);
    buf.writeBytes(encoded);
    stream.write(buf.toUint8Array());
  }

  /**
   * Build a SETTINGS frame.
   */
  _buildSettingsFrame() {
    const settingsBuf = new ByteBuffer(128);
    for (const [id, value] of Object.entries(this.localSettings)) {
      settingsBuf.writeVarInt(parseInt(id));
      settingsBuf.writeVarInt(value);
    }
    const settingsData = settingsBuf.toUint8Array();

    const frameBuf = new ByteBuffer(settingsData.length + 16);
    frameBuf.writeVarInt(H3FrameType.SETTINGS);
    frameBuf.writeVarInt(settingsData.length);
    frameBuf.writeBytes(settingsData);

    return frameBuf.toUint8Array();
  }
}

/**
 * WebTransport Session (RFC 9220)
 *
 * A WebTransport session runs over HTTP/3 and provides:
 * - Bidirectional streams
 * - Unidirectional streams
 * - Datagrams
 */
export class WebTransportSession extends EventEmitter {
  constructor(sessionId, http3, path, origin) {
    super();
    this.sessionId = sessionId;
    this.http3 = http3;
    this.path = path;
    this.origin = origin;
    this.closed = false;

    // Streams within this session
    this.bidiStreams = new Map();
    this.incomingUniStreams = new Map();
    this.outgoingUniStreams = new Map();
  }

  /**
   * Create a new bidirectional stream.
   */
  createBidirectionalStream() {
    const stream = this.http3.quic.streamManager.openBidiStream();
    this.bidiStreams.set(stream.streamId, stream);

    // Write the WebTransport stream header
    const buf = new ByteBuffer(16);
    buf.writeVarInt(0x41); // WEBTRANSPORT_STREAM frame type
    buf.writeVarInt(this.sessionId);
    stream.write(buf.toUint8Array());

    return stream;
  }

  /**
   * Create a new unidirectional stream.
   */
  createUnidirectionalStream() {
    const stream = this.http3.quic.streamManager.openUniStream();
    this.outgoingUniStreams.set(stream.streamId, stream);

    // Write stream type + session ID
    const buf = new ByteBuffer(16);
    buf.writeVarInt(H3StreamType.WEBTRANSPORT_UNI);
    buf.writeVarInt(this.sessionId);
    stream.write(buf.toUint8Array());

    return stream;
  }

  /**
   * Send a datagram.
   */
  async sendDatagram(data) {
    // Prefix with quarter-stream-ID
    const quarterStreamId = Math.floor(this.sessionId / 4);
    const prefix = ByteBuffer.encodeVarInt(quarterStreamId);
    const payload = concatBytes(prefix, data);
    await this.http3.quic.sendDatagram(payload);
  }

  /**
   * Handle an incoming unidirectional stream.
   */
  _handleIncomingUniStream(stream, initialData) {
    this.incomingUniStreams.set(stream.streamId, stream);
    this.emit('unidirectional-stream', stream, initialData);
  }

  /**
   * Handle an incoming datagram.
   */
  _handleDatagram(data) {
    this.emit('datagram', data);
  }

  /**
   * Close the session.
   */
  close(errorCode = 0, reason = '') {
    if (this.closed) return;
    this.closed = true;

    // Close all streams
    for (const stream of this.bidiStreams.values()) stream.close();
    for (const stream of this.outgoingUniStreams.values()) stream.close();

    this.http3.sessions.delete(this.sessionId);
    this.emit('close', { errorCode, reason });
  }
}

/**
 * QPACK Static Table (partial - most commonly used entries).
 * Full table is in RFC 9204.
 */
const QPACK_STATIC_TABLE = [
  [':authority', ''],            // 0
  [':path', '/'],                // 1
  ['age', '0'],                  // 2
  ['content-disposition', ''],   // 3
  ['content-length', '0'],       // 4
  ['cookie', ''],                // 5
  ['date', ''],                  // 6
  ['etag', ''],                  // 7
  ['if-modified-since', ''],     // 8
  ['if-none-match', ''],         // 9
  ['last-modified', ''],         // 10
  ['link', ''],                  // 11
  ['location', ''],              // 12
  ['referer', ''],               // 13
  ['set-cookie', ''],            // 14
  [':method', 'CONNECT'],        // 15
  [':method', 'DELETE'],         // 16
  [':method', 'GET'],            // 17
  [':method', 'HEAD'],           // 18
  [':method', 'OPTIONS'],        // 19
  [':method', 'POST'],           // 20
  [':method', 'PUT'],            // 21
  [':scheme', 'http'],           // 22
  [':scheme', 'https'],          // 23
  [':status', '103'],            // 24
  [':status', '200'],            // 25
  [':status', '304'],            // 26
  [':status', '404'],            // 27
  [':status', '503'],            // 28
  ['accept', '*/*'],             // 29
  ['accept', 'application/dns-message'],  // 30
  ['accept-encoding', 'gzip, deflate, br'], // 31
  ['accept-ranges', 'bytes'],    // 32
  ['access-control-allow-headers', 'cache-control'], // 33
  ['access-control-allow-headers', 'content-type'],  // 34
  ['access-control-allow-origin', '*'],    // 35
  ['cache-control', 'max-age=0'],          // 36
  ['cache-control', 'max-age=2592000'],    // 37
  ['cache-control', 'max-age=604800'],     // 38
  ['cache-control', 'no-cache'],           // 39
  ['cache-control', 'no-store'],           // 40
  ['cache-control', 'public, max-age=31536000'], // 41
  ['content-encoding', 'br'],    // 42
  ['content-encoding', 'gzip'],  // 43
  ['content-type', 'application/dns-message'], // 44
  ['content-type', 'application/javascript'],  // 45
  ['content-type', 'application/json'],        // 46
  ['content-type', 'application/x-www-form-urlencoded'], // 47
  ['content-type', 'image/gif'],  // 48
  ['content-type', 'image/jpeg'], // 49
  ['content-type', 'image/png'],  // 50
  ['content-type', 'text/css'],   // 51
  ['content-type', 'text/html; charset=utf-8'], // 52
  ['content-type', 'text/plain'],               // 53
  ['content-type', 'text/plain;charset=utf-8'], // 54
  ['range', 'bytes=0-'],          // 55
  ['strict-transport-security', 'max-age=31536000'], // 56
  ['strict-transport-security', 'max-age=31536000; includesubdomains'], // 57
  ['strict-transport-security', 'max-age=31536000; includesubdomains; preload'], // 58
  ['vary', 'accept-encoding'],    // 59
  ['vary', 'origin'],             // 60
  ['x-content-type-options', 'nosniff'], // 61
  ['x-xss-protection', '1; mode=block'], // 62
  [':status', '100'],             // 63
  [':status', '204'],             // 64
  [':status', '206'],             // 65
  [':status', '302'],             // 66
  [':status', '400'],             // 67
  [':status', '403'],             // 68
  [':status', '421'],             // 69
  [':status', '425'],             // 70
  [':status', '500'],             // 71
  ['accept-language', ''],        // 72
  ['access-control-allow-credentials', 'FALSE'], // 73
  ['access-control-allow-credentials', 'TRUE'],  // 74
  ['access-control-allow-headers', '*'],  // 75
  ['access-control-allow-methods', 'get'],  // 76
  ['access-control-allow-methods', 'get, post, options'], // 77
  ['access-control-allow-methods', 'options'], // 78
  ['access-control-expose-headers', 'content-length'], // 79
  ['access-control-request-headers', 'content-type'],  // 80
  ['access-control-request-method', 'get'],  // 81
  ['access-control-request-method', 'post'], // 82
  ['alt-svc', 'clear'],           // 83
  ['authorization', ''],          // 84
  ['content-security-policy', "script-src 'none'; object-src 'none'; base-uri 'none'"], // 85
  ['early-data', '1'],            // 86
  ['expect-ct', ''],              // 87
  ['forwarded', ''],              // 88
  ['if-range', ''],               // 89
  ['origin', ''],                 // 90
  ['purpose', 'prefetch'],        // 91
  ['server', ''],                 // 92
  ['timing-allow-origin', '*'],   // 93
  ['upgrade-insecure-requests', '1'], // 94
  ['user-agent', ''],             // 95
  ['x-forwarded-for', ''],        // 96
  ['x-frame-options', 'deny'],    // 97
  ['x-frame-options', 'sameorigin'], // 98
  [':protocol', 'webtransport'],  // 99 (for Extended CONNECT)
];