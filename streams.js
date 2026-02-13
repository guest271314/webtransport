/**
 * QUIC Stream Manager (RFC 9000 Sections 2-3)
 *
 * QUIC supports multiplexed streams within a single connection.
 * Stream IDs encode the initiator and directionality:
 *   - Bit 0: 0 = client-initiated, 1 = server-initiated
 *   - Bit 1: 0 = bidirectional, 1 = unidirectional
 *
 *   Type 0x00: Client-initiated bidirectional (0, 4, 8, ...)
 *   Type 0x01: Server-initiated bidirectional (1, 5, 9, ...)
 *   Type 0x02: Client-initiated unidirectional (2, 6, 10, ...)
 *   Type 0x03: Server-initiated unidirectional (3, 7, 11, ...)
 */

import { EventEmitter } from './event-emitter.js';

export class QuicStream extends EventEmitter {
  constructor(streamId, connection) {
    super();
    this.streamId = streamId;
    this.connection = connection;

    // Stream type
    this.initiator = (streamId & 0x01) === 0 ? 'client' : 'server';
    this.bidirectional = (streamId & 0x02) === 0;

    // Send state
    this.sendOffset = 0;
    this.sendBuffer = [];
    this.sendFin = false;
    this.maxSendData = connection.peerParams?.initialMaxStreamDataBidiRemote || 262144;

    // Receive state
    this.recvOffset = 0;
    this.recvBuffer = new Map(); // offset -> data
    this.recvFin = false;
    this.recvFinOffset = -1;
    this.maxRecvData = 262144;
    this.totalRecvBytes = 0;

    // State
    this.readable = true;
    this.writable = true;
    this.closed = false;
  }

  /**
   * Write data to the stream.
   */
  write(data, fin = false) {
    if (!this.writable || this.closed) {
      throw new Error('Stream is not writable');
    }

    this.sendBuffer.push({ offset: this.sendOffset, data: new Uint8Array(data), fin });
    this.sendOffset += data.length;

    if (fin) {
      this.sendFin = true;
      this.writable = false;
    }

    // Signal the connection to send
    this.connection._onStreamDataReady(this.streamId);
  }

  /**
   * Process received STREAM frame data.
   */
  _receiveData(offset, data, fin) {
    if (this.closed) return;

    // Store data (handle out-of-order delivery)
    this.recvBuffer.set(offset, data);
    this.totalRecvBytes += data.length;

    if (fin) {
      this.recvFin = true;
      this.recvFinOffset = offset + data.length;
    }

    // Try to deliver contiguous data
    this._deliverData();
  }

  /**
   * Deliver contiguous data to the application.
   */
  _deliverData() {
    while (this.recvBuffer.has(this.recvOffset)) {
      const data = this.recvBuffer.get(this.recvOffset);
      this.recvBuffer.delete(this.recvOffset);
      this.recvOffset += data.length;

      this.emit('data', data);
    }

    // Check if stream is fully received
    if (this.recvFin && this.recvOffset >= this.recvFinOffset) {
      this.readable = false;
      this.emit('end');

      if (!this.writable) {
        this._close();
      }
    }
  }

  /**
   * Get pending data to send.
   */
  _getPendingData(maxBytes) {
    if (this.sendBuffer.length === 0) return null;

    const entry = this.sendBuffer[0];
    if (entry.data.length <= maxBytes) {
      this.sendBuffer.shift();
      return entry;
    }

    // Split the data
    const chunk = {
      offset: entry.offset,
      data: entry.data.slice(0, maxBytes),
      fin: false,
    };
    entry.offset += maxBytes;
    entry.data = entry.data.slice(maxBytes);
    return chunk;
  }

  /**
   * Close the stream.
   */
  close() {
    if (!this.sendFin) {
      this.write(new Uint8Array(0), true);
    }
  }

  _close() {
    this.closed = true;
    this.readable = false;
    this.writable = false;
    this.emit('close');
  }

  /**
   * Reset the stream with an error.
   */
  reset(errorCode = 0) {
    this.closed = true;
    this.readable = false;
    this.writable = false;
    this.emit('reset', errorCode);
    this.connection._onStreamReset(this.streamId, errorCode);
  }
}

/**
 * Manages all streams for a QUIC connection.
 */
export class StreamManager extends EventEmitter {
  constructor(connection) {
    super();
    this.connection = connection;
    this.streams = new Map();

    // Next stream IDs (server-initiated)
    this.nextBidiStreamId = 1;   // 1, 5, 9, ...
    this.nextUniStreamId = 3;    // 3, 7, 11, ...

    // Stream limits
    this.maxClientBidiStreams = 100;
    this.maxClientUniStreams = 100;
    this.maxServerBidiStreams = 100;
    this.maxServerUniStreams = 100;

    // Current counts
    this.clientBidiCount = 0;
    this.clientUniCount = 0;
    this.serverBidiCount = 0;
    this.serverUniCount = 0;
  }

  /**
   * Get or create a stream by ID.
   */
  getOrCreateStream(streamId) {
    if (this.streams.has(streamId)) {
      return this.streams.get(streamId);
    }

    const stream = new QuicStream(streamId, this.connection);
    this.streams.set(streamId, stream);

    // Track counts
    const type = streamId & 0x03;
    switch (type) {
      case 0: this.clientBidiCount++; break;
      case 1: this.serverBidiCount++; break;
      case 2: this.clientUniCount++; break;
      case 3: this.serverUniCount++; break;
    }

    this.emit('stream', stream);
    return stream;
  }

  /**
   * Open a new server-initiated bidirectional stream.
   */
  openBidiStream() {
    const streamId = this.nextBidiStreamId;
    this.nextBidiStreamId += 4;

    const stream = new QuicStream(streamId, this.connection);
    this.streams.set(streamId, stream);
    this.serverBidiCount++;

    return stream;
  }

  /**
   * Open a new server-initiated unidirectional stream.
   */
  openUniStream() {
    const streamId = this.nextUniStreamId;
    this.nextUniStreamId += 4;

    const stream = new QuicStream(streamId, this.connection);
    this.streams.set(streamId, stream);
    this.serverUniCount++;

    return stream;
  }

  /**
   * Close a stream.
   */
  closeStream(streamId) {
    const stream = this.streams.get(streamId);
    if (stream) {
      stream._close();
      this.streams.delete(streamId);
    }
  }

  /**
   * Get all streams with pending data to send.
   */
  getStreamsWithPendingData() {
    const result = [];
    for (const [id, stream] of this.streams) {
      if (stream.sendBuffer.length > 0) {
        result.push(stream);
      }
    }
    return result;
  }

  /**
   * Close all streams.
   */
  closeAll() {
    for (const [id, stream] of this.streams) {
      stream._close();
    }
    this.streams.clear();
  }
}