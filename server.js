/**
 * WebTransport Server using Direct Sockets UDPSocket API.
 *
 * This is the main entry point. It:
 * 1. Opens a UDPSocket for listening
 * 2. Dispatches incoming UDP datagrams to QUIC connections
 * 3. Manages connection lifecycle
 * 4. Exposes WebTransport sessions to the application
 *
 * Usage (in an Isolated Web App):
 *
 *   const server = new WebTransportServer({ port: 4433 });
 *   server.on('session', (session) => {
 *     console.log('New WebTransport session:', session.path);
 *
 *     session.on('datagram', (data) => {
 *       console.log('Received datagram')
 *       session.sendDatagram(data); // Echo
 *     });
 *
 *     session.on('unidirectional-stream', (stream) => {
 *       stream.on('data', (chunk) => console.log('Stream data:', chunk));
 *     });
 *   });
 *
 *   await server.listen();
 */

import { EventEmitter } from './event-emitter.js';
import { QuicConnection } from './connection.js';
import { Http3Connection, WebTransportSession } from './http3.js';
import { bytesToHex, randomBytes } from './byte-buffer.js';
import { isLongHeader, parseLongHeader} from './packet.js';
import { QUIC_VERSION_1, PacketType } from './constants.js';
import { importCertFromPem } from "./tls-crypto.js";

//importCertFromPem(myJsonCerts[0]);
//const server = new WebTransportServer({ port: 4433, cert });
/**
 * WebTransport Server.
 *
 * Listens on a UDP port using the Direct Sockets API and handles
 * incoming QUIC connections and WebTransport sessions.
 */
export class WebTransportServer extends EventEmitter {
  /**
   * @param {Object} options
   * @param {number} options.port - UDP port to listen on
   * @param {string} [options.host='0.0.0.0'] - Host to bind to
   * @param {Object} [options.cert] - TLS certificate { certificate, privateKey }
   * @param {Object} [options.transportParams] - Custom QUIC transport parameters
   */
  constructor(options = {}) {
    super();

    this.port = options.port || 4433;
    this.host = options.host || '0.0.0.0';
    this.cert = options.cert || null;
    this.transportParams = options.transportParams || {};

    // UDP socket
    this.socket = null;
    this.readable = null;
    this.writable = null;
    this.writer = null;

    // Connection tracking (by destination connection ID hex)
    this.connections = new Map();

    // Stats
    this.stats = {
      packetsReceived: 0,
      packetsSent: 0,
      bytesReceived: 0,
      bytesSent: 0,
      connectionsTotal: 0,
      connectionsActive: 0,
      sessionsTotal: 0,
    };

    this._running = false;
  }

  /**
   * Start listening for incoming connections.
   */
  async listen() {
    if (this._running) throw new Error('Server already running');

    // Check for Direct Sockets API availability
    if (typeof UDPSocket === 'undefined') {
      throw new Error(
        'UDPSocket is not available. This API requires:\n' +
        '1. Chrome/Chromium with Direct Sockets API enabled\n' +
        '2. Running as an Isolated Web App (IWA)\n' +
        '3. "direct-sockets" permission in the manifest\n\n' +
        'For development/testing, use the Node.js adapter instead.'
      );
    }

    try {
      // Open UDP socket
      this.socket = new UDPSocket({
        localAddress: this.host,
        localPort: this.port,
      });

      // Wait for the socket to be ready
      const { readable, writable } = await this.socket.opened;
      this.readable = readable;
      this.writable = writable;
      this.writer = this.writable.getWriter();

      this._running = true;

      console.log(`WebTransport server listening on ${this.host}:${this.port}`);
      this.emit('listening', { host: this.host, port: this.port });

      // Start reading datagrams
      this._startReading();
    } catch (err) {
      throw new Error(`Failed to open UDPSocket: ${err.message}`);
    }
  }

  /**
   * Start the datagram reading loop.
   */
  async _startReading() {
    const reader = this.readable.getReader();

    try {
      while (this._running) {
        const { value, done } = await reader.read();
        if (done) break;

        // value is { data: ArrayBuffer, remoteAddress: string, remotePort: number }
        const { data, remoteAddress, remotePort } = value;
        const packet = new Uint8Array(data);

        this.stats.packetsReceived++;
        this.stats.bytesReceived += packet.length;

        await this._handleDatagram(packet, remoteAddress, remotePort);
      }
    } catch (err) {
      if (this._running) {
        console.error('Error reading from socket:', err);
        this.emit('error', err);
      }
    } finally {
      reader.releaseLock();
    }
  }

  /**
   * Handle an incoming UDP datagram.
   */
  async _handleDatagram(data, remoteAddr, remotePort) {
    if (data.length < 1) return;

    try {
      // Determine if this belongs to an existing connection
      const connection = this._findConnection(data, remoteAddr, remotePort);

      if (connection) {
        await connection.processPacket(data);
      } else if (isLongHeader(data[0])) {
        // Potentially a new connection (Initial packet)
        await this._handleNewConnection(data, remoteAddr, remotePort);
      } else {
        // Short header with no matching connection - drop
        console.debug('Dropping packet: no matching connection');
      }
    } catch (err) {
      console.error('Error handling datagram:', err);
    }
  }

  /**
   * Find an existing connection for a packet.
   */
  _findConnection(data, remoteAddr, remotePort) {
    // For long headers, use the destination connection ID
    if (isLongHeader(data[0])) {
      try {
        const parsed = parseLongHeader(data);
        const dcidHex = bytesToHex(parsed.dcid);

        // Look up by DCID
        const conn = this.connections.get(dcidHex);
        if (conn) return conn;

        // Also check if this is a handshake packet for a connection
        // identified by a different DCID
        for (const [key, conn] of this.connections) {
          if (conn.remoteAddr === remoteAddr && conn.remotePort === remotePort) {
            return conn;
          }
        }
      } catch (e) {
        // Parse error
      }
    } else {
      // Short header - need to match by DCID (which is our local connection ID)
      // Since we know our DCID length, extract it
      // For simplicity, try all connections
      for (const [key, conn] of this.connections) {
        if (conn.remoteAddr === remoteAddr && conn.remotePort === remotePort) {
          return conn;
        }
      }
    }

    return null;
  }

  /**
   * Handle a potential new connection (Initial packet).
   */
  async _handleNewConnection(data, remoteAddr, remotePort) {
    const parsed = parseLongHeader(data);

    // Must be an Initial packet
    if (parsed.packetType !== PacketType.INITIAL) {
      console.debug('Not an Initial packet, dropping');
      return;
    }

    // Must be QUIC v1
    if (parsed.version !== QUIC_VERSION_1) {
      // TODO: Send Version Negotiation packet
      console.warn(`Unsupported version: 0x${parsed.version.toString(16)}`);
      return;
    }

    // Initial packets must be at least 1200 bytes
    if (data.length < 1200) {
      console.debug('Initial packet too small, dropping');
      return;
    }

    // Create a new connection
    const localConnId = randomBytes(8);
    const dcidHex = bytesToHex(localConnId);

    const conn = new QuicConnection({
      localConnId,
      remoteConnId: parsed.scid,
      originalDestConnId: parsed.dcid,
      remoteAddr,
      remotePort,
      sendPacket: (packet, addr, port) => this._sendPacket(packet, addr, port),
    });

    // Store connection
    this.connections.set(dcidHex, conn);
    // Also store by original DCID so we can match subsequent Initial packets
    this.connections.set(bytesToHex(parsed.dcid), conn);

    this.stats.connectionsTotal++;
    this.stats.connectionsActive++;

    // Initialize
    await conn.init();

    // Set up HTTP/3
    conn.on('connected', async () => {
      const http3 = new Http3Connection(conn);
      await http3.init();

      http3.on('webtransport-session', (session) => {
        this.stats.sessionsTotal++;
        this.emit('session', session);
      });

      conn._http3 = http3;
    });

    conn.on('closed', () => {
      this.connections.delete(dcidHex);
      this.connections.delete(bytesToHex(parsed.dcid));
      this.stats.connectionsActive--;
      this.emit('connection-closed', conn);
    });

    conn.on('error', (err) => {
      console.error(`Connection error [${dcidHex}]:`, err);
      this.emit('connection-error', { connection: conn, error: err });
    });

    this.emit('connection', conn);

    // Process the Initial packet
    await conn.processPacket(data);
  }

  /**
   * Send a UDP packet.
   */
  async _sendPacket(data, remoteAddr, remotePort) {
    if (!this.writer) {
      throw new Error('Socket not open');
    }

    try {
      await this.writer.write({
        data: data.buffer,
        remoteAddress: remoteAddr,
        remotePort: remotePort,
      });

      this.stats.packetsSent++;
      this.stats.bytesSent += data.length;
    } catch (err) {
      console.error('Failed to send packet:', err);
      throw err;
    }
  }

  /**
   * Close the server.
   */
  async close() {
    this._running = false;

    // Close all connections
    for (const conn of this.connections.values()) {
      await conn.close(0, 'server shutdown');
    }

    // Close the socket
    if (this.writer) {
      try { this.writer.releaseLock(); } catch (e) {}
    }
    if (this.socket) {
      try { await this.socket.close(); } catch (e) {}
    }

    this.emit('close');
  }

  /**
   * Get server statistics.
   */
  getStats() {
    return { ...this.stats };
  }

  /**
   * Get info about all active connections.
   */
  getConnections() {
    const result = [];
    const seen = new Set();
    for (const conn of this.connections.values()) {
      const id = bytesToHex(conn.localConnId);
      if (!seen.has(id)) {
        seen.add(id);
        result.push(conn.getInfo());
      }
    }
    return result;
  }
}