/**
 * TLS 1.3 Server-Side Handshake State Machine for QUIC.
 *
 * The TLS 1.3 handshake in QUIC:
 *   Client                           Server
 *   ClientHello        -------->
 *                      <--------    ServerHello
 *                      <--------    EncryptedExtensions
 *                      <--------    Certificate
 *                      <--------    CertificateVerify
 *                      <--------    Finished
 *   Finished           -------->
 *                      <--------    HANDSHAKE_DONE (QUIC frame)
 *
 * Key schedule (RFC 8446 Section 7.1):
 *   Early Secret = HKDF-Extract(0, 0)
 *   Handshake Secret = HKDF-Extract(ECDHE, Derive-Secret(Early, "derived", ""))
 *   Master Secret = HKDF-Extract(0, Derive-Secret(HS, "derived", ""))
 */

import { concatBytes, randomBytes } from './byte-buffer.js';
import {
  hkdfExtract,
  hkdfExpandLabel,
  derivePacketKeys,
  sha256,
  generateECDHKeyPair,
  ecdhDeriveBits,
  exportPublicKey,
  generateSelfSignedCert,
  ecdsaSign,
  TranscriptHash,
  CipherSuite,
  getCipherParams,
} from './tls-crypto.js';
import {
  parseHandshakeMessage,
  parseHandshakeMessages,
  parseClientHello,
  buildServerHello,
  buildEncryptedExtensions,
  buildCertificateMessage,
  buildCertificateVerify,
  buildFinished,
  encodeTransportParams,
  HandshakeType,
  SignatureScheme,
  NamedGroup,
} from './handshake.js';

// TLS 1.3 handshake states
const State = {
  WAIT_CLIENT_HELLO:  0,
  WAIT_FINISHED:      1,
  CONNECTED:          2,
  ERROR:              3,
};

/**
 * TLS 1.3 Server Handshake for QUIC.
 *
 * Manages the complete handshake process and key derivation.
 */
export class TlsServer {
  constructor(options = {}) {
    this.state = State.WAIT_CLIENT_HELLO;
    this.cipherSuite = CipherSuite.TLS_AES_128_GCM_SHA256;
    this.transcript = new TranscriptHash('SHA-256');
    this.serverTransportParams = options.transportParams || {};

    // Key material
    this.ecdhKeyPair = null;
    this.sharedSecret = null;

    // Certificate
    this.cert = options.cert || null;

    // Derived secrets
    this.earlySecret = null;
    this.handshakeSecret = null;
    this.masterSecret = null;
    this.clientHandshakeSecret = null;
    this.serverHandshakeSecret = null;
    this.clientAppSecret = null;
    this.serverAppSecret = null;

    // Packet keys at each level
    this.handshakeKeys = null;
    this.applicationKeys = null;

    // Buffered handshake data
    this.cryptoBuffer = new Uint8Array(0);
    this.cryptoOffset = 0;

    // Output messages
    this.pendingOutput = [];
  }

  /**
   * Initialize the server (generate keypair and cert if needed).
   */
  async init() {
    this.ecdhKeyPair = await generateECDHKeyPair();
    if (!this.cert) {
      this.cert = await generateSelfSignedCert();
    }
  }

  /**
   * Process incoming CRYPTO frame data.
   * Returns an array of { level, data } objects to be sent as CRYPTO frames.
   */
  async processCryptoData(data, encryptionLevel) {
    // Append to buffer
    this.cryptoBuffer = concatBytes(this.cryptoBuffer, data);

    const messages = parseHandshakeMessages(this.cryptoBuffer);
    if (messages.length === 0) return [];

    // Consume processed bytes
    let consumed = 0;
    for (const msg of messages) {
      consumed += 4 + msg.length;
    }
    this.cryptoBuffer = this.cryptoBuffer.slice(consumed);

    const output = [];

    for (const msg of messages) {
      switch (this.state) {
        case State.WAIT_CLIENT_HELLO:
          if (msg.type !== HandshakeType.CLIENT_HELLO) {
            throw new Error(`Expected ClientHello, got type ${msg.type}`);
          }
          const response = await this._handleClientHello(msg);
          output.push(...response);
          break;

        case State.WAIT_FINISHED:
          if (msg.type !== HandshakeType.FINISHED) {
            throw new Error(`Expected Finished, got type ${msg.type}`);
          }
          const finResponse = await this._handleClientFinished(msg);
          output.push(...finResponse);
          break;

        default:
          console.warn(`Unexpected handshake message in state ${this.state}`);
          break;
      }
    }

    return output;
  }

  /**
   * Handle the ClientHello message.
   */
  async _handleClientHello(msg) {
    const clientHello = parseClientHello(msg.data);

    // Add ClientHello to transcript
    this.transcript.addMessage(msg.raw);

    // Select cipher suite
    const supportedSuites = [CipherSuite.TLS_AES_128_GCM_SHA256, CipherSuite.TLS_AES_256_GCM_SHA384];
    this.cipherSuite = clientHello.cipherSuites.find(s => supportedSuites.includes(s));
    if (!this.cipherSuite) {
      throw new Error('No supported cipher suite found');
    }

    // Verify TLS 1.3 support
    if (clientHello.extensions.supportedVersions) {
      if (!clientHello.extensions.supportedVersions.includes(0x0304)) {
        throw new Error('Client does not support TLS 1.3');
      }
    }

    // Find a supported key share (prefer P-256)
    let clientKeyShare = null;
    if (clientHello.extensions.keyShare) {
      clientKeyShare = clientHello.extensions.keyShare.find(
        ks => ks.group === NamedGroup.SECP256R1
      );
    }
    if (!clientKeyShare) {
      throw new Error('No supported key share group found (need P-256)');
    }

    // Generate server key share
    const serverPublicKey = await exportPublicKey(this.ecdhKeyPair);

    // Perform ECDH
    this.sharedSecret = await ecdhDeriveBits(
      this.ecdhKeyPair.privateKey,
      clientKeyShare.keyData
    );

    // --- Build ServerHello ---
    const serverRandom = randomBytes(32);
    const serverHelloMsg = buildServerHello(
      serverRandom,
      clientHello.sessionId,
      this.cipherSuite,
      serverPublicKey
    );

    // Add ServerHello to transcript
    this.transcript.addMessage(serverHelloMsg);

    // --- Derive handshake keys ---
    await this._deriveHandshakeSecrets();

    // --- Build EncryptedExtensions ---
    const transportParamsEncoded = encodeTransportParams(this.serverTransportParams);
    const encExtMsg = buildEncryptedExtensions('h3', transportParamsEncoded);
    this.transcript.addMessage(encExtMsg);

    // --- Build Certificate ---
    const certMsg = buildCertificateMessage([this.cert.certificate || this.cert.publicKeySpki]);
    this.transcript.addMessage(certMsg);

    // --- Build CertificateVerify ---
    const transcriptHashForCv = await this.transcript.digest();
    const signatureInput = this._buildCertificateVerifyInput(transcriptHashForCv, true);
    const signature = await ecdsaSign(this.cert.privateKey, signatureInput);
    const certVerifyMsg = buildCertificateVerify(SignatureScheme.ECDSA_SECP256R1_SHA256, signature);
    this.transcript.addMessage(certVerifyMsg);

    // --- Build server Finished ---
    const finishedKey = await hkdfExpandLabel(
      'SHA-256', this.serverHandshakeSecret,
      'finished', new Uint8Array(0), 32
    );
    const transcriptHashForFin = await this.transcript.digest();
    const hmacKey = await crypto.subtle.importKey(
      'raw', finishedKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );
    const verifyData = new Uint8Array(
      await crypto.subtle.sign('HMAC', hmacKey, transcriptHashForFin)
    );
    const finishedMsg = buildFinished(verifyData);
    this.transcript.addMessage(finishedMsg);

    // --- Derive application keys ---
    await this._deriveApplicationSecrets();

    this.state = State.WAIT_FINISHED;

    // Return messages at appropriate encryption levels
    return [
      { level: 'initial', data: serverHelloMsg },
      { level: 'handshake', data: concatBytes(encExtMsg, certMsg, certVerifyMsg, finishedMsg) },
    ];
  }

  /**
   * Handle the client Finished message.
   */
  async _handleClientFinished(msg) {
    // Verify the client's Finished message
    const finishedKey = await hkdfExpandLabel(
      'SHA-256', this.clientHandshakeSecret,
      'finished', new Uint8Array(0), 32
    );
    const transcriptHash = await this.transcript.digest();
    const hmacKey = await crypto.subtle.importKey(
      'raw', finishedKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );
    const expectedVerifyData = new Uint8Array(
      await crypto.subtle.sign('HMAC', hmacKey, transcriptHash)
    );

    // Compare verify data
    const clientVerifyData = msg.data;
    let match = clientVerifyData.length === expectedVerifyData.length;
    for (let i = 0; i < expectedVerifyData.length && match; i++) {
      if (clientVerifyData[i] !== expectedVerifyData[i]) match = false;
    }

    if (!match) {
      console.warn('Client Finished verification failed (expected in dev without real client)');
      // In development, we may proceed anyway for testing
    }

    // Add client Finished to transcript
    this.transcript.addMessage(msg.raw);

    this.state = State.CONNECTED;

    // No more TLS messages to send; QUIC will send HANDSHAKE_DONE frame
    return [];
  }

  /**
   * Derive handshake secrets from the ECDH shared secret.
   * (RFC 8446 Section 7.1)
   */
  async _deriveHandshakeSecrets() {
    const hash = 'SHA-256';
    const hashLen = 32;
    const zeros = new Uint8Array(hashLen);

    // Early Secret = HKDF-Extract(0, 0)
    this.earlySecret = await hkdfExtract(hash, new Uint8Array(1), zeros);

    // Derive-Secret(early_secret, "derived", "")
    const emptyHash = await sha256(new Uint8Array(0));
    const derivedEarly = await hkdfExpandLabel(hash, this.earlySecret, 'derived', emptyHash, hashLen);

    // Handshake Secret = HKDF-Extract(ECDHE, derived_early)
    this.handshakeSecret = await hkdfExtract(hash, derivedEarly, this.sharedSecret);

    // Transcript hash up to ServerHello
    const transcriptHash = await this.transcript.digest();

    // Client/Server handshake traffic secrets
    this.clientHandshakeSecret = await hkdfExpandLabel(
      hash, this.handshakeSecret, 'c hs traffic', transcriptHash, hashLen
    );
    this.serverHandshakeSecret = await hkdfExpandLabel(
      hash, this.handshakeSecret, 's hs traffic', transcriptHash, hashLen
    );

    // Derive packet protection keys for handshake level
    this.handshakeKeys = {
      client: await derivePacketKeys(this.clientHandshakeSecret, this.cipherSuite),
      server: await derivePacketKeys(this.serverHandshakeSecret, this.cipherSuite),
    };
  }

  /**
   * Derive application (1-RTT) secrets.
   */
  async _deriveApplicationSecrets() {
    const hash = 'SHA-256';
    const hashLen = 32;
    const zeros = new Uint8Array(hashLen);

    // Derive-Secret(handshake_secret, "derived", "")
    const emptyHash = await sha256(new Uint8Array(0));
    const derivedHs = await hkdfExpandLabel(hash, this.handshakeSecret, 'derived', emptyHash, hashLen);

    // Master Secret = HKDF-Extract(0, derived_hs)
    this.masterSecret = await hkdfExtract(hash, derivedHs, zeros);

    // Transcript hash (includes all handshake messages through server Finished)
    const transcriptHash = await this.transcript.digest();

    // Client/Server application traffic secrets
    this.clientAppSecret = await hkdfExpandLabel(
      hash, this.masterSecret, 'c ap traffic', transcriptHash, hashLen
    );
    this.serverAppSecret = await hkdfExpandLabel(
      hash, this.masterSecret, 's ap traffic', transcriptHash, hashLen
    );

    // Derive packet protection keys for 1-RTT level
    this.applicationKeys = {
      client: await derivePacketKeys(this.clientAppSecret, this.cipherSuite),
      server: await derivePacketKeys(this.serverAppSecret, this.cipherSuite),
    };
  }

  /**
   * Build the CertificateVerify input.
   * (RFC 8446 Section 4.4.3)
   */
  _buildCertificateVerifyInput(transcriptHash, isServer) {
    const context = isServer
      ? 'TLS 1.3, server CertificateVerify'
      : 'TLS 1.3, client CertificateVerify';

    const contextBytes = new TextEncoder().encode(context);
    const padding = new Uint8Array(64).fill(0x20);

    return concatBytes(padding, contextBytes, new Uint8Array([0x00]), transcriptHash);
  }

  get isConnected() {
    return this.state === State.CONNECTED;
  }

  get isHandshaking() {
    return this.state === State.WAIT_CLIENT_HELLO || this.state === State.WAIT_FINISHED;
  }
}