/**
 * QUIC Protocol Constants and Types (RFC 9000)
 */

// QUIC versions
export const QUIC_VERSION_1 = 0x00000001;
export const QUIC_VERSION_2 = 0x6b3343cf;

// Long header packet types (RFC 9000 Section 17.2)
export const PacketType = {
  INITIAL:   0x00,
  ZERO_RTT:  0x01,
  HANDSHAKE: 0x02,
  RETRY:     0x03,
};

// Frame types (RFC 9000 Section 19)
export const FrameType = {
  PADDING:                0x00,
  PING:                   0x01,
  ACK:                    0x02,
  ACK_ECN:               0x03,
  RESET_STREAM:          0x04,
  STOP_SENDING:          0x05,
  CRYPTO:                0x06,
  NEW_TOKEN:             0x07,
  STREAM:                0x08, // 0x08 - 0x0f (with flags)
  MAX_DATA:              0x10,
  MAX_STREAM_DATA:       0x11,
  MAX_STREAMS_BIDI:      0x12,
  MAX_STREAMS_UNI:       0x13,
  DATA_BLOCKED:          0x14,
  STREAM_DATA_BLOCKED:   0x15,
  STREAMS_BLOCKED_BIDI:  0x16,
  STREAMS_BLOCKED_UNI:   0x17,
  NEW_CONNECTION_ID:     0x18,
  RETIRE_CONNECTION_ID:  0x19,
  PATH_CHALLENGE:        0x1a,
  PATH_RESPONSE:         0x1b,
  CONNECTION_CLOSE:      0x1c,
  CONNECTION_CLOSE_APP:  0x1d,
  HANDSHAKE_DONE:        0x1e,
  // Extension: DATAGRAM (RFC 9221)
  DATAGRAM:              0x30,
  DATAGRAM_LEN:          0x31,
};

// Transport parameters (RFC 9000 Section 18.2)
export const TransportParamId = {
  ORIGINAL_DESTINATION_CONNECTION_ID: 0x00,
  MAX_IDLE_TIMEOUT:                   0x01,
  STATELESS_RESET_TOKEN:              0x02,
  MAX_UDP_PAYLOAD_SIZE:               0x03,
  INITIAL_MAX_DATA:                   0x04,
  INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: 0x05,
  INITIAL_MAX_STREAM_DATA_BIDI_REMOTE:0x06,
  INITIAL_MAX_STREAM_DATA_UNI:        0x07,
  INITIAL_MAX_STREAMS_BIDI:           0x08,
  INITIAL_MAX_STREAMS_UNI:            0x09,
  ACK_DELAY_EXPONENT:                 0x0a,
  MAX_ACK_DELAY:                      0x0b,
  DISABLE_ACTIVE_MIGRATION:           0x0c,
  PREFERRED_ADDRESS:                  0x0d,
  ACTIVE_CONNECTION_ID_LIMIT:         0x0e,
  INITIAL_SOURCE_CONNECTION_ID:       0x0f,
  RETRY_SOURCE_CONNECTION_ID:         0x10,
  // WebTransport extension
  MAX_DATAGRAM_FRAME_SIZE:            0x0020,
  // HTTP/3 SETTINGS for WebTransport
  ENABLE_WEBTRANSPORT:                0x2b603742,
};

// QUIC error codes (RFC 9000 Section 20)
export const TransportError = {
  NO_ERROR:                  0x00,
  INTERNAL_ERROR:            0x01,
  CONNECTION_REFUSED:        0x02,
  FLOW_CONTROL_ERROR:        0x03,
  STREAM_LIMIT_ERROR:        0x04,
  STREAM_STATE_ERROR:        0x05,
  FINAL_SIZE_ERROR:          0x06,
  FRAME_ENCODING_ERROR:      0x07,
  TRANSPORT_PARAMETER_ERROR: 0x08,
  CONNECTION_ID_LIMIT_ERROR: 0x09,
  PROTOCOL_VIOLATION:        0x0a,
  INVALID_TOKEN:             0x0b,
  APPLICATION_ERROR:         0x0c,
  CRYPTO_BUFFER_EXCEEDED:    0x0d,
  KEY_UPDATE_ERROR:          0x0e,
  AEAD_LIMIT_REACHED:        0x0f,
  NO_VIABLE_PATH:            0x10,
  CRYPTO_ERROR:              0x100, // 0x100 - 0x1ff
};

// Stream types
export const StreamType = {
  CLIENT_BIDI: 0x00,
  SERVER_BIDI: 0x01,
  CLIENT_UNI:  0x02,
  SERVER_UNI:  0x03,
};

// Connection states
export const ConnectionState = {
  IDLE:            'idle',
  HANDSHAKE:       'handshake',
  HANDSHAKE_DONE:  'handshake_done',
  CONNECTED:       'connected',
  CLOSING:         'closing',
  DRAINING:        'draining',
  CLOSED:          'closed',
};

// Encryption levels
export const EncryptionLevel = {
  INITIAL:   'initial',
  HANDSHAKE: 'handshake',
  ZERO_RTT:  '0-rtt',
  ONE_RTT:   '1-rtt',
};

// Default transport parameters for our server
export const DEFAULT_SERVER_TRANSPORT_PARAMS = {
  maxIdleTimeout: 30000,               // 30 seconds
  maxUdpPayloadSize: 1200,             // conservative minimum
  initialMaxData: 1048576,             // 1 MB
  initialMaxStreamDataBidiLocal: 262144,  // 256 KB
  initialMaxStreamDataBidiRemote: 262144,
  initialMaxStreamDataUni: 262144,
  initialMaxStreamsBidi: 100,
  initialMaxStreamsUni: 100,
  ackDelayExponent: 3,
  maxAckDelay: 25,
  disableActiveMigration: false,
  activeConnectionIdLimit: 8,
  maxDatagramFrameSize: 65535,         // WebTransport datagrams
};