// https://github.com/endel/quic-zig/tree/wasm-experiment
/**
 * WebTransport client example using quic-zig WASM as the QUIC server.
 *
 * Architecture:
 *
 *   Browser WebTransport client (Chrome built-in QUIC)
 *       │
 *       │  raw QUIC/UDP packets
 *       ▼
 *   UDPSocket (Direct Sockets API)
 *       │
 *       │  Uint8Array ─── qz_recv_packet() ──► WASM QUIC state machine
 *       │                                         │
 *       │  Uint8Array ◄── qz_send_packets() ◄────┘
 *       │
 *       ▼
 *   Browser WebTransport client receives server response
 *
 * Data flow for a bidi stream echo:
 *
 *   1. WT client sends "hello" on a bidi stream
 *   2. Chrome encodes it as QUIC packets, arrives at UDPSocket
 *   3. feedPacket() copies Uint8Array into WASM memory → qz_recv_packet()
 *   4. qz_poll_event() returns EVT_WT_SESSION (CONNECT request)
 *   5. qz_wt_accept_session() sends HTTP/3 200
 *   6. qz_poll_event() returns EVT_WT_BIDI_STREAM (new bidi stream)
 *   7. qz_poll_eventconst certHash = await crypto.subtle.digest("SHA-256", certDer);() returns EVT_WT_STREAM_DATA (data available)
 *   8. qz_wt_read_stream() → "hello"        ← YOUR DECODED DATA IS HERE
 *   9. qz_wt_send_stream() ← "Echo: hello"  ← YOU WRITE RESPONSE DATA HERE
 *  10. qz_wt_close_stream()
 *  11. qz_send_packets() → response QUIC packets
 *  12. writer.write() sends them back to the WT client
 */

// ============================================================================
// STEP 1: Load WASM and set certificates
// ============================================================================
// import certificate from "./cert.json" with {type: "json"};
const runtime = navigator.userAgent;
let readFile = null;
let createSocket;
if (/Node.js|Deno|Bun/.test(runtime)) {
  ({ readFile } = await import("node:fs/promises"));
  ({ createSocket } = await import("node:dgram"));
} else {
  if (/txiki.js/.test(runtime)) {
    readFile = tjs.readFile;
  }
}

if (readFile === null) {
  readFile = async function (url) {
    return fetch(new URL(url, location.href))
      .then((r) => r.arrayBuffer());
  };
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();
let _sessionId = BigInt(0);
let interval = Promise.resolve();

async function loadWasm(wasmUrl, certDerUrl, keyDerUrl) {
  const [wasmBytes, certDer, keyDer] = await Promise.all([
    readFile(wasmUrl),
    readFile(certDerUrl),
    readFile(keyDerUrl),
  ]);
  // Import Memory into WASM from host
  /*
  const memory = new WebAssembly.Memory({
    initial: 85,
    maximum: 320,
  });
  */
  const { instance } = await WebAssembly.instantiate(wasmBytes, {
    env: {
      // memory,
      get_time_ns: () => BigInt(Math.round(performance.now() * 1_000_000)),
      console_log: (ptr, len) => {
        const bytes = new Uint8Array(instance.exports.memory.buffer, ptr, len);
        console.log("[wasm]", new TextDecoder().decode(bytes));
      },
      random_fill: (ptr, len) => {
        crypto.getRandomValues(
          new Uint8Array(instance.exports.memory.buffer, ptr, len),
        );
      },
    },
  });
  const wasm = instance.exports;

  // Set runtime certificates before init
  copyToWasm(
    wasm,
    new Uint8Array(certDer),
    (ptr, len) => wasm.qz_set_cert(ptr, len),
  );
  copyToWasm(
    wasm,
    new Uint8Array(keyDer),
    (ptr, len) => wasm.qz_set_key(ptr, len),
  );

  return wasm;
}

// ============================================================================
// STEP 2: Memory helpers
// ============================================================================

// Copy a Uint8Array into WASM memory, call fn(ptr, len), then free.
function copyToWasm(wasm, data, fn) {
  // if (!data) return;
  // data can be undefined here...
  if (data === void 0 || data.byteLength === 0) {
    return fn(0, 0);
  }
  const ptr = wasm.qz_alloc(data.byteLength);
  if (ptr === 0) {
    throw new Error("WASM allocation failed for " + data.byteLength + " bytes");
  }
  // NOTE: always create a fresh view — any prior WASM call may have
  // triggered memory.grow which detaches the old ArrayBuffer.
  new Uint8Array(wasm.memory.buffer, ptr, data.byteLength).set(data);
  const result = fn(ptr, data.byteLength);
  wasm.qz_free(ptr, data.byteLength);
  return result;
}

// Read bytes out of WASM memory into a new Uint8Array.
// Always copies immediately to avoid detached-buffer issues.
function readFromWasm(wasm, ptr, len) {
  return new Uint8Array(new Uint8Array(wasm.memory.buffer, ptr, len));
}

// ============================================================================
// STEP 3: Packet I/O — feeding packets in, draining packets out
// ============================================================================

// Feed a raw QUIC packet (Uint8Array) into the WASM state machine.
//
//   ┌─────────────────────────────────────────────────────┐
//   │  This is where UDP data ENTERS the QUIC server.     │
//   │  The packet is decrypted and parsed internally.     │
//   │  After this call, new events may be available via   │
//   │  qz_poll_event(), and response packets may be       │
//   │  waiting in qz_send_packets().                      │
//   └─────────────────────────────────────────────────────┘
//
function feedPacket(wasm, packet /* Uint8Array */) {
  copyToWasm(wasm, packet, (ptr, len) => wasm.qz_recv_packet(ptr, len));
}

// Drain all outgoing QUIC packets from the WASM state machine.
// Returns an array of Uint8Arrays, each a complete QUIC packet.
//
//   ┌─────────────────────────────────────────────────────┐
//   │  These are encrypted QUIC packets ready to send     │
//   │  back to the WebTransport client via UDPSocket.     │
//   └─────────────────────────────────────────────────────┘
//
function drainPackets(wasm) {
  const BUF = 65536;
  const ptr = wasm.qz_alloc(BUF);
  const total = wasm.qz_send_packets(ptr, BUF);
  const raw = readFromWasm(wasm, ptr, total);
  wasm.qz_free(ptr, BUF);

  const packets = [];
  let off = 0;
  while (off + 4 <= total) {
    const len = (raw[off] << 24) | (raw[off + 1] << 16) | (raw[off + 2] << 8) |
      raw[off + 3];
    off += 4;
    packets.push(raw.slice(off, off + len));
    off += len;
  }
  return packets;
}

// ============================================================================
// STEP 4: Event polling — reacting to decoded QUIC/H3/WT events
// ============================================================================

// Event type constants (must match wasm_api.zig)
const EVT_ESTABLISHED = 0x01;
const EVT_CLOSED = 0x02;
const EVT_WT_SESSION = 0x05;
const EVT_WT_BIDI_STREAM = 0x06;
const EVT_WT_STREAM_DATA = 0x07;
const EVT_WT_STREAM_FIN = 0x08;
const EVT_WT_DATAGRAM = 0x09;
const EVT_WT_SESSION_CLOSED = 0x0a;

function pollEvents(wasm, handlers) {
  const BUF = 1024;
  const ptr = wasm.qz_alloc(BUF);

  while (true) {
    const n = wasm.qz_poll_event(ptr, BUF);
    if (n === 0) {
      break;
    }

    const view = new DataView(wasm.memory.buffer, ptr, n);
    const type = view.getUint8(0);

    switch (type) {
      case EVT_ESTABLISHED:
        handlers.onEstablished?.();
        break;

      case EVT_CLOSED:
        handlers.onClosed?.();
        break;

        // ── WebTransport session request (Extended CONNECT) ──
        // The browser's WebTransport client sent a CONNECT request.
        // You MUST call qz_wt_accept_session() to send the 200 response.
      case EVT_WT_SESSION: {
        const sessionId = view.getBigUint64(1);
        handlers.onSessionRequest?.(sessionId);
        break;
      }

      // ── New bidi stream opened by the WT client ──
      // The stream_id identifies the QUIC stream to read/write.
      case EVT_WT_BIDI_STREAM: {
        const sessionId = view.getBigUint64(1);
        const streamId = view.getBigUint64(9);
        handlers.onBidiStream?.(sessionId, streamId);
        break;
      }

      // ── Data available on a WT stream ──
      //
      //   ┌─────────────────────────────────────────────────┐
      //   │  YOUR DECODED APPLICATION DATA IS HERE.         │
      //   │  Call qz_wt_read_stream(streamId, ...) to       │
      //   │  copy the decrypted bytes out of WASM memory.   │
      //   └─────────────────────────────────────────────────┘
      //
      case EVT_WT_STREAM_DATA: {
        const streamId = view.getBigUint64(1);
        const length = Number(view.getBigUint64(9));
        handlers.onStreamData?.(streamId, length);
        break;
      }

      // ── Stream FIN (remote side closed their send half) ──
      case EVT_WT_STREAM_FIN: {
        const streamId = view.getBigUint64(1);
        handlers.onStreamFinished?.(streamId);
        break;
      }

      // ── WT datagram received ──
      case EVT_WT_DATAGRAM: {
        const sessionId = view.getBigUint64(1);
        const length = Number(view.getBigUint64(9));
        handlers.onDatagram?.(sessionId, length);
        break;
      }

      // ── WT session closed by peer ──
      case EVT_WT_SESSION_CLOSED: {
        const sessionId = view.getBigUint64(1);
        const errorCode = view.getUint32(9);
        handlers.onSessionClosed?.(sessionId, errorCode);
        break;
      }
    }
  }
  wasm.qz_free(ptr, BUF);
}

// ============================================================================
// STEP 5: Reading and writing application data
// ============================================================================

// Read decoded stream data out of WASM.
//
//   ┌─────────────────────────────────────────────────────┐
//   │  This returns the actual application bytes that     │
//   │  the WebTransport client sent on a bidi/uni stream. │
//   │  The QUIC decryption + H3 framing is already done.  │
//   └─────────────────────────────────────────────────────┘
//
function readStreamData(wasm, streamId /* BigInt */) {
  const BUF = 65536;
  const ptr = wasm.qz_alloc(BUF);
  const chunks = [];

  while (true) {
    const n = wasm.qz_wt_read_stream(streamId, ptr, BUF);
    if (n <= 0) {
      break;
    }
    chunks.push(readFromWasm(wasm, ptr, n));
  }

  wasm.qz_free(ptr, BUF);
  return chunks;
}

// Write application data into the WASM state machine on a WT stream.
//
//   ┌─────────────────────────────────────────────────────┐
//   │  This is where you write your RESPONSE DATA.        │
//   │  The data will be H3-framed, encrypted, and         │
//   │  packed into QUIC packets on the next                │
//   │  qz_send_packets() call.                            │
//   └─────────────────────────────────────────────────────┘
//
function writeStreamData(wasm, streamId, /* BigInt */ data /* Uint8Array */) {
  copyToWasm(
    wasm,
    data,
    (ptr, len) => wasm.qz_wt_send_stream(streamId, ptr, len),
  );
}

// ============================================================================
// STEP 6: Full example — WASM WT server on a browser UDPSocket
// ============================================================================

async function main({
  reader,
  writer,
}) {
  let lastRemote = null;
  let timer = true;
  // --- Load WASM with runtime certs ---
  const wasm = await loadWasm("./quic.wasm", "./cert.der", "./key.der");
  wasm.qz_init_server();
  console.log("WASM QUIC server initialized");

  // --- Compute cert hash for WebTransport client ---
  const certDer = await readFile("./cert.der");
  const certHash = await crypto.subtle.digest("SHA-256", certDer);
  const CERT_DIGEST = new Uint8Array(certHash);
  console.log(
    "Cert SHA-256:",
    [...CERT_DIGEST].map((b) => b.toString(16).padStart(2, "0")).join(""),
  );
  console.log(
    "Cert SHA-256:",
    [...CERT_DIGEST].map((b) => b.toString(16).padStart(2, "0")).join(""),
  );

  // --- Open UDP socket ---
  // const socket = new UDPSocket({ localPort: 4433, localAddress: "0.0.0.0" });
  // const { readable, writable } = await socket.opened;
  // const writer = writable.getWriter();
  // let lastRemote = null;

  // Helper: send all pending WASM packets to the remote peer
  function flushToNetwork() {
    if (!lastRemote) {
      return;
    }
    for (const pkt of drainPackets(wasm)) {
      writer.write({
        data: pkt,
        remoteAddress: lastRemote.address,
        remotePort: lastRemote.port,
      });
    }
  }

  // --- Event handlers ---
  const handlers = {
    onEstablished() {
      console.log("QUIC connection established");
    },

    // Browser sent Extended CONNECT → accept the WT session
    onSessionRequest(sessionId) {
      console.log("WT session request, session_id:", sessionId);

      //   ┌─────────────────────────────────────────────────┐
      //   │  Accept the session. This sends an HTTP/3 200   │
      //   │  response back to the browser's WebTransport    │
      //   │  client, which resolves its .ready promise.     │
      //   └─────────────────────────────────────────────────┘
      wasm.qz_wt_accept_session(sessionId);
      _sessionId = sessionId;
    },

    // Browser opened a bidi stream on this session
    onBidiStream(sessionId, streamId) {
      console.log(`New bidi stream: session=${sessionId}, stream=${streamId}`);
    },

    // Data arrived on a WT stream
    onStreamData(streamId, length) {
      //   ┌─────────────────────────────────────────────────┐
      //   │  READ: the decrypted application data.          │
      //   │  This is what the browser's WT client sent.     │
      //   └─────────────────────────────────────────────────┘
      const [chunks] = readStreamData(wasm, streamId);
      // const text = chunks.map((c) => decoder.decode(c)).join("");
      // console.log(`Stream ${streamId} data (${length}B)`);

      //   ┌─────────────────────────────────────────────────┐
      //   │  WRITE: your modified/response data.            │
      //   │  This gets encrypted and sent back to the       │
      //   │  browser as QUIC packets.                       │
      //   └─────────────────────────────────────────────────┘
      // const response = encoder.encode("Echo: " + text);
      writeStreamData(wasm, streamId, chunks);

      // Don't close the stream — keep it open for full-duplex.
      // Close only when the remote sends FIN (onStreamFinished).
    },

    async onStreamFinished(streamId) {
      try {
        console.log(`Stream ${streamId} finished (remote FIN)`);
        while (writer.desiredSize < 1) {
          await new Promise((resolve) => setTimeout(resolve, 50));
        }
        timer = false;
        // Peer closed their send side — close ours too.
        wasm.qz_wt_close_stream(streamId);
        wasm.qz_wt_close_session(_sessionId);
        wasm.qz_deinit();
        console.log(wasm.qz_is_closed());
        writer.ready.then(() => writer.close()).catch(console.log);
        reader.cancel().catch(console.log);
      } catch (e) {
        console.log(e);
      }
    },

    onDatagram(sessionId, length) {
      // Read datagram stashed during WT poll
      const BUF = 1200;
      const ptr = wasm.qz_alloc(BUF);
      const n = wasm.qz_wt_read_datagram(sessionId, ptr, BUF);
      if (n > 0) {
        //   ┌─────────────────────────────────────────────────┐
        //   │  READ: decoded datagram payload.                │
        //   └─────────────────────────────────────────────────┘
        const data = readFromWasm(wasm, ptr, n);
        //  const text = decoder.decode(data);
        //  console.log(`Datagram on session ${sessionId}: "${text}"`);

        //   ┌─────────────────────────────────────────────────┐
        //   │  WRITE: echo the datagram back via WT layer.    │
        //   └─────────────────────────────────────────────────┘
        //  const response = encoder.encode("Echo: " + text);
        copyToWasm(
          wasm,
          data,
          (p, l) => wasm.qz_wt_send_datagram(sessionId, p, l),
        );
      }
      wasm.qz_free(ptr, BUF);
    },

    onSessionClosed(sessionId, errorCode) {
      console.log(`WT session ${sessionId} closed, code=${errorCode}`);
      timer = false;
      wasm.qz_wt_close_session(_sessionId);
      wasm.qz_deinit();
      console.log(wasm.qz_is_closed());
      writer.close().catch(console.log);
      reader.cancel().catch(console.log);
    },

    onClosed() {
      console.log("QUIC connection closed");
    },
  };

  // --- Receive loop: UDP → WASM → process → UDP ---
  const processStream = (async () => {
    while (true) {
      const {
        value,
        done,
      } = await reader.read();
      if (done) {
        break;
        return reader.closed;
      }
      const {
        data,
        remoteAddress,
        remotePort,
      } = value;
      lastRemote = {
        address: remoteAddress,
        port: remotePort,
      };

      //   ┌─────────────────────────────────────────────────┐
      //   │  INPUT: raw QUIC packet from the network.       │
      //   │  This is an encrypted UDP payload. The WASM     │
      //   │  state machine decrypts it, processes frames,   │
      //   │  and queues events + response packets.          │
      //   └─────────────────────────────────────────────────┘
      feedPacket(wasm, new Uint8Array(data));

      // Process any events that resulted from this packet
      pollEvents(wasm, handlers);

      //   ┌─────────────────────────────────────────────────┐
      //   │  OUTPUT: encrypted QUIC response packets.       │
      //   │  Send them back to the WebTransport client.     │
      //   └─────────────────────────────────────────────────┘
      flushToNetwork();
    }
  })().catch(console.log);

  // --- Timer loop: handle QUIC retransmits, PTO, keepalives ---
  interval.then(async () => {
    while (timer) {
      await new Promise((resolve) => setTimeout(resolve, 1));
      wasm.qz_on_timeout();
      pollEvents(wasm, handlers);
      flushToNetwork();
    }
  }).catch(console.log);

  // --- Connect the browser's WebTransport client ---
  console.log("Waiting for WebTransport client connection...");
  console.log("Connect with:");
  console.log(`
  var wt = new WebTransport("https://127.0.0.1:4433",{
    serverCertificateHashes: [{
      algorithm: "sha-256",
      value: new Uint8Array([${[...CERT_DIGEST].join(",")}]),
    }],
  });
  await wt.ready;
  // Read the echo back:
  var data = new Uint8Array(1024 ** 2);
  var len = 0;
  wt.closed.then(console.log).catch(console.error);
  // Send on a bidi stream:
  var wt_stream = await wt.createBidirectionalStream().catch(console.log);
  var wt_writer = wt_stream.writable.getWriter();
  await wt_writer.ready;
  // Read the echo back:
  wt_stream.readable.pipeTo(new WritableStream({
    write(value) {
      console.log(len += value.length);
      if (len === data.length) {
        // Chrome, Bun, Deno generally get here, Node.js and txiki.js don't
        console.log("Echo roundtrip complete");
        len = 0;
      }
    },
    close() {
      console.log("readable close");
    },
    abort(reason) {
      console.log(reason);
    }
  })).catch(console.log);
  await wt_writer.write(data);
  // await wt_writer.close();
  // wt.close({ closeCode: 4999, reason: "Done streaming." });
  `);
  return Promise.allSettled([reader.closed, writer.closed]).catch(console.log);
}
// TODO
class MulticastControllerImpl {
  #socket;
  #joinedGroups = new Set();

  constructor(socket) {
    this.#socket = socket;
  }

  async joinGroup(ipAddress) {
    return new Promise((resolve, reject) => {
      try {
        // Ensure the socket is bound and listening before joining
        // Node.js dgram throws if called on an unbound socket
        this.#socket.addMembership(ipAddress);
        this.#joinedGroups.add(ipAddress);
        resolve();
      } catch (e) {
        // Common errors: EADDRINUSE (if another process joined)
        // or EINVAL (if ipAddress is not a valid multicast address)
        reject(e);
      }
    });
  }

  async leaveGroup(ipAddress) {
    return new Promise((resolve, reject) => {
      try {
        this.#socket.dropMembership(ipAddress);
        this.#joinedGroups.delete(ipAddress);
        resolve();
      } catch (e) {
        reject(e);
      }
    });
  }

  get joinedGroups() {
    return Object.freeze([...this.#joinedGroups]);
  }
}
// Direct Sockets UDPSocket polyfill
class DirectSocketsUDPSocket {
  #socket;
  #opened;
  #closed;
  #resolveOpened;
  #rejectOpened;
  #resolveClosed;
  constructor(options = {}) {
    const type = options.ipv6Only ? "udp6" : "udp4";
    this.#socket = createSocket({
      type,
      reuseAddr: options.reuseAddr || options.multicastAllowAddressSharing,
    });
    this.#opened = new Promise((resolve, reject) => {
      this.#resolveOpened = resolve;
      this.#rejectOpened = reject;
    });
    this.#closed = new Promise((resolve) => {
      this.#resolveClosed = resolve;
    });
    this.#init(options);
  }
  #init(options) {
    this.#socket.on("error", (err) => {
      this.#rejectOpened(err);
      this.close();
    });
    this.#socket.bind({
      address: options.localAddress,
      port: options.localPort,
    }, () => {
      const addr = this.#socket.address();
      const readable = new ReadableStream({
        start: (controller) => {
          this.#socket.on("message", (msg, rinfo) => {
            controller.enqueue({
              data: new Uint8Array(msg.buffer, msg.byteOffset, msg.byteLength),
              remoteAddress: rinfo.address,
              remotePort: rinfo.port,
            });
          });
        },
      });
      const writable = new WritableStream({
        write: async (message) => {
          return new Promise((resolve, reject) => {
            this.#socket.send(
              message.data,
              message.remotePort,
              message.remoteAddress,
              (err) => {
                if (err) reject(err);
                else resolve();
              },
            );
          });
        },
      });
      this.#resolveOpened({
        readable,
        writable,
        localAddress: addr.address,
        localPort: addr.port,
        // TODO
        // multicastController: new MulticastControllerImpl(this.#socket),
      });
    });
  }
  get opened() {
    return this.#opened;
  }
  get closed() {
    return this.#closed;
  }
  close() {
    try {
      this.#socket.close();
    } catch (e) {
      // Already closed
      console.log(e);
    }
    this.#resolveClosed();
  }
}

if (!Object.hasOwn(globalThis, "UDPSocket")) {
  globalThis.UDPSocket = class UDPSocket extends DirectSocketsUDPSocket {
    constructor(options) {
      super(options);
    }
  };
}

const stream = new ReadableStream({
  async start(controller) {
    console.log("Starting WebTransportServerSocket");
  },
  async pull(controller) {
    const socket = new UDPSocket({
      localPort: 4433,
      localAddress: "0.0.0.0",
    });
    controller.enqueue({
      socket,
    });
    await socket.closed;
    // For Deno, to prevent Error: bind EADDRINUSE 0.0.0.0:4433
    // pull() is called immediately
    if (runtime.startsWith("Deno")) {
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
  },
  cancel(reason) {
    console.log({ reason });
  },
});

async function webTransportServerSocket(socketStream) {
  for await (const { socket } of socketStream) {
    try {
      const { readable, writable } = await socket.opened.catch((e) => {
        console.log(e);
        throw e;
      });
      console.log(socket, readable, writable);
      socket.closed.then(console.log).catch(console.log);
      const writer = writable.getWriter();
      const reader = readable.getReader();
      await main({
        reader,
        writer,
      }).then((result) =>
        console.log({
          result,
        })
      ).catch((e) => {
        console.log(e);
      });
      socket.close();
      await socket.closed;
    } catch (e) {
      console.error(e);
      break;
    } finally {
      // continue;
    }
  }
}

webTransportServerSocket(stream).catch(console.log);

/*
class UDPDemultiplexer {
  #sessions = new Map();

  constructor(socket) {
    this.socket = socket;
  }

  async start(sessionHandler) {
    // Await the opened promise and destructure the stream objects
    const openedInfo = await this.socket.opened;
    if (!openedInfo || !openedInfo.readable) {
        throw new Error("Socket failed to provide a readable stream");
    }

    const { readable, writable } = openedInfo;
    const reader = readable.getReader();
    const writer = writable.getWriter();

    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;

        const sessionKey = `${value.remoteAddress}:${value.remotePort}`;

        if (!this.#sessions.has(sessionKey)) {
          const session = this.#createSession(sessionKey, writer, value.remoteAddress, value.remotePort);
          this.#sessions.set(sessionKey, session);

          sessionHandler(session).finally(() => {
            this.#sessions.delete(sessionKey);
          });
        }

        const { controller } = this.#sessions.get(sessionKey);
        controller.enqueue(value.data);
      }
    } finally {
      reader.releaseLock();
    }
  }

  #createSession(key, sharedWriter, remoteAddress, remotePort) {
    let controller;
    const readable = new ReadableStream({
      start(c) { controller = c; }
    });

    const writable = new WritableStream({
      write: (chunk) => sharedWriter.write({
        data: chunk,
        remoteAddress,
        remotePort
      })
    });

    return { readable, writable, controller };
  }
}

(async () => {
  const serverSocket = new UDPSocket({
    localPort: 4433,
    localAddress: "0.0.0.0",
    reuseAddr: true
  });

  const mux = new UDPDemultiplexer(serverSocket);

  console.log("Server listening on 4433...");

  // This will trigger for EVERY unique client IP/Port combo
  await mux.start(async ({ reader, writer }) => {
    try {
      console.log("New virtual session detected");

      // Run your WebTransport/App logic here
      await main({ reader, writer });

    } catch (e) {
      console.error("Session error:", e);
    }
  });
})();
*/
