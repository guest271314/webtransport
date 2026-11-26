//! quico-bundle-run.js
//! guest271314 11-24-2026
//! node quico-bundle-run.js
//! deno -A quico-bundle-run.js
//! bun -b quico-bundle-run.js
//! tjs run quico-bundle-run.js
//! chrome <devtools> quico-bundle-run.js
//! QUICO_DEBUG=1 <runtime> quico-bundle-run.js

const ua = globalThis.navigator?.userAgent ?? "";
const isDeno = ua.startsWith("Deno");
const isTjs = ua.startsWith("txiki.js");
const isBun = ua.startsWith("Bun");
const isBrowser = typeof globalThis.document !== "undefined";

// 1. Universal WICG Direct Sockets UDPSocket Polyfill
// Native globalThis.UDPSocket is used automatically when present (Chrome Direct Sockets).
if (typeof globalThis.UDPSocket === "undefined") {
  class UDPSocket {
    #socket = null;
    #mode;
    #remoteAddress;
    #remotePort;
    #openedResolve;
    #openedReject;
    #closedResolve;
    #closedReject;
    #closePromise = null;

    constructor(options = {}) {
      this.opened = new Promise((resolve, reject) => {
        this.#openedResolve = resolve;
        this.#openedReject = reject;
      });

      this.closed = new Promise((resolve, reject) => {
        this.#closedResolve = resolve;
        this.#closedReject = reject;
      });

      this.#init(options).catch((err) => {
        this.#openedReject(err);
        this.closed.catch(() => {});
        this.#closedReject(err);
      });
    }

    async #init(options) {
      const {
        remoteAddress,
        remotePort,
        localAddress,
        localPort,
        sendBufferSize,
        receiveBufferSize,
        dnsQueryType,
        ipv6Only = false,
        multicastAllowAddressSharing = false,
      } = options;

      const hasRemote = remoteAddress !== undefined || remotePort !== undefined;
      const hasLocal = localAddress !== undefined || localPort !== undefined;

      if ((hasRemote && hasLocal) || (!hasRemote && !hasLocal)) {
        throw new DOMException(
          "Specify either (remoteAddress + remotePort) or (localAddress).",
          "InvalidAccessError",
        );
      }

      if (hasRemote && (!remoteAddress || remotePort === undefined)) {
        throw new DOMException(
          "Both remoteAddress and remotePort are required for connected mode.",
          "InvalidAccessError",
        );
      }

      if (hasLocal && !localAddress) {
        throw new DOMException(
          "localAddress is required for bound mode.",
          "InvalidAccessError",
        );
      }

      this.#mode = hasRemote ? "connected" : "bound";

      // --- A. txiki.js (tjs.listen) ---
      if (isTjs) {
        if (this.#mode === "connected") {
          this.#remoteAddress = remoteAddress;
          this.#remotePort = remotePort;
          this.#socket = await globalThis.tjs.listen(
            "udp",
            remoteAddress.includes(":") ? "::" : "0.0.0.0",
            0,
          );
        } else {
          this.#socket = await globalThis.tjs.listen(
            "udp",
            localAddress,
            localPort || 0,
            {
              reuseAddr: Boolean(multicastAllowAddressSharing),
              ipv6Only: Boolean(ipv6Only),
            },
          );
        }

        const addr = this.#socket.localAddress;
        const openInfo = {
          readable: this.#createTjsReadableStream(),
          writable: this.#createTjsWritableStream(),
          localAddress: addr.ip,
          localPort: addr.port,
        };

        if (this.#mode === "connected") {
          openInfo.remoteAddress = this.#remoteAddress;
          openInfo.remotePort = this.#remotePort;
        }

        this.#openedResolve(openInfo);
        return;
      }

      // --- B. Node.js / Deno / Bun (node:dgram) ---
      const dgram = await import("node:dgram");
      const dns = await import("node:dns/promises");
      const net = await import("node:net");

      let targetIp = remoteAddress;
      let family = 4;

      if (this.#mode === "connected") {
        const ipVersion = net.isIP(remoteAddress);
        if (ipVersion) {
          family = ipVersion;
        } else {
          const lookupOpts = dnsQueryType === "ipv6"
            ? { family: 6 }
            : dnsQueryType === "ipv4"
            ? { family: 4 }
            : {};
          const resolved = await dns.lookup(remoteAddress, lookupOpts);
          targetIp = resolved.address;
          family = resolved.family;
        }
        this.#remoteAddress = targetIp;
        this.#remotePort = remotePort;
      } else {
        const ipVersion = net.isIP(localAddress);
        if (!ipVersion) {
          throw new DOMException(
            "localAddress must be a valid IP address.",
            "InvalidAccessError",
          );
        }
        family = ipVersion;
      }

      const socketType = family === 6 ? "udp6" : "udp4";
      this.#socket = dgram.createSocket({ type: socketType });

      this.#socket.on("error", (err) => {
        if (!this.#closePromise) {
          this.#closePromise = Promise.resolve();
          this.#closedReject(new DOMException(err.message, "NetworkError"));
        }
      });

      await new Promise((resolve, reject) => {
        const onError = (err) =>
          reject(new DOMException(err.message, "NetworkError"));
        this.#socket.once("error", onError);

        if (this.#mode === "bound") {
          this.#socket.bind(localPort || 0, localAddress, () => {
            this.#socket.off("error", onError);
            resolve();
          });
        } else {
          this.#socket.connect(this.#remotePort, this.#remoteAddress, () => {
            this.#socket.off("error", onError);
            resolve();
          });
        }
      });

      try {
        if (sendBufferSize) this.#socket.setSendBufferSize(sendBufferSize);
        if (receiveBufferSize) {
          this.#socket.setRecvBufferSize(receiveBufferSize);
        }
      } catch {}

      const localInfo = this.#socket.address();
      const openInfo = {
        readable: this.#createNodeReadableStream(),
        writable: this.#createNodeWritableStream(),
        localAddress: localInfo.address,
        localPort: localInfo.port,
      };

      if (this.#mode === "connected") {
        openInfo.remoteAddress = this.#remoteAddress;
        openInfo.remotePort = this.#remotePort;
      }

      this.#openedResolve(openInfo);
    }
    #createTjsReadableStream() {
      return new ReadableStream({
        pull: async (controller) => {
          try {
            const buf = new Uint8Array(65536);
            const { nread, addr } = await this.#socket.recv(buf);
            if (nread === null) {
              controller.close();
              return;
            }
            const data = buf.slice(0, nread);
            const packet = this.#mode === "bound"
              ? { data, remoteAddress: addr.ip, remotePort: addr.port }
              : { data };
            controller.enqueue(packet);
          } catch (err) {
            if (this.#closePromise) {
              try {
                controller.close();
              } catch {}
            } else {
              controller.error(new DOMException(err.message, "NetworkError"));
            }
          }
        },
        cancel: () => this.close(),
      });
    }

    #createTjsWritableStream() {
      return new WritableStream({
        write: async (chunk) => {
          if (!chunk || !chunk.data) {
            throw new TypeError(
              "UDPMessage must contain a 'data' BufferSource.",
            );
          }
          const view = ArrayBuffer.isView(chunk.data)
            ? new Uint8Array(
              chunk.data.buffer,
              chunk.data.byteOffset,
              chunk.data.byteLength,
            )
            : new Uint8Array(chunk.data);

          const ip = this.#mode === "connected"
            ? this.#remoteAddress
            : chunk.remoteAddress;
          const port = this.#mode === "connected"
            ? this.#remotePort
            : chunk.remotePort;

          await this.#socket.send(view, { ip, port });
        },
        close: () => this.close(),
        abort: () => this.close(),
      });
    }

    #createNodeReadableStream() {
      return new ReadableStream({
        start: (controller) => {
          this.#socket.on("message", (msg, rinfo) => {
            const data = new Uint8Array(msg.byteLength);
            data.set(
              new Uint8Array(msg.buffer, msg.byteOffset, msg.byteLength),
            );

            const packet = this.#mode === "bound"
              ? { data, remoteAddress: rinfo.address, remotePort: rinfo.port }
              : { data };
            controller.enqueue(packet);
          });
          this.#socket.on("close", () => {
            try {
              controller.close();
            } catch {}
          });
        },
        cancel: () => this.close(),
      });
    }

    #createNodeWritableStream() {
      return new WritableStream({
        write: async (chunk) => {
          if (!chunk || !chunk.data) {
            throw new TypeError(
              "UDPMessage must contain a 'data' BufferSource.",
            );
          }
          const view = ArrayBuffer.isView(chunk.data)
            ? new Uint8Array(
              chunk.data.buffer,
              chunk.data.byteOffset,
              chunk.data.byteLength,
            )
            : new Uint8Array(chunk.data);

          const payload = typeof globalThis.Buffer !== "undefined"
            ? globalThis.Buffer.from(
              view.buffer,
              view.byteOffset,
              view.byteLength,
            )
            : view;

          if (this.#mode === "connected") {
            if (chunk.remoteAddress || chunk.remotePort) {
              throw new DOMException(
                "remoteAddress/remotePort cannot be set on connected UDPSocket.",
                "InvalidAccessError",
              );
            }
            await new Promise((resolve, reject) => {
              this.#socket.send(
                payload,
                (err) => (err ? reject(err) : resolve()),
              );
            });
          } else {
            if (!chunk.remoteAddress || chunk.remotePort === undefined) {
              throw new DOMException(
                "remoteAddress and remotePort are required in bound mode.",
                "InvalidAccessError",
              );
            }
            await new Promise((resolve, reject) => {
              this.#socket.send(
                payload,
                chunk.remotePort,
                chunk.remoteAddress,
                (err) => (err ? reject(err) : resolve()),
              );
            });
          }
        },
        close: () => this.close(),
        abort: () => this.close(),
      });
    }

    close() {
      if (this.#closePromise) return this.#closePromise;

      this.#closePromise = new Promise((resolve) => {
        if (!this.#socket) {
          this.#closedResolve();
          return resolve();
        }
        try {
          if (isTjs) {
            this.#socket.close();
            this.#closedResolve();
            resolve();
          } else {
            this.#socket.close(() => {
              this.#closedResolve();
              resolve();
            });
          }
        } catch {
          this.#closedResolve();
          resolve();
        }
      });

      return this.#closePromise;
    }
  }

  globalThis.UDPSocket = UDPSocket;
}

// 2. Browser-bundle globals shim
if (typeof globalThis.process === "undefined") {
  globalThis.process = {
    env: {},
    version: "v20.0.0",
    nextTick: (fn, ...args) => queueMicrotask(() => fn(...args)),
  };
}

if (typeof globalThis.setImmediate !== "function") {
  let nextId = 1;
  const tasks = new Map();
  const channel = new MessageChannel();

  channel.port1.onmessage = ({ data: id }) => {
    const task = tasks.get(id);
    if (!task) return;
    tasks.delete(id);
    task.fn(...task.args);
  };

  globalThis.setImmediate = (fn, ...args) => {
    const id = nextId++;
    tasks.set(id, { fn, args });
    channel.port2.postMessage(id);
    return id;
  };

  globalThis.clearImmediate = (id) => {
    tasks.delete(id);
  };
}
// 3. Resolve base URL for assets
async function resolveBase() {
  if (globalThis.__ASSET_BASE__) {
    return new URL(
      globalThis.__ASSET_BASE__,
      globalThis.location?.href ?? "file:///",
    ).href;
  }
  if (globalThis.document?.baseURI) return globalThis.document.baseURI;
  if (isDeno) return globalThis.Deno.mainModule;
  if (isTjs) {
    const cwd = typeof globalThis.tjs.cwd === "function"
      ? globalThis.tjs.cwd()
      : globalThis.tjs.cwd;
    return `file://${cwd}/`;
  }
  const { pathToFileURL } = await import("node:url");
  return pathToFileURL(globalThis.process.argv[1]).href;
}

const BASE = await resolveBase();

const { createH3Server } = await import(
  new URL("./quico-bundle-min.js", BASE).href
);

async function loadAsset(relativePath, asText = true) {
  const url = new URL(relativePath, BASE);
  try {
    const res = await fetch(url);
    if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
    return asText ? await res.text() : new Uint8Array(await res.arrayBuffer());
  } catch (err) {
    if (isBrowser) throw err;
    if (isTjs) {
      const bytes = await globalThis.tjs.readFile(url.pathname);
      return asText ? new TextDecoder().decode(bytes) : bytes;
    }
    const fs = await import("node:fs/promises");
    return asText
      ? await fs.readFile(url, "utf8")
      : new Uint8Array(await fs.readFile(url));
  }
}

// const key = await loadAsset("./key.pem", true);
// const cert = await loadAsset("./cert.pem", true);
// const certDer = await loadAsset("./cert.der", false);

import certificates from "./cert.json" with { type: "json" };
const { cert, key, certHash } = certificates;

// const certHash = await crypto.subtle.digest("SHA-256", certDer);
const CERT_DIGEST = new Uint8Array(certHash);

// 4. WebTransport over WICG Direct Sockets server
async function startDirectSocketsWebTransport({
  keyPem,
  certPem,
  localAddress = "0.0.0.0",
  localPort = 4433,
}) {
  const udp = new UDPSocket({ localAddress, localPort });
  udp.closed.then(console.log).catch(console.error).then(() =>
    console.log("UDPSocket closed")
  );

  const { readable, writable, localAddress: boundAddr, localPort: boundPort } =
    await udp.opened;
  const writer = writable.getWriter();
  const reader = readable.getReader();

  const externalSocket = {
    address() {
      return {
        address: boundAddr,
        port: boundPort,
        family: boundAddr.includes(":") ? "IPv6" : "IPv4",
      };
    },
    send(msg, offset, length, port, address, cb) {
      if (
        typeof offset === "number" &&
        typeof length === "number" &&
        typeof port === "number"
      ) {
        msg = msg.subarray(offset, offset + length);
      } else {
        cb = address;
        address = length;
        port = offset;
      }

      const data = new Uint8Array(msg.byteLength);
      data.set(new Uint8Array(msg.buffer, msg.byteOffset, msg.byteLength));

      writer
        .write({ data, remoteAddress: address, remotePort: port })
        .then(() => cb?.(null))
        .catch((err) => {
          console.error("UDPSocket write failed:", err);
          cb?.(err);
        });
    },
    close(cb) {
      Promise.allSettled([reader.cancel(), writer.close(), udp.close()]).then(
        () => cb?.(),
      );
    },
  };

  const server = createH3Server(
    {
      key: keyPem,
      cert: certPem,
      socket: externalSocket,
    },
    (req, res) => {
      if (req.headers[":protocol"] !== "webtransport") {
        res.writeHead(404);
        res.end("WebTransport only");
        return;
      }

      if (req.webTransportProtocols?.length) {
        res.setWebTransportProtocol(req.webTransportProtocols);
      }

      res.writeHead(200);
      console.log("WebTransport session connected:", req.url);

      // 1. Server-initiated bidirectional stream (Node Duplex)
      const bidi = res.createBidirectionalStream();
      bidi.write("hello from server");
      bidi.on("data", (chunk) => {
        console.log("Client replied on server stream:", chunk.toString());
      });
      bidi.end();

      // 2. Server-initiated unidirectional stream (Node Writable)
      const uni = res.createUnidirectionalStream(
        { waitUntilAvailable: true, sendOrder: 5 },
        (err) => {
          if (err) return; // Session closed before client granted stream credit
          console.log("Unidirectional stream is open");
        },
      );
      uni.write("one-way push payload");
      uni.end();

      req.on("close", () => {
        console.log("WebTransport session closed:", req.url);
        console.log("closeInfo", req.closeInfo);
      });

      req.on("stream", (stream) => {
        stream.on("data", (chunk) => stream.write(chunk));
        stream.on("end", () => stream.end());
      });

      req.on("unidirectionalStream", (readableStream) => {
        const writableStream = res.createUnidirectionalStream();
        readableStream.pipe(writableStream);
      });

      req.on("datagram", (data) => {
        res.sendDatagram(data);
      });
    },
  );

  (async () => {
    while (true) {
      let r;
      try {
        r = await reader.read();
      } catch (err) {
        console.error("UDPSocket read error:", err);
        break;
      }
      if (r.done) break;
      try {
        server.handlePacket(r.value.data, {
          address: r.value.remoteAddress,
          port: r.value.remotePort,
          family: r.value.remoteAddress.includes(":") ? "IPv6" : "IPv4",
          size: r.value.data.byteLength,
        });
      } catch (err) {
        console.error("handlePacket failed:", err);
      }
    }
  })();

  console.log(
    "Cert SHA-256:",
    [...CERT_DIGEST].map((b) => b.toString(16).padStart(2, "0")).join(""),
  );
  console.log(`WebTransport server bound on ${boundAddr}:${boundPort}`);
  console.log("Waiting for WebTransport client connection...");
  console.log("Connect with:");
  const clientCode = `
var wt = new WebTransport("https://127.0.0.1:4433", {
  serverCertificateHashes: [{
    algorithm: "sha-256",
    value: new Uint8Array([${[...CERT_DIGEST].join(",")}]),
  }],
});
await wt.ready.catch((e) => console.log(e));

// Handle incoming server-initiated bidirectional streams
(async () => {
  const reader = wt.incomingBidirectionalStreams.getReader();
  while (true) {
    const { value: stream, done } = await reader.read();
    if (done) break;

    // stream has WHATWG { readable, writable }
    const textReader = stream.readable.pipeThrough(new TextDecoderStream())
      .getReader();
    const { value } = await textReader.read();
    console.log("Received:", value);

    const writer = stream.writable.getWriter();
    await writer.write(new TextEncoder().encode("ack from client"));
    await writer.close();
  }
})();

// Handle incoming server-initiated unidirectional streams
(async () => {
  const reader = wt.incomingUnidirectionalStreams.getReader();
  // console.log(reader);
  while (true) {
    const { value: readable, done } = await reader.read();
    if (done) break;

    for await (const chunk of readable) {
      console.log("Push chunk:", new TextDecoder().decode(chunk));
    }
  }
})();
var data = new Uint8Array(1024);
var len = 0;
wt.closed.then(console.log).catch(console.error);
var wt_stream = await wt.createBidirectionalStream().catch(console.log);
var wt_writer = wt_stream.writable.getWriter();
await wt_writer.ready;
wt_stream.readable.pipeTo(
  new WritableStream({
    async write(value) {
      console.log(len += value.length);
      if (len === data.length) {
        console.log("Echo roundtrip complete");
        len = 0;
        await wt_writer.close();
        wt.close({ closeCode: 4999, reason: "Done streaming." });
        await new Promise((r) => setTimeout(r, 1000));
        process.exit(0);
      }
    },
    close() {
      console.log("readable close");
    },
    abort(reason) {
      console.log(reason);
    },
  }),
  { highWaterMark: Infinity },
).catch(console.log);
await wt_writer.write(data);
  `;
  console.log(clientCode);
  return server;
}

if (!globalThis.__WT_SERVER_STARTED__) {
  globalThis.__WT_SERVER_STARTED__ = true;
  startDirectSocketsWebTransport({ keyPem: key, certPem: cert }).catch(
    console.error,
  );
}

globalThis.addEventListener?.("unhandledrejection", (e) => {
  console.error("unhandledrejection:", e.reason);
});
globalThis.addEventListener?.("error", (e) => {
  console.error("uncaught:", e.error ?? e.message);
});
