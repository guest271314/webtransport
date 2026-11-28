// tjs-shims.js — runtime shims so the quico *browser* bundle runs on txiki.js.
// Import this BEFORE the patched bundle:  import "./tjs-shims.js";
//
// Provides:
//   globalThis.__tjs_dgram  -> node:dgram subset (createSocket) over WICG Direct Sockets UDPSocket
//   globalThis.__tjs_dns    -> node:dns subset (lookup) over tjs.getaddrinfo
//   globalThis.process      -> minimal (nextTick, env, platform, exit, emitWarning, ...)
//   setImmediate / clearImmediate, ReadableStream async iteration, TextDecoderStream/TextEncoderStream
//
// Needs globalThis.UDPSocket (Direct Sockets) and tjs.getaddrinfo (for non-literal hostnames).

const tjsRT = globalThis.tjs;
// Packet-level tracing (off by default): TJS_SHIM_DEBUG=1 tjs run wtclient-tjs.js
let envFlag;
try { envFlag = tjsRT?.env?.TJS_SHIM_DEBUG ?? globalThis.process?.env?.TJS_SHIM_DEBUG; } catch {}
const DBG = globalThis.__TJS_SHIM_DEBUG ?? (envFlag === "1"); // opt-in: TJS_SHIM_DEBUG=1
const dbg = (...a) => DBG && console.log("[shim]", ...a);

// ---------- tiny EventEmitter (can't import node:events in tjs) ----------
class Emitter {
  #h = new Map();
  on(ev, fn) { (this.#h.get(ev) ?? this.#h.set(ev, []).get(ev)).push(fn); return this; }
  addListener(ev, fn) { return this.on(ev, fn); }
  once(ev, fn) {
    const w = (...a) => { this.off(ev, w); fn.apply(this, a); };
    w.listener = fn;
    return this.on(ev, w);
  }
  off(ev, fn) {
    const l = this.#h.get(ev);
    if (l) this.#h.set(ev, l.filter((f) => f !== fn && f.listener !== fn));
    return this;
  }
  removeListener(ev, fn) { return this.off(ev, fn); }
  removeAllListeners(ev) { ev === undefined ? this.#h.clear() : this.#h.delete(ev); return this; }
  emit(ev, ...a) {
    const l = this.#h.get(ev);
    if (!l || !l.length) {
      if (ev === "error") throw a[0];
      return false;
    }
    for (const f of [...l]) f.apply(this, a);
    return true;
  }
}

// ---------- process ----------
{
  const p = (globalThis.process ??= {});
  p.nextTick ??= (fn, ...args) => queueMicrotask(() => fn(...args));
  p.env ??= { ...(tjsRT?.env ?? {}) };
  p.platform ??= "linux"; // only compared against "win32" in the bundle
  p.version ??= "v0.0.0";
  p.versions ??= {};
  p.pid ??= 0;
  p.browser ??= false;
  p.cwd ??= () => "/";
  p.emitWarning ??= (w) => console.warn(String(w?.message ?? w));
  p.stdout ??= { write: (s) => (console.log(String(s).replace(/\n$/, "")), true) };
  p.stderr ??= { write: (s) => (console.error(String(s).replace(/\n$/, "")), true), isTTY: false };
  p.exit ??= (code = 0) => tjsRT.exit(code);
}

// ---------- setImmediate ----------
globalThis.setImmediate ??= (fn, ...a) => setTimeout(fn, 0, ...a);
globalThis.clearImmediate ??= (id) => clearTimeout(id);

// ---------- Web streams extras ----------
if (globalThis.ReadableStream && !ReadableStream.prototype[Symbol.asyncIterator]) {
  ReadableStream.prototype[Symbol.asyncIterator] = async function* () {
    const r = this.getReader();
    try {
      for (;;) {
        const { value, done } = await r.read();
        if (done) return;
        yield value;
      }
    } finally {
      r.releaseLock();
    }
  };
}
if (!globalThis.TextDecoderStream && globalThis.TransformStream) {
  globalThis.TextDecoderStream = class TextDecoderStream {
    constructor(label = "utf-8", opts) {
      const dec = new TextDecoder(label, opts);
      const ts = new TransformStream({
        transform(chunk, c) { const s = dec.decode(chunk, { stream: true }); if (s) c.enqueue(s); },
        flush(c) { const s = dec.decode(); if (s) c.enqueue(s); },
      });
      this.readable = ts.readable;
      this.writable = ts.writable;
      this.encoding = dec.encoding;
    }
  };
}
if (!globalThis.TextEncoderStream && globalThis.TransformStream) {
  globalThis.TextEncoderStream = class TextEncoderStream {
    constructor() {
      const enc = new TextEncoder();
      const ts = new TransformStream({ transform(s, c) { c.enqueue(enc.encode(s)); } });
      this.readable = ts.readable;
      this.writable = ts.writable;
      this.encoding = "utf-8";
    }
  };
}

// =====================================================================
// node:dgram subset over WICG Direct Sockets (bound-mode UDPSocket)
// =====================================================================
const DEFAULT_BUF = 4 << 20; // matches the bundle's DEFAULT_SOCKET_BUFFER_SIZE

async function openUdp(type) {
  if (typeof globalThis.UDPSocket !== "function") throw new Error("Direct Sockets UDPSocket is not available");
  const base = { localAddress: type === "udp6" ? "::" : "0.0.0.0" }; // bound mode: no remote*, ephemeral port
  const open = async (opts) => {
    dbg("new UDPSocket", JSON.stringify(opts));
    const sock = new UDPSocket(opts);
    dbg("constructed; awaiting socket.opened");
    const t = setTimeout(() => dbg("WARNING: socket.opened still pending after 3s"), 3000);
    try {
      const info = await sock.opened;
      return { sock, info };
    } finally {
      clearTimeout(t);
    }
  };
  try {
    return await open({ ...base, sendBufferSize: DEFAULT_BUF, receiveBufferSize: DEFAULT_BUF });
  } catch (e) {
    dbg("open with buffer sizes failed, retrying without:", e);
    return await open(base); // buffer-size options unsupported/rejected
  }
}

class UdpSocket extends Emitter {
  constructor(type) {
    super();
    this.type = typeof type === "object" ? type.type : type;
    this._sock = null;
    this._reader = null;
    this._writer = null;
    this._opening = null;
    this._closed = false;
    this._queue = [];
    this._bound = null;
  }

  bind(port, address, cb) {
    if (typeof port === "function") { cb = port; port = 0; address = undefined; }
    else if (typeof address === "function") { cb = address; address = undefined; }
    if (this._opening) return this;
    dbg("bind() called", this.type);
    this._opening = openUdp(this.type).then(({ sock, info }) => {
      if (this._closed) { try { sock.close(); } catch {} return; }
      this._sock = sock;
      dbg("opened", this.type, JSON.stringify({ localAddress: info.localAddress, localPort: info.localPort }));
      this._reader = info.readable.getReader();
      this._writer = info.writable.getWriter();
      this._bound = {
        address: info.localAddress ?? "0.0.0.0",
        family: this.type === "udp6" ? "IPv6" : "IPv4",
        port: info.localPort ?? 0,
      };
      this._pump();
      for (const q of this._queue.splice(0)) this._sendNow(...q);
      this.emit("listening");
      cb?.call(this);
    }).catch((e) => { dbg("open failed", e); this.emit("error", e); });
    return this;
  }

  address() {
    if (!this._bound) throw Object.assign(new Error("getsockname EBADF"), { code: "EBADF" });
    return this._bound;
  }

  async _pump() {
    for (;;) {
      let r;
      try {
        r = await this._reader.read();
      } catch (e) {
        dbg("read error", e);
        if (!this._closed) this.emit("error", e);
        return;
      }
      if (r.done || this._closed) return;
      const m = r.value; // UDPMessage { data, remoteAddress, remotePort }
      dbg("recv", m.data?.byteLength, "bytes from", m.remoteAddress, m.remotePort);
      const ip = m.remoteAddress ?? "";
      this.emit("message", m.data, {
        address: ip,
        family: ip.includes(":") ? "IPv6" : "IPv4",
        port: m.remotePort ?? 0,
        size: m.data.byteLength,
      });
    }
  }

  // send(msg, port, address, cb) | send(msg, offset, length, port, address, cb)
  send(msg, ...args) {
    const cb = typeof args.at(-1) === "function" ? args.pop() : undefined;
    let off = 0, len = msg.byteLength, port, addr;
    if (args.length >= 4) [off, len, port, addr] = args;
    else [port, addr] = args;
    const data = new Uint8Array(msg.buffer, msg.byteOffset + off, len);
    if (this._closed) {
      cb?.(Object.assign(new Error("Not running"), { code: "ERR_SOCKET_DGRAM_NOT_RUNNING" }));
      return;
    }
    if (!this._writer) {
      if (!this._opening) this.bind(0); // implicit bind, like node
      this._queue.push([data, port, addr, cb]);
      return;
    }
    this._sendNow(data, port, addr, cb);
  }

  _sendNow(data, port, addr, cb) {
    const remoteAddress = addr ?? (this.type === "udp6" ? "::1" : "127.0.0.1");
    dbg("send", data.byteLength, "bytes to", remoteAddress, port);
    // Copy: the caller may reuse its buffer before the stream consumes the chunk.
    this._writer.write({ data: data.slice(), remoteAddress, remotePort: port }).then(
      () => cb?.(null, data.byteLength),
      (e) => { dbg("send error", e); cb ? cb(e) : this.emit("error", e); },
    );
  }

  // Sizes are applied at open time (see openUdp); the bundle's later calls are harmless no-ops.
  setRecvBufferSize() {}
  setSendBufferSize() {}
  getRecvBufferSize() { return DEFAULT_BUF; }
  getSendBufferSize() { return DEFAULT_BUF; }
  setBroadcast() {}
  setTTL() {}
  ref() { return this; }
  unref() { return this; }

  close(cb) {
    if (this._closed) return this;
    this._closed = true;
    const { _reader: r, _writer: w, _sock: s } = this;
    (async () => {
      try { await r?.cancel(); } catch {}
      try { r?.releaseLock(); } catch {}
      try { w?.releaseLock(); } catch {}
      try { await s?.close(); } catch {}
      this.emit("close");
      cb?.();
    })();
    return this;
  }
}

globalThis.__tjs_dgram = { createSocket: (type) => new UdpSocket(type), Socket: UdpSocket };

// ---------- node:dns subset (Direct Sockets has no resolver; use tjs.getaddrinfo) ----------
async function resolveHost(name, family) {
  const hints = family ? { family: family === 6 ? 10 /* AF_INET6 */ : 2 /* AF_INET */ } : undefined;
  const res = await tjsRT.getaddrinfo(name, undefined, hints);
  const list = Array.isArray(res) ? res : [res];
  const want = (a) => !family || (family === 6) === String(a.ip ?? a.address).includes(":");
  const hit = list.find(want) ?? list[0];
  if (!hit) throw Object.assign(new Error("getaddrinfo ENOTFOUND " + name), { code: "ENOTFOUND" });
  const address = hit.ip ?? hit.address;
  return { address, family: address.includes(":") ? 6 : 4 };
}

globalThis.__tjs_dns = {
  lookup(name, opts, cb) {
    if (typeof opts === "function") { cb = opts; opts = {}; }
    const family = typeof opts === "number" ? opts : opts?.family ?? 0;
    if (name === "localhost") {
      queueMicrotask(() => cb(null, family === 6 ? "::1" : "127.0.0.1", family === 6 ? 6 : 4));
      return;
    }
    resolveHost(name, family).then((r) => cb(null, r.address, r.family), (e) => cb(e));
  },
};

dbg("loaded", JSON.stringify({
  UDPSocket: typeof globalThis.UDPSocket,
  getaddrinfo: typeof tjsRT?.getaddrinfo,
  nativeProcess: typeof globalThis.process,
  nextTick: typeof globalThis.process?.nextTick,
  setImmediate: typeof globalThis.setImmediate,
  envFlag: envFlag ?? null,
}));
