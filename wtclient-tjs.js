// txiki.js entry. Run:  TJS_SHIM_DEBUG=1 tjs run wtclient-tjs.js
// Uses plain getReader()/getWriter() loops (no pipeTo/pipeThrough/for-await) so it only needs
// the most basic web-streams support, and logs every phase so a stall shows where it stops.
import "./tjs-shims.js"; // must evaluate before the bundle
const DEBUG = (globalThis.tjs?.env?.TJS_SHIM_DEBUG ?? globalThis.process.env.TJS_SHIM_DEBUG) === "1";
const log = (...a) => DEBUG && console.log("[client]", ...a); // phase tracing, opt-in
const fail = (...a) => console.error("[client]", ...a);      // errors always print
const exit = (c) => (globalThis.tjs ? tjs.exit(c) : process.exit(c));
const { cert, key, certHash } = (await import("./cert.json", {with: { type: "json" }})).default;

/*
log("streams:", {
  ReadableStream: typeof globalThis.ReadableStream,
  WritableStream: typeof globalThis.WritableStream,
  TransformStream: typeof globalThis.TransformStream,
  pipeTo: typeof globalThis.ReadableStream?.prototype?.pipeTo,
  pipeThrough: typeof globalThis.ReadableStream?.prototype?.pipeThrough,
});
*/
// The bundle reads these once at load time, so set them before importing it.
// Verbose protocol tracing only when TJS_SHIM_DEBUG=1 is set in the environment.
if (DEBUG) {
  globalThis.process.env.QUICO_DEBUG = "1";
  globalThis.process.env.LEMON_DEBUG = "1";
}

if (!Object.hasOwn(globalThis, "WebTransport")) {
  const { WebTransport, WebTransportError } = await import("./wt-client-bundle-tjs.js");
  Object.assign(globalThis, { WebTransport, WebTransportError });
}
log("bundle loaded");
const decoder = new TextDecoder();
const encoder = new TextEncoder();
const wt = new WebTransport("https://127.0.0.1:4433", {
  serverCertificateHashes: [{ algorithm: "sha-256", value: new Uint8Array(certHash) }],
});
log("WebTransport constructed");
//const stillWaiting = setInterval(() => log("still waiting for ready..."), 3000);
wt.closed.then((i) => log("session closed:", i), (e) => fail("session closed with error:", e));
await wt.ready.then(() => log("ready"), (e) => fail("ready failed:", e));
//clearInterval(stillWaiting);

// Server-initiated bidirectional streams: read first chunk, ack, close.
(async () => {
  const sr = wt.incomingBidirectionalStreams.getReader();
  for (;;) {
    const { value: stream, done } = await sr.read();
    if (done) return log("incoming bidi streams ended");
    log("incoming bidi stream");
    const r = stream.readable.getReader();
    const { value } = await r.read();
    console.log("Received:", value && decoder.decode(value));
    r.releaseLock();
    const w = stream.writable.getWriter();
    await w.write(encoder.encode("ack from client"));
    await w.close();
  }
})().catch((e) => fail("bidi loop error:", e));

// Server-initiated unidirectional streams: read until the server closes them.
(async () => {
  const sr = wt.incomingUnidirectionalStreams.getReader();
  for (;;) {
    const { value: readable, done } = await sr.read();
    if (done) return log("incoming uni streams ended");
    log("incoming uni stream");
    (async () => {
      const r = readable.getReader();
      // const dec = new TextDecoder();
      for (;;) {
        const { value, done } = await r.read();
        if (done) return log("uni stream finished");
        console.log("Push chunk:", decoder.decode(value, { stream: true }));
      }
    })().catch((e) => fail("uni stream error:", e));
  }
})().catch((e) => fail("uni loop error:", e));

// Echo round trip on a client-initiated bidirectional stream.
const data = new Uint8Array(1024**2*20);
let len = 0;
const bidi = await wt.createBidirectionalStream();
log("created bidi stream");
const writer = bidi.writable.getWriter();
await writer.ready;
log("writer ready");

// const watchdog = setTimeout(() => fail(`WATCHDOG: no full echo after 10s, received ${len}/${data.length} bytes`), 10000);

(async () => {
  const r = bidi.readable.getReader();
  for (;;) {
    const { value, done } = await r.read();
    if (done) return log("echo readable closed");
    console.log(len += value.length);
    if (len === data.length) {
      console.log("Echo roundtrip complete");
      // clearTimeout(watchdog);
      await writer.close();
      wt.close({ closeCode: 4999, reason: "Done streaming." });
      await new Promise((res) => setTimeout(res, 1000));
      exit(0);
    }
  }
})().catch((e) => fail("echo read error:", e));

await writer.write(data);
log("wrote", data.length, "bytes");
