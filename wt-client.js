  var wt = new WebTransport("https://127.0.0.1:4433",{
    serverCertificateHashes: [{
      algorithm: "sha-256",
      value: new Uint8Array([0,1,2]),
    }],
  });
  await wt.ready;
  wt.closed.then(console.log).catch(console.error);
  // Send on a bidi stream:
  var wt_stream = await wt.createBidirectionalStream().catch(console.log);
  var wt_writer = wt_stream.writable.getWriter();
  await wt_writer.ready;
  // Read the echo back:
  var data = new Uint8Array(1024**2);
  var len = 0;
  wt_stream.readable.pipeTo(new WritableStream({
    write(value) {
      console.log(len += value.length); 
      if (len === data.length) {
        // Bun, Deno get here, Node.js and txiki.js don't
        console.log("Echo roundtrip complete");
        len = 0;
        // wt.close({code:4999, reason:"Done streaming."});
      }      
    },
    close() {
      console.log("readable close");
    },
    abort(reason) {
      console.log({ reason });
    }
  })).catch((e) => console.log({ e }));
  //for (let n = 65507, i = 0; i < data.length; i += n) {
  await wt_writer.write(data);
  await wt_writer.ready;
  await new Promise((r) => setTimeout(r, 5000));
  wt.close({code:4999, reason:"Done streaming."});
    // await wt_writer.ready;
  //}
  // await wt_writer.close().catch(console.log);
  // wt.close({ closeCode: 4999, reason: "Done streaming." });
