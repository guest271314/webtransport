var json = (await import("./export/cert.json", {
  with: {
    type: "json",
  },
})).default;

async function testEcho(config) {
    const url = "https://127.0.0.1:4433";
    console.log(`⏳ Connecting to WebTransport server at ${url}...`);

    try {
        const transport = new WebTransport(url, {
            serverCertificateHashes: [
                {
                    algorithm: "sha-256",
                    value: new Uint8Array(config.hash.digest)
                }
            ]
        });

        await transport.ready;
        console.log("✅ WebTransport is ready!");

        // Test Datagrams
        const writer = transport.datagrams.writable.getWriter();
        const data = new TextEncoder().encode("Hello WebTransport Echo!");
        await writer.write(data);
        console.log("📤 Sent Datagram:", new TextDecoder().decode(data));

        const reader = transport.datagrams.readable.getReader();
        const { value } = await reader.read();
        console.log("📥 Received Echo:", new TextDecoder().decode(value));

    } catch (e) {
        console.error("❌ Test Failed:", e);
    }
}

// Usage:
// testEcho(json[0]);

testEcho(json[0]).catch(console.log);
// https://gemini.google.com/share/a34176ee9792
