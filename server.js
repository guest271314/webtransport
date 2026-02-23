import { deriveInitialSecrets } from './tls-crypto.js';
import { unprotectPacket, protectPacket, isLongHeader, createAckFrame, createWebTransportSettings } from './packet.js';
import { concatBytes } from './byte-buffer.js';

export class WebTransportEchoServer {
    constructor(certConfigArray) {
        const config = certConfigArray[0];
        this.certDer = Uint8Array.from(atob(config.pem.replace(/-----(BEGIN|END) CERTIFICATE-----/g, "").replace(/\s+/g, "")), c => c.charCodeAt(0));
        this.socket = null;
        this.writer = null;
        this.keys = null;
        this.nextPn = 0;
    }

    async start(address = '127.0.0.1', port = 4433) {
        this.socket = new UDPSocket({ localAddress: address, localPort: port });
        const { readable, writable } = await this.socket.opened;
        this.writer = writable.getWriter();
        console.log(`🚀 UDPSocket Server listening on ${address}:${port}`);
        this._listen(readable);
    }

    async _listen(readable) {
        const reader = readable.getReader();
        while (true) {
            const { value, done } = await reader.read();
            if (done) break;
            const packetData = new Uint8Array(value.data);
            if (!isLongHeader(packetData[0])) continue;

            const dcid = packetData.slice(6, 6 + packetData[5]);
            if (!this.keys) this.keys = await deriveInitialSecrets(dcid);

            try {
                const { pn, plaintext } = await unprotectPacket(packetData, this.keys.client);
                console.log(`🚀 Decrypted PN: ${pn}`);
                const payload = concatBytes(createAckFrame(pn), createWebTransportSettings());
                await this.sendResponse(payload, packetData, value.remoteAddress, value.remotePort);
            } catch (e) { 
                console.error("Decryption failed. Check SALT or HP Mask.");
                this.keys = null; 
            }
        }
    }

    async sendResponse(payload, rawData, remoteAddress, remotePort) {
        const dcidLen = rawData[5];
        const dcid = rawData.slice(6, 6 + dcidLen);
        const scidLen = rawData[6 + dcidLen];
        const scid = rawData.slice(7 + dcidLen, 7 + dcidLen + scidLen);
        
        const resHeaderBase = concatBytes(
            new Uint8Array([0xc3]), 
            rawData.slice(1, 5),    
            new Uint8Array([scidLen]), scid,
            new Uint8Array([dcidLen]), dcid,
            new Uint8Array([0x00])  
        );

        const protectedPacket = await protectPacket(resHeaderBase, this.nextPn++, payload, this.keys.server);
        
        // HEX LOG for debugging
        const hex = Array.from(protectedPacket).map(b => b.toString(16).padStart(2, '0')).join(' ');
        console.log(`📤 Sending PN ${this.nextPn - 1}: ${hex.substring(0, 50)}...`);

        await this.writer.write({ data: protectedPacket.buffer, remoteAddress, remotePort });
    }
}
// Load and Boot
const certData =
  (await import("./cert.json", { with: { type: "json" } })).default;
const server = new WebTransportEchoServer(certData);
server.start("127.0.0.1", 4433);
