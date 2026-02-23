/**
 * byte-buffer.js
 */
export class ByteBuffer {
  constructor(data) {
    this.buffer = new Uint8Array(data);
    this.offset = 0;
  }

  remaining() {
    return this.buffer.length - this.offset;
  }

  readUint8() {
    return this.buffer[this.offset++];
  }

  readBytes(len) {
    const res = this.buffer.slice(this.offset, this.offset + len);
    this.offset += len;
    return res;
  }

  /**
   * RFC 9000 Section 16: Variable-Length Integer Encoding
   */
  readVarInt() {
    if (this.offset >= this.buffer.length) return 0;

    const first = this.buffer[this.offset++];
    // The two MSB bits determine the length (2^type bytes)
    const type = (first & 0xc0) >> 6;
    let val = BigInt(first & 0x3f);

    // len is the number of ADDITIONAL bytes to read (0, 1, 3, or 7)
    const extraBytes = (1 << type) - 1;

    for (let i = 0; i < extraBytes; i++) {
      val = (val << 8n) | BigInt(this.buffer[this.offset++]);
    }

    return Number(val);
  }
}

/**
 * Encodes a number into a QUIC VarInt Uint8Array.
 * Uses the smallest possible representation.
 */
export function encodeVarInt(v) {
  if (v < 0x40) {
    return new Uint8Array([v]);
  } else if (v < 0x4000) {
    return new Uint8Array([0x40 | (v >> 8), v & 0xff]);
  } else if (v < 0x40000000) {
    return new Uint8Array([
      0x80 | (v >> 24),
      (v >> 16) & 0xff,
      (v >> 8) & 0xff,
      v & 0xff,
    ]);
  } else {
    // 8-byte encoding for very large numbers
    const res = new Uint8Array(8);
    res[0] = 0xc0;
    const b = BigInt(v);
    for (let i = 0; i < 7; i++) {
      res[7 - i] = Number((b >> BigInt(i * 8)) & 0xffn);
    }
    return res;
  }
}

/**
 * Helper to merge multiple Uint8Arrays into one.
 */
export function concatBytes(...arrays) {
  const total = arrays.reduce((acc, arr) => acc + arr.length, 0);
  const res = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) {
    res.set(a, off);
    off += a.length;
  }
  return res;
}
