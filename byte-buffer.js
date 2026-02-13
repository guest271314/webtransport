/**
 * ByteBuffer - Utility for reading/writing binary data with QUIC variable-length integer support.
 * QUIC uses a variable-length integer encoding (RFC 9000 Section 16).
 */
export class ByteBuffer {
  constructor(data) {
    if (data instanceof ArrayBuffer) {
      this.buffer = new Uint8Array(data);
    } else if (data instanceof Uint8Array) {
      this.buffer = data;
    } else if (typeof data === 'number') {
      this.buffer = new Uint8Array(data);
    } else {
      this.buffer = new Uint8Array(0);
    }
    this.offset = 0;
  }

  get length() { return this.buffer.length; }
  get remaining() { return this.buffer.length - this.offset; }

  reset() { this.offset = 0; return this; }
  seek(pos) { this.offset = pos; return this; }
  skip(n) { this.offset += n; return this; }

  slice(start, end) {
    return new Uint8Array(this.buffer.buffer, this.buffer.byteOffset + start, end - start);
  }

  // --- Read operations ---

  readUint8() {
    if (this.offset >= this.buffer.length) throw new RangeError('Buffer underflow');
    return this.buffer[this.offset++];
  }

  readUint16() {
    if (this.offset + 2 > this.buffer.length) throw new RangeError('Buffer underflow');
    const val = (this.buffer[this.offset] << 8) | this.buffer[this.offset + 1];
    this.offset += 2;
    return val;
  }

  readUint24() {
    if (this.offset + 3 > this.buffer.length) throw new RangeError('Buffer underflow');
    const val = (this.buffer[this.offset] << 16) | (this.buffer[this.offset + 1] << 8) | this.buffer[this.offset + 2];
    this.offset += 3;
    return val;
  }

  readUint32() {
    if (this.offset + 4 > this.buffer.length) throw new RangeError('Buffer underflow');
    const val = ((this.buffer[this.offset] << 24) >>> 0) |
                (this.buffer[this.offset + 1] << 16) |
                (this.buffer[this.offset + 2] << 8) |
                this.buffer[this.offset + 3];
    this.offset += 4;
    return val >>> 0;
  }

  readBytes(n) {
    if (this.offset + n > this.buffer.length) throw new RangeError('Buffer underflow');
    const bytes = this.buffer.slice(this.offset, this.offset + n);
    this.offset += n;
    return bytes;
  }

  readRemainingBytes() {
    return this.readBytes(this.remaining);
  }

  /**
   * Read a QUIC variable-length integer (RFC 9000 Section 16).
   * The two most significant bits encode the length:
   *   00 = 1 byte  (6-bit value, max 63)
   *   01 = 2 bytes (14-bit value, max 16383)
   *   10 = 4 bytes (30-bit value, max 1073741823)
   *   11 = 8 bytes (62-bit value, max 4611686018427387903)
   */
  readVarInt() {
    if (this.remaining < 1) throw new RangeError('Buffer underflow');
    const first = this.buffer[this.offset];
    const prefix = first >> 6;
    let length, value;

    switch (prefix) {
      case 0:
        length = 1;
        value = first & 0x3f;
        break;
      case 1:
        length = 2;
        if (this.remaining < 2) throw new RangeError('Buffer underflow');
        value = ((first & 0x3f) << 8) | this.buffer[this.offset + 1];
        break;
      case 2:
        length = 4;
        if (this.remaining < 4) throw new RangeError('Buffer underflow');
        value = ((first & 0x3f) << 24) |
                (this.buffer[this.offset + 1] << 16) |
                (this.buffer[this.offset + 2] << 8) |
                this.buffer[this.offset + 3];
        value = value >>> 0;
        break;
      case 3:
        length = 8;
        if (this.remaining < 8) throw new RangeError('Buffer underflow');
        // For 62-bit values, we use BigInt internally but return Number if safe
        const hi = ((first & 0x3f) << 24) |
                   (this.buffer[this.offset + 1] << 16) |
                   (this.buffer[this.offset + 2] << 8) |
                   this.buffer[this.offset + 3];
        const lo = (this.buffer[this.offset + 4] << 24) |
                   (this.buffer[this.offset + 5] << 16) |
                   (this.buffer[this.offset + 6] << 8) |
                   this.buffer[this.offset + 7];
        value = (hi >>> 0) * 0x100000000 + (lo >>> 0);
        break;
    }

    this.offset += length;
    return value;
  }

  // --- Write operations ---

  writeUint8(val) {
    this._ensureCapacity(1);
    this.buffer[this.offset++] = val & 0xff;
    return this;
  }

  writeUint16(val) {
    this._ensureCapacity(2);
    this.buffer[this.offset++] = (val >> 8) & 0xff;
    this.buffer[this.offset++] = val & 0xff;
    return this;
  }

  writeUint24(val) {
    this._ensureCapacity(3);
    this.buffer[this.offset++] = (val >> 16) & 0xff;
    this.buffer[this.offset++] = (val >> 8) & 0xff;
    this.buffer[this.offset++] = val & 0xff;
    return this;
  }

  writeUint32(val) {
    this._ensureCapacity(4);
    this.buffer[this.offset++] = (val >>> 24) & 0xff;
    this.buffer[this.offset++] = (val >> 16) & 0xff;
    this.buffer[this.offset++] = (val >> 8) & 0xff;
    this.buffer[this.offset++] = val & 0xff;
    return this;
  }

  writeBytes(bytes) {
    this._ensureCapacity(bytes.length);
    this.buffer.set(bytes, this.offset);
    this.offset += bytes.length;
    return this;
  }

  /**
   * Write a QUIC variable-length integer.
   */
  writeVarInt(val) {
    if (val < 0) throw new RangeError('VarInt must be non-negative');
    if (val <= 0x3f) {
      this._ensureCapacity(1);
      this.buffer[this.offset++] = val;
    } else if (val <= 0x3fff) {
      this._ensureCapacity(2);
      this.buffer[this.offset++] = 0x40 | ((val >> 8) & 0x3f);
      this.buffer[this.offset++] = val & 0xff;
    } else if (val <= 0x3fffffff) {
      this._ensureCapacity(4);
      this.buffer[this.offset++] = 0x80 | ((val >> 24) & 0x3f);
      this.buffer[this.offset++] = (val >> 16) & 0xff;
      this.buffer[this.offset++] = (val >> 8) & 0xff;
      this.buffer[this.offset++] = val & 0xff;
    } else {
      this._ensureCapacity(8);
      const hi = Math.floor(val / 0x100000000);
      const lo = val >>> 0;
      this.buffer[this.offset++] = 0xc0 | ((hi >> 24) & 0x3f);
      this.buffer[this.offset++] = (hi >> 16) & 0xff;
      this.buffer[this.offset++] = (hi >> 8) & 0xff;
      this.buffer[this.offset++] = hi & 0xff;
      this.buffer[this.offset++] = (lo >> 24) & 0xff;
      this.buffer[this.offset++] = (lo >> 16) & 0xff;
      this.buffer[this.offset++] = (lo >> 8) & 0xff;
      this.buffer[this.offset++] = lo & 0xff;
    }
    return this;
  }

  /**
   * Get the encoded size of a QUIC variable-length integer.
   */
  static varIntSize(val) {
    if (val <= 0x3f) return 1;
    if (val <= 0x3fff) return 2;
    if (val <= 0x3fffffff) return 4;
    return 8;
  }

  /**
   * Encode a QUIC variable-length integer to a new Uint8Array.
   */
  static encodeVarInt(val) {
    const buf = new ByteBuffer(ByteBuffer.varIntSize(val));
    buf.writeVarInt(val);
    return buf.buffer;
  }

  toUint8Array() {
    return this.buffer.slice(0, this.offset);
  }

  _ensureCapacity(needed) {
    if (this.offset + needed > this.buffer.length) {
      const newSize = Math.max(this.buffer.length * 2, this.offset + needed);
      const newBuf = new Uint8Array(newSize);
      newBuf.set(this.buffer);
      this.buffer = newBuf;
    }
  }
}

/**
 * Utility functions for byte manipulation.
 */
export function concatBytes(...arrays) {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

export function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

export function randomBytes(n) {
  const buf = new Uint8Array(n);
  crypto.getRandomValues(buf);
  return buf;
}

export function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

export function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function utf8Encode(str) {
  return new TextEncoder().encode(str);
}

export function utf8Decode(bytes) {
  return new TextDecoder().decode(bytes);
}