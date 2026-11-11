// Minimal ZIP writer (deflate via CompressionStream, falls back to "stored").
// Works in extension pages, service workers and Node >= 18.

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

export function crc32(bytes) {
  let c = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) c = CRC_TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

async function deflateRaw(bytes) {
  if (typeof CompressionStream === 'undefined') return null;
  try {
    const stream = new Blob([bytes]).stream().pipeThrough(new CompressionStream('deflate-raw'));
    return new Uint8Array(await new Response(stream).arrayBuffer());
  } catch {
    return null;
  }
}

function dosDateTime(d) {
  const year = Math.max(1980, d.getFullYear());
  return {
    time: (d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1),
    date: ((year - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate(),
  };
}

const enc = new TextEncoder();

export class ZipWriter {
  constructor() {
    this.parts = [];
    this.central = [];
    this.offset = 0;
    this.names = new Set();
    this.count = 0;
    this.bytes = 0;
  }

  /** Returns a unique variant of `name` ("a.js" → "a~2.js"). */
  unique(name) {
    if (!this.names.has(name)) return name;
    const dot = name.lastIndexOf('.');
    const slash = name.lastIndexOf('/');
    const [stem, ext] = dot > slash ? [name.slice(0, dot), name.slice(dot)] : [name, ''];
    let i = 2;
    while (this.names.has(`${stem}~${i}${ext}`)) i++;
    return `${stem}~${i}${ext}`;
  }

  /** Adds a file. `data` is a string or Uint8Array. Returns the name actually used. */
  async add(name, data, date = new Date()) {
    if (this.count >= 65000) throw new Error('ZIP entry limit reached');
    const bytes = typeof data === 'string' ? enc.encode(data) : data;
    const crc = crc32(bytes);
    let body = bytes;
    let method = 0;
    if (bytes.length > 128) {
      const d = await deflateRaw(bytes);
      if (d && d.length < bytes.length) {
        body = d;
        method = 8;
      }
    }
    // Everything below is synchronous, so concurrent add() calls cannot interleave offsets.
    const finalName = this.unique(name);
    this.names.add(finalName);
    const nameBytes = enc.encode(finalName);
    const { time, date: day } = dosDateTime(date);

    const local = new DataView(new ArrayBuffer(30));
    local.setUint32(0, 0x04034b50, true);
    local.setUint16(4, 20, true);
    local.setUint16(6, 0x0800, true); // UTF-8 names
    local.setUint16(8, method, true);
    local.setUint16(10, time, true);
    local.setUint16(12, day, true);
    local.setUint32(14, crc, true);
    local.setUint32(18, body.length, true);
    local.setUint32(22, bytes.length, true);
    local.setUint16(26, nameBytes.length, true);
    local.setUint16(28, 0, true);

    const cen = new DataView(new ArrayBuffer(46));
    cen.setUint32(0, 0x02014b50, true);
    cen.setUint16(4, 20, true);
    cen.setUint16(6, 20, true);
    cen.setUint16(8, 0x0800, true);
    cen.setUint16(10, method, true);
    cen.setUint16(12, time, true);
    cen.setUint16(14, day, true);
    cen.setUint32(16, crc, true);
    cen.setUint32(20, body.length, true);
    cen.setUint32(24, bytes.length, true);
    cen.setUint16(28, nameBytes.length, true);
    cen.setUint32(42, this.offset, true);

    this.parts.push(local.buffer, nameBytes, body);
    this.central.push(cen.buffer, nameBytes);
    this.offset += 30 + nameBytes.length + body.length;
    this.count++;
    this.bytes += bytes.length;
    return finalName;
  }

  blob() {
    let cdSize = 0;
    for (const c of this.central) cdSize += c.byteLength;
    const end = new DataView(new ArrayBuffer(22));
    end.setUint32(0, 0x06054b50, true);
    end.setUint16(8, this.count, true);
    end.setUint16(10, this.count, true);
    end.setUint32(12, cdSize, true);
    end.setUint32(16, this.offset, true);
    return new Blob([...this.parts, ...this.central, end.buffer], { type: 'application/zip' });
  }
}

/** Makes a URL or source path safe as a ZIP entry path (also safe to extract on Windows). */
export function zipPath(p) {
  return String(p)
    .replace(/\\/g, '/')
    .split('/')
    .filter((s) => s && s !== '.')
    .map((s) => (s === '..' ? '_' : s.replace(/[<>:"|?*\x00-\x1f]/g, '_').replace(/[. ]+$/, '_').slice(0, 120)))
    .join('/');
}
