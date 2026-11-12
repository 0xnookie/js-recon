// Minimal ZIP reader for the tests: walks the central directory, cross-checks each local header,
// inflates with node:zlib and verifies sizes + CRC-32. Reading archives in-process keeps the tests
// independent of the host's tar/unzip and locale (e.g. Ubuntu 24.04's unzip ignores the UTF-8 name
// flag and writes "ünïcode.txt" as CP437 mojibake; Windows bsdtar has its own quirks).
import { inflateRawSync } from 'node:zlib';

const CRC_TABLE = new Uint32Array(256).map((_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});
const crc32 = (buf) => {
  let c = 0xffffffff;
  for (const b of buf) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
};
const utf8 = new TextDecoder('utf-8', { fatal: true });

/**
 * Parses a ZIP and returns Map<name, { data: Buffer, method: number, utf8: boolean }>.
 * Throws on any structural, size or CRC mismatch.
 */
export function readZip(input) {
  const buf = Buffer.from(input);
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 22 - 0xffff); i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error('zip: end of central directory not found');
  const count = buf.readUInt16LE(eocd + 10);
  const cdSize = buf.readUInt32LE(eocd + 12);
  const cdOffset = buf.readUInt32LE(eocd + 16);
  if (cdOffset + cdSize !== eocd) throw new Error('zip: central directory size/offset mismatch');

  const entries = new Map();
  let p = cdOffset;
  for (let i = 0; i < count; i++) {
    if (buf.readUInt32LE(p) !== 0x02014b50) throw new Error(`zip: bad central header #${i}`);
    const flags = buf.readUInt16LE(p + 8);
    const method = buf.readUInt16LE(p + 10);
    const crc = buf.readUInt32LE(p + 16);
    const csize = buf.readUInt32LE(p + 20);
    const usize = buf.readUInt32LE(p + 24);
    const nlen = buf.readUInt16LE(p + 28);
    const xlen = buf.readUInt16LE(p + 30);
    const clen = buf.readUInt16LE(p + 32);
    const lho = buf.readUInt32LE(p + 42);
    const rawName = buf.subarray(p + 46, p + 46 + nlen);
    const isUtf8 = (flags & 0x0800) !== 0;
    const name = isUtf8 ? utf8.decode(rawName) : rawName.toString('latin1');
    p += 46 + nlen + xlen + clen;

    if (buf.readUInt32LE(lho) !== 0x04034b50) throw new Error(`zip: bad local header for ${name}`);
    const lnlen = buf.readUInt16LE(lho + 26);
    const lxlen = buf.readUInt16LE(lho + 28);
    if (!buf.subarray(lho + 30, lho + 30 + lnlen).equals(rawName)) throw new Error(`zip: local/central name mismatch for ${name}`);
    if (buf.readUInt16LE(lho + 8) !== method || buf.readUInt32LE(lho + 14) !== crc) throw new Error(`zip: local/central header mismatch for ${name}`);
    const start = lho + 30 + lnlen + lxlen;
    const body = buf.subarray(start, start + csize);
    let data;
    if (method === 0) data = Buffer.from(body);
    else if (method === 8) data = inflateRawSync(body);
    else throw new Error(`zip: unsupported method ${method} for ${name}`);
    if (data.length !== usize) throw new Error(`zip: size mismatch for ${name} (${data.length} != ${usize})`);
    if (crc32(data) !== crc) throw new Error(`zip: CRC mismatch for ${name}`);
    if (entries.has(name)) throw new Error(`zip: duplicate entry ${name}`);
    entries.set(name, { data, method, utf8: isUtf8 });
  }
  if (p !== eocd) throw new Error('zip: trailing bytes after central directory');
  return entries;
}
