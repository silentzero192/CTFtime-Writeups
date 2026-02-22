#!/usr/bin/env node
"use strict";

const fs = require("fs");
const zlib = require("zlib");
const { Readable } = require("stream");

const FLAG_RE = /BCCTF\{[^}\r\n]{1,200}\}/;
const DEFAULT_PCAP = "map.pcap";
const MAX_SYNC_OUT = 1024 * 1024;
const MAX_STREAM_SCAN = 8 * 1024 * 1024;
const PERIOD_HINT = 105;

function ipToStr(bytes, off) {
  return `${bytes[off]}.${bytes[off + 1]}.${bytes[off + 2]}.${bytes[off + 3]}`;
}

function parsePcapRecords(buf) {
  if (buf.length < 24) {
    throw new Error("pcap is too short");
  }

  const magicLE = buf.readUInt32LE(0);
  const magicBE = buf.readUInt32BE(0);
  let readU32;
  if (magicLE === 0xa1b2c3d4 || magicLE === 0xa1b23c4d) {
    readU32 = (b, o) => b.readUInt32LE(o);
  } else if (magicBE === 0xa1b2c3d4 || magicBE === 0xa1b23c4d) {
    readU32 = (b, o) => b.readUInt32BE(o);
  } else {
    throw new Error("unsupported pcap magic");
  }

  const records = [];
  let pos = 24;
  while (pos + 16 <= buf.length) {
    const inclLen = readU32(buf, pos + 8);
    pos += 16;
    if (pos + inclLen > buf.length) {
      break;
    }
    records.push(buf.subarray(pos, pos + inclLen));
    pos += inclLen;
  }
  return records;
}

function parseTcpPayload(ethFrame) {
  if (ethFrame.length < 14) return null;
  const etherType = ethFrame.readUInt16BE(12);
  if (etherType !== 0x0800) return null;

  const ip = ethFrame.subarray(14);
  if (ip.length < 20) return null;
  const version = ip[0] >> 4;
  if (version !== 4) return null;
  const ihl = (ip[0] & 0x0f) * 4;
  if (ip.length < ihl) return null;
  const totalLen = ip.readUInt16BE(2);
  if (totalLen < ihl || totalLen > ip.length) return null;
  if (ip[9] !== 6) return null;

  const srcIp = ipToStr(ip, 12);
  const dstIp = ipToStr(ip, 16);
  const tcp = ip.subarray(ihl, totalLen);
  if (tcp.length < 20) return null;
  const srcPort = tcp.readUInt16BE(0);
  const dstPort = tcp.readUInt16BE(2);
  const seq = tcp.readUInt32BE(4);
  const dataOffset = (tcp[12] >> 4) * 4;
  if (dataOffset < 20 || dataOffset > tcp.length) return null;
  const payload = tcp.subarray(dataOffset);
  if (payload.length === 0) return null;

  return { srcIp, dstIp, srcPort, dstPort, seq, payload };
}

function reassembleStream(records) {
  const parsed = [];
  for (const rec of records) {
    const p = parseTcpPayload(rec);
    if (p) parsed.push(p);
  }
  if (parsed.length === 0) {
    throw new Error("no TCP payloads found");
  }

  const responsePacket = parsed.find((p) =>
    p.payload.includes(Buffer.from("HTTP/1.1 200 OK", "ascii")),
  );
  if (!responsePacket) {
    throw new Error("could not locate HTTP response");
  }

  const flow = {
    srcIp: responsePacket.srcIp,
    dstIp: responsePacket.dstIp,
    srcPort: responsePacket.srcPort,
    dstPort: responsePacket.dstPort,
  };

  const segments = parsed
    .filter(
      (p) =>
        p.srcIp === flow.srcIp &&
        p.dstIp === flow.dstIp &&
        p.srcPort === flow.srcPort &&
        p.dstPort === flow.dstPort,
    )
    .map((p) => ({ seq: p.seq, payload: p.payload }))
    .sort((a, b) => a.seq - b.seq);

  if (segments.length === 0) {
    throw new Error("no response segments found");
  }

  const baseSeq = segments[0].seq;
  let stream = Buffer.alloc(0);

  for (const seg of segments) {
    const start = seg.seq - baseSeq;
    if (start < 0) continue;
    const end = start + seg.payload.length;
    if (end > stream.length) {
      const grown = Buffer.alloc(end);
      stream.copy(grown, 0, 0, stream.length);
      stream = grown;
    }
    seg.payload.copy(stream, start);
  }

  return stream;
}

function splitHttp(stream) {
  const sep = Buffer.from("\r\n\r\n", "ascii");
  const idx = stream.indexOf(sep);
  if (idx === -1) {
    throw new Error("HTTP header separator not found");
  }
  const headerBuf = stream.subarray(0, idx + sep.length);
  const body = stream.subarray(idx + sep.length);
  return { headerBuf, body };
}

function hasBrotliEncoding(headerBuf) {
  const headers = headerBuf.toString("latin1").toLowerCase();
  return headers.includes("content-encoding: br");
}

function trySmallDecompress(input) {
  try {
    const out = zlib.brotliDecompressSync(input, { maxOutputLength: MAX_SYNC_OUT });
    return { kind: "ok", out };
  } catch (err) {
    if (err && err.code === "ERR_BUFFER_TOO_LARGE") {
      return { kind: "too_large" };
    }
    return { kind: "bad" };
  }
}

function extractFlagFromBuffer(buf) {
  const m = buf.toString("latin1").match(FLAG_RE);
  return m ? m[0] : null;
}

function streamFindFlag(input, maxOutputBytes) {
  return new Promise((resolve) => {
    const dec = zlib.createBrotliDecompress();
    let seen = 0;
    let tail = "";
    let done = false;

    const finish = (value) => {
      if (done) return;
      done = true;
      dec.destroy();
      resolve(value);
    };

    dec.on("data", (chunk) => {
      seen += chunk.length;
      tail += chunk.toString("latin1");

      const m = tail.match(FLAG_RE);
      if (m) {
        finish(m[0]);
        return;
      }

      if (tail.length > 4096) {
        tail = tail.slice(-2048);
      }

      if (seen > maxOutputBytes) {
        finish(null);
      }
    });

    dec.on("error", () => finish(null));
    dec.on("end", () => finish(null));

    Readable.from(input).pipe(dec);
  });
}

async function findFlagInBrotliBody(body) {
  const direct = trySmallDecompress(body);
  if (direct.kind === "ok") {
    const flag = extractFlagFromBuffer(direct.out);
    if (flag) return flag;
  }

  const candidates = [];
  for (let off = 0; off < body.length; off += PERIOD_HINT) {
    const probe = trySmallDecompress(body.subarray(off));
    if (probe.kind === "ok") {
      const flag = extractFlagFromBuffer(probe.out);
      if (flag) return flag;
    } else if (probe.kind === "too_large") {
      candidates.push(off);
    }
  }

  for (const off of candidates) {
    const flag = await streamFindFlag(body.subarray(off), MAX_STREAM_SCAN);
    if (flag) return flag;
  }

  return null;
}

async function main() {
  const pcapPath = process.argv[2] || DEFAULT_PCAP;
  const pcap = fs.readFileSync(pcapPath);

  const records = parsePcapRecords(pcap);
  const stream = reassembleStream(records);
  const { headerBuf, body } = splitHttp(stream);

  if (!hasBrotliEncoding(headerBuf)) {
    throw new Error("expected Brotli HTTP body");
  }

  const flag = await findFlagInBrotliBody(body);
  if (!flag) {
    throw new Error("flag not found");
  }

  console.log(flag);
}

main().catch((err) => {
  console.error(`[-] ${err.message}`);
  process.exit(1);
});
