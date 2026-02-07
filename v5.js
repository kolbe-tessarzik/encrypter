import pako from 'https://cdn.jsdelivr.net/npm/pako@2.1.0/dist/pako.esm.mjs';

(function () {
  "use strict";

  // ----------------- Configuration -----------------
  const DICT = [
    " the "," and "," to "," of "," in "," that "," is "," for ",
    "ing","tion","ion","ed ","ly ","er ","re ","on ","th","he","in","er"
  ].sort((a, b) => b.length - a.length);
  // ensure DICT length <= 254 so our escape scheme fits
  if (DICT.length > 254) throw new Error("DICT too large");

  // We'll build a large printable charset once (cached)
  let BLOCK_CHARS = null;

  // ----------------- Utilities -----------------
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  // SHA-256 -> offset
  async function sha256ToOffset(str, mod) {
    if (!str) return 0;
    const data = enc.encode(str);
    const digest = await crypto.subtle.digest("SHA-256", data);
    const dv = new DataView(digest);
    // use first 4 bytes
    return dv.getUint32(0) % mod;
  }

  // Build printable Unicode set once (skip whitespace, control, combining, surrogates)
  function buildBlockChars() {
    if (BLOCK_CHARS) return BLOCK_CHARS;
    const out = [];
    // iterate through a wide range of codepoints; start at 0x21 (printable)
    // go up to 0x10FFFF — skip surrogates and undesirable categories
    const reCcCf = /[\p{Cc}\p{Cf}]/u;
    const reMnMe = /\p{Mn}|\p{Me}/u;
    for (let cp = 0x21; cp <= 0x10FFFF; cp++) {
      if (cp >= 0xD800 && cp <= 0xDFFF) { cp = 0xDFFF; continue; } // skip surrogates block efficiently
      try {
        const ch = String.fromCodePoint(cp);
        // skip whitespace (spaces, tabs, newlines, NBSP, etc.)
        if (/\s/.test(ch)) continue;
        if (reCcCf.test(ch)) continue;
        if (reMnMe.test(ch)) continue;
        out.push(ch);
      } catch (e) {
        // ignore invalid codepoints
      }
      // IMPORTANT: building ~1.1M codepoints can be slow; but we do it once.
      // If you want a faster startup, confine to a smaller range (e.g., 0x200..0xFFFD).
    }
    return out;
  }

  // keyed rotation of block chars
  async function getKeyedChars(key) {
    if (!BLOCK_CHARS) BLOCK_CHARS = buildBlockChars();
    if (!key) return BLOCK_CHARS;
    const off = await sha256ToOffset(key, BLOCK_CHARS.length);
    // rotate
    return BLOCK_CHARS.slice(off).concat(BLOCK_CHARS.slice(0, off));
  }

  // ----------------- Tokenization (byte-level safe) -----------------
  // We'll encode dictionary tokens into bytes using an escape byte 0xFF followed by index (0..253)
  const ESC = 0xFF;

  function tokenizeToBytes(str) {
    const out = [];
    let i = 0;
    while (i < str.length) {
      let matched = false;
      for (let j = 0; j < DICT.length; j++) {
        const d = DICT[j];
        if (str.startsWith(d, i)) {
          out.push(ESC, j); // ESC + index
          i += d.length;
          matched = true;
          break;
        }
      }
      if (matched) continue;
      const cp = str.codePointAt(i);
      const ch = String.fromCodePoint(cp);
      const bs = enc.encode(ch);
      for (const b of bs) out.push(b);
      i += ch.length;
    }
    return new Uint8Array(out);
  }

  function detokenizeFromBytes(bytes) {
    const resultBytes = [];
    for (let i = 0; i < bytes.length; i++) {
      const b = bytes[i];
      if (b === ESC) {
        if (i + 1 >= bytes.length) throw new Error("Truncated token stream");
        const idx = bytes[++i];
        if (idx >= DICT.length) throw new Error("Invalid token index");
        const chunk = enc.encode(DICT[idx]);
        for (const cb of chunk) resultBytes.push(cb);
      } else {
        resultBytes.push(b);
      }
    }
    return dec.decode(new Uint8Array(resultBytes));
  }

  // ----------------- Framing + XOR -----------------
  function makeFrame(compressedBytes) {
    // 4-byte big-endian length (compressed length)
    const len = compressedBytes.length;
    const frame = new Uint8Array(4 + len);
    frame[0] = (len >> 24) & 0xFF;
    frame[1] = (len >> 16) & 0xFF;
    frame[2] = (len >> 8) & 0xFF;
    frame[3] = len & 0xFF;
    frame.set(compressedBytes, 4);
    return frame;
  }

  function readFrame(buf) {
    if (buf.length < 4) throw new Error("Frame too small");
    const len = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
    if (buf.length < 4 + len) throw new Error("Frame shorter than indicated length");
    return buf.slice(4, 4 + len);
  }

  function xorBytesWithKey(u8, keyStr) {
    if (!keyStr) return u8;
    const k = enc.encode(keyStr);
    if (k.length === 0) return u8;
    const out = new Uint8Array(u8.length);
    for (let i = 0; i < u8.length; i++) out[i] = u8[i] ^ k[i % k.length];
    return out;
  }

  // ----------------- Bitpack to keyed chars -----------------
  function encodeBytesToChars(bytes, keyedChars) {
    // determine bits per output char
    const bitsPerChar = Math.floor(Math.log2(keyedChars.length));
    if (bitsPerChar <= 0) throw new Error("charset too small");

    let buf = 0n;
    let bits = 0n;
    let out = "";

    const writeBits = (value, n) => {
      if (n === 0) return;
      buf = (buf << BigInt(n)) | BigInt(value & ((1 << n) - 1));
      bits += BigInt(n);
      while (bits >= BigInt(bitsPerChar)) {
        bits -= BigInt(bitsPerChar);
        const idx = Number((buf >> bits) & BigInt((1 << bitsPerChar) - 1));
        out += keyedChars[idx];
      }
    };

    for (let i = 0; i < bytes.length; i++) {
      writeBits(bytes[i], 8);
    }

    if (bits > 0n) {
      const pad = BigInt(bitsPerChar) - bits;
      // shift left to fill a full symbol (pad with zeros)
      const idx = Number((buf << pad) & BigInt((1 << bitsPerChar) - 1));
      out += keyedChars[idx];
    }

    return out;
  }

  function decodeCharsToBytes(str, keyedChars) {
    const map = Object.fromEntries(keyedChars.map((c, i) => [c, i]));
    const bitsPerChar = Math.floor(Math.log2(keyedChars.length));
    let buf = 0n;
    let bits = 0n;
    const out = [];

    // iterate codepoints (safe for surrogate pairs)
    for (let i = 0; i < str.length; ) {
      const code = str.codePointAt(i);
      const ch = String.fromCodePoint(code);
      i += ch.length;
      if (!(ch in map)) throw new Error("Invalid encoded character encountered during decode");
      const idx = BigInt(map[ch]);
      buf = (buf << BigInt(bitsPerChar)) | idx;
      bits += BigInt(bitsPerChar);
      while (bits >= 8n) {
        bits -= 8n;
        const byte = Number((buf >> bits) & 0xFFn);
        out.push(byte);
      }
    }
    return new Uint8Array(out);
  }

  // ----------------- Full encode / decode functions -----------------
  async function compressAndEncode(text, key) {
    // 1) tokenize to bytes (escape tokens)
    const tokenBytes = tokenizeToBytes(text); // Uint8Array

    // 2) compress via pako (deflate)
    const compressed = pako.deflate(tokenBytes); // Uint8Array

    // 3) frame length + compressed
    const frame = makeFrame(compressed);

    // 4) XOR with key (applied to frame)
    const xored = xorBytesWithKey(frame, key);

    // 5) get keyed char set
    const keyed = await getKeyedChars(key || "");

    // 6) bitpack to chars
    const outStr = encodeBytesToChars(xored, keyed);
    return outStr;
  }

  async function decodeAndDecompress(str, key) {
    // 1) keyed char set
    const keyed = await getKeyedChars(key || "");

    // 2) bit-decode to bytes
    const bytes = decodeCharsToBytes(str, keyed);

    // 3) XOR with key (descramble)
    const descr = xorBytesWithKey(bytes, key);

    // 4) read frame length and extract compressed portion
    const compressedBytes = readFrame(descr);

    // 5) inflate (pako)
    const inflated = pako.inflate(compressedBytes);

    // 6) detokenize
    const out = detokenizeFromBytes(inflated);
    return out;
  }

  window.encrypt = (text, key) => {
    if (text == "") {
      return "";
    } else {
      return compressAndEncode(text, key);
    }
  };

  window.decrypt = (str, key) => {
    if (str == "") {
      return "";
    } else {
      return decodeAndDecompress(str, key);
    }
  }
  // Note: UI wiring is intentionally left in HTML.
})();
