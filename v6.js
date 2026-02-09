import pako from 'https://cdn.jsdelivr.net/npm/pako@2.1.0/dist/pako.esm.mjs';

(function () {
  "use strict";

  /* --- CONFIGURATION --- */
const STATIC_DICT = [
  " the "," and "," to "," of "," in "," that "," is "," for ",
  "ing","tion","ion","ed ","ly ","er ","re ","on ","th","he","in","er"
].sort((a,b)=>b.length-a.length);

const MIN_MATCH = 4;
const MAX_MATCH = 10;
const MIN_OCCURRENCE = 2;
const MAX_DICT_ENTRIES = 200; // keep <=254 so token indices fit in one byte
const ESC = 0xFF; // escape marker for tokens
const enc = new TextEncoder();
const dec = new TextDecoder();

/* --- BLOCK_CHARS / keyed alphabet (copied from your file) --- */
let BLOCK_CHARS = null;
function buildBlockChars() {
  if (BLOCK_CHARS) return BLOCK_CHARS;
  const out = [];
  const reCcCf = /[\p{Cc}\p{Cf}]/u;
  const reMnMe = /\p{Mn}|\p{Me}/u;
  for (let cp = 0x21; cp <= 0xFFFD; cp++) {
    if (cp >= 0xD800 && cp <= 0xDFFF) { cp = 0xDFFF; continue; }
    try {
      const ch = String.fromCodePoint(cp);
      if (/\s/.test(ch)) continue;
      if (reCcCf.test(ch)) continue;
      if (reMnMe.test(ch)) continue;
      out.push(ch);
    } catch (e) {}
  }
  BLOCK_CHARS = out;
  return out;
}
async function sha256ToOffset(str, mod) {
  if (!str) return 0;
  const data = enc.encode(str);
  const digest = await crypto.subtle.digest("SHA-256", data);
  const dv = new DataView(digest);
  return dv.getUint32(0) % mod;
}
async function getKeyedChars(key) {
  if (!BLOCK_CHARS) BLOCK_CHARS = buildBlockChars();
  if (!key) return BLOCK_CHARS;
  const off = await sha256ToOffset(key, BLOCK_CHARS.length);
  return BLOCK_CHARS.slice(off).concat(BLOCK_CHARS.slice(0, off));
}

/* --- Dynamic dictionary (digger) --- */
function findCandidates(text, sampleLimit = 200000) {
  // sample prefix for performance
  const s = (text.length > sampleLimit) ? text.slice(0, sampleLimit) : text;
  const counts = new Map();

  for (let L = MIN_MATCH; L <= MAX_MATCH; L++) {
    const seen = new Map();
    for (let i = 0; i + L <= s.length; i++) {
      const sub = s.slice(i, i + L);
      const v = (seen.get(sub) || 0) + 1;
      seen.set(sub, v);
    }
    for (const [sub, cnt] of seen.entries()) {
      if (cnt >= MIN_OCCURRENCE) {
        counts.set(sub, (counts.get(sub) || 0) + cnt);
      }
    }
  }

  const candidates = [];
  for (const [sub, cnt] of counts.entries()) {
    const len = sub.length;
    const savingPer = len - 3; // using ESC + 1-byte index (3 bytes) for token
    const estSavings = cnt * savingPer - (2 + len); // minus dict storage
    if (estSavings > 0) candidates.push({ sub, cnt, len, estSavings });
  }

  candidates.sort((a,b)=>b.estSavings - a.estSavings);
  return candidates.slice(0, MAX_DICT_ENTRIES);
}

function buildDynamicDict(text) {
  const candidates = findCandidates(text);
  const dict = candidates.map(c => c.sub);
  // append static dict entries afterwards (longest first)
  const merged = dict.concat(STATIC_DICT.filter(s => !dict.includes(s)));
  // cap to 254 entries (reserve indices 0..253)
  return merged.slice(0, 254);
}

/* --- Tokenize / detokenize using ESC + single-byte index --- */
function tokenizeWithDict(str, dict) {
  const out = [];
  let i = 0;
  while (i < str.length) {
    let matched = false;
    for (let j = 0; j < dict.length; j++) {
      const d = dict[j];
      if (str.startsWith(d, i)) {
        // ESC + 1-byte index
        out.push(ESC, j);
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

function detokenizeFromBytesWithDict(bytes, dict) {
  const result = [];
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    if (b === ESC) {
      if (i + 1 >= bytes.length) throw new Error("Truncated token stream");
      const idx = bytes[++i];
      if (idx >= dict.length) throw new Error("Invalid token index");
      const chunk = enc.encode(dict[idx]);
      for (const cb of chunk) result.push(cb);
    } else {
      result.push(b);
    }
  }
  return dec.decode(new Uint8Array(result));
}

/* --- Huffman coding (canonical) --- */
function buildHuffmanLengths(bytes) {
  // frequency count
  const freq = new Uint32Array(256);
  for (const b of bytes) freq[b]++;

  // build nodes: leaves for symbols with freq>0
  const nodes = [];
  for (let s = 0; s < 256; s++) {
    if (freq[s] > 0) nodes.push({ sym: s, w: freq[s] });
  }
  if (nodes.length === 0) return {}; // empty

  // special case single symbol
  if (nodes.length === 1) {
    const out = { lengths: { [nodes[0].sym]: 1 } };
    return out;
  }

  // build Huffman tree (simple array-based PQ)
  // node: { w, sym?, left, right }
  const pq = nodes.slice();
  pq.sort((a,b)=>a.w - b.w);
  while (pq.length > 1) {
    const a = pq.shift();
    const b = pq.shift();
    const parent = { w: a.w + b.w, left: a, right: b };
    // insert back keeping sorted
    let inserted = false;
    for (let i = 0; i < pq.length; i++) {
      if (parent.w <= pq[i].w) { pq.splice(i, 0, parent); inserted = true; break; }
    }
    if (!inserted) pq.push(parent);
  }
  const root = pq[0];

  // walk tree to get lengths
  const lengths = {};
  function walk(n, depth) {
    if (!n) return;
    if (n.sym !== undefined) {
      lengths[n.sym] = depth;
      return;
    }
    walk(n.left, depth + 1);
    walk(n.right, depth + 1);
  }
  walk(root, 0);

  return { lengths };
}

// build canonical codes from lengths map {sym:len}
function buildCanonicalCodes(lengthsMap) {
  // lengthsMap: object sym->len
  const items = Object.entries(lengthsMap).map(([s,l]) => ({ sym: Number(s), len: l }));
  items.sort((a,b) => a.len - b.len || a.sym - b.sym);
  const codes = {};
  let code = 0;
  let prevLen = 0;
  for (const it of items) {
    if (it.len !== prevLen) {
      code <<= (it.len - prevLen);
      prevLen = it.len;
    }
    codes[it.sym] = { code: code, len: it.len };
    code++;
  }
  // return codes and also inverse mapping by length
  const byLen = {};
  for (const symStr in codes) {
    const s = Number(symStr);
    const { code: c, len } = codes[s];
    if (!byLen[len]) byLen[len] = new Map();
    byLen[len].set(c, s);
  }
  return { codes, byLen };
}

function huffmanEncode(bytes, codes) {
  // codes: sym-> {code, len}
  const out = [];
  let cur = 0;
  let nbits = 0;
  for (const b of bytes) {
    const e = codes[b];
    if (!e) throw new Error("Missing Huffman code for symbol: " + b);
    const { code, len } = e;
    // append len bits (MSB-first)
    let shift = len - 1;
    for (let k = shift; k >= 0; k--) {
      const bit = (code >> k) & 1;
      cur = (cur << 1) | bit;
      nbits++;
      if (nbits === 8) {
        out.push(cur & 0xFF);
        cur = 0; nbits = 0;
      }
    }
  }
  if (nbits > 0) {
    cur = cur << (8 - nbits);
    out.push(cur & 0xFF);
  }
  return { bytes: new Uint8Array(out), bitLen: (bytes.length ? (Object.values(codes).reduce((a,b)=>a,0), 0) : 0), validBits: (out.length * 8) - (8 - nbits) }; // validBits we'll compute below differently
}

// We'll write a safer bit writer to compute actual bit length
function huffmanEncodeWithBitlen(bytes, codes) {
  const out = [];
  let cur = 0;
  let nbits = 0;
  let totalBits = 0;
  for (const b of bytes) {
    const e = codes[b];
    if (!e) throw new Error("Missing Huffman code for symbol: " + b);
    const { code, len } = e;
    totalBits += len;
    // write MSB-first
    for (let k = len - 1; k >= 0; k--) {
      const bit = (code >> k) & 1;
      cur = (cur << 1) | bit;
      nbits++;
      if (nbits === 8) {
        out.push(cur & 0xFF);
        cur = 0; nbits = 0;
      }
    }
  }
  if (nbits > 0) {
    cur = cur << (8 - nbits);
    out.push(cur & 0xFF);
  }
  return { bytes: new Uint8Array(out), bitLen: totalBits };
}

function huffmanDecodeFromBits(bytes, bitLen, byLen) {
  // byLen: Map length -> Map(code->sym)
  const out = [];
  let acc = 0;
  let accLen = 0;
  let bitsConsumed = 0;
  for (let i = 0; i < bytes.length; i++) {
    let val = bytes[i];
    for (let b = 7; b >= 0; b--) {
      if (bitsConsumed >= bitLen) break;
      const bit = (val >> b) & 1;
      acc = (acc << 1) | bit;
      accLen++;
      bitsConsumed++;
      const mp = byLen[accLen];
      if (mp && mp.has(acc)) {
        out.push(mp.get(acc));
        acc = 0;
        accLen = 0;
      }
    }
  }
  if (bitsConsumed !== bitLen) {
    // It might be okay if there's padding bits, but bitLen tells exact valid bits
  }
  return new Uint8Array(out);
}

/* --- framing helpers (same as earlier pipeline but we will include huffman table in preframe) --- */
function u32(n){ return [(n>>24)&0xFF,(n>>16)&0xFF,(n>>8)&0xFF,n&0xFF]; }
function makeFrameRaw(dict, huffEntries, dataBitLen, dataBytes) {
  // dict: array of strings
  // huffEntries: array of {sym, len}
  // dataBitLen: integer
  const dictEncoded = dict.map(s => enc.encode(s));
  let dictBytesLen = 0;
  for (const d of dictEncoded) dictBytesLen += d.length;
  const huffEntriesLen = huffEntries.length; // each entry is 2 bytes
  const headerLen = 2 + dict.length*2 + (huffEntriesLen?2 + (huffEntriesLen*2):2) + 4; // dictCount + lens + huffCount + entries + dataBitLen(4)
  const totalLen = headerLen + dictBytesLen + dataBytes.length;
  const out = new Uint8Array(totalLen);
  let p = 0;
  // dict count
  out[p++] = (dict.length >> 8) & 0xFF;
  out[p++] = dict.length & 0xFF;
  // dict entries: len(2) + bytes
  for (const b of dictEncoded) {
    out[p++] = (b.length >> 8) & 0xFF;
    out[p++] = b.length & 0xFF;
    out.set(b, p); p += b.length;
  }
  // huffman entries: count(2)
  out[p++] = (huffEntriesLen >> 8) & 0xFF;
  out[p++] = huffEntriesLen & 0xFF;
  for (const h of huffEntries) {
    out[p++] = h.sym & 0xFF;
    out[p++] = h.len & 0xFF;
  }
  // data bit length (4)
  out.set(u32(dataBitLen), p); p += 4;
  // data bytes
  out.set(dataBytes, p); p += dataBytes.length;
  return out;
}

function parseFrameRaw(frameBytes) {
  let p = 0;
  if (frameBytes.length < 6) throw new Error("Frame too small");
  const dictCount = (frameBytes[p++]<<8) | frameBytes[p++];
  const dict = [];
  for (let i = 0; i < dictCount; i++) {
    const ln = (frameBytes[p++]<<8) | frameBytes[p++];
    const slice = frameBytes.slice(p, p + ln);
    dict.push(dec.decode(slice));
    p += ln;
  }
  const huffCount = (frameBytes[p++]<<8) | frameBytes[p++];
  const huffEntries = [];
  for (let i = 0; i < huffCount; i++) {
    const sym = frameBytes[p++];
    const len = frameBytes[p++];
    huffEntries.push({ sym, len });
  }
  const dataBitLen = (frameBytes[p++]<<24) | (frameBytes[p++]<<16) | (frameBytes[p++]<<8) | frameBytes[p++];
  const data = frameBytes.slice(p);
  return { dict, huffEntries, dataBitLen, data };
}

/* --- existing functions for bitpack keyed chars --- */
function encodeBytesToChars(bytes, keyedChars) {
  const bitsPerChar = Math.floor(Math.log2(keyedChars.length));
  if (bitsPerChar <= 0) throw new Error("charset too small");
  let buf = 0n;
  let bits = 0n;
  let out = "";
  const mask = (1 << bitsPerChar) - 1;
  for (let i = 0; i < bytes.length; i++) {
    buf = (buf << 8n) | BigInt(bytes[i]);
    bits += 8n;
    while (bits >= BigInt(bitsPerChar)) {
      bits -= BigInt(bitsPerChar);
      const idx = Number((buf >> bits) & BigInt(mask));
      out += keyedChars[idx];
    }
  }
  if (bits > 0n) {
    const idx = Number((buf << (BigInt(bitsPerChar) - bits)) & BigInt(mask));
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
  const mask = (1 << bitsPerChar) - 1;
  for (let i = 0; i < str.length;) {
    const code = str.codePointAt(i);
    const ch = String.fromCodePoint(code);
    i += ch.length;
    const idx = map[ch];
    if (idx === undefined) throw new Error("Invalid encoded character during decode");
    buf = (buf << BigInt(bitsPerChar)) | BigInt(idx);
    bits += BigInt(bitsPerChar);
    while (bits >= 8n) {
      bits -= 8n;
      const byte = Number((buf >> bits) & 0xFFn);
      out.push(byte);
    }
  }
  return new Uint8Array(out);
}

/* --- HIGH LEVEL: compressAndEncode / decodeAndDecompress (with digger + huffman) --- */
async function compressAndEncode(text, key) {
  // 1) build dynamic dict, merge with static (dynamic first)
  const dynamic = buildDynamicDict(text);
  // ensure dict length <= 254
  const dict = dynamic.slice(0, MAX_DICT_ENTRIES).concat(STATIC_DICT.filter(s => !dynamic.includes(s))).slice(0, 254);

  // 2) tokenize using dict (ESC + 1-byte index)
  const tokenBytes = tokenizeWithDict(text, dict);

  // 3) build Huffman lengths & codes over tokenBytes
  const { lengths } = buildHuffmanLengths(tokenBytes);
  // lengths is object sym->len
  const lengthMap = lengths || {};
  const canonical = buildCanonicalCodes(lengthMap); // { codes, byLen }
  const codes = canonical.codes || {};
  const byLen = canonical.byLen || {};

  // prepare huffman entries: array of {sym, len}
  const huffEntries = Object.keys(lengthMap).map(k => ({ sym: Number(k), len: lengthMap[k] }));

  // 4) huffman encode tokenBytes into bitstream
  const { bytes: huffBytes, bitLen } = huffmanEncodeWithBitlen(tokenBytes, codes);

  // 5) make raw preframe including dict + huff table + bitLen + huffBytes
  const preframe = makeFrameRaw(dict, huffEntries, bitLen, huffBytes);

  // 6) compress preframe with pako.deflate
  const compressed = pako.deflate(preframe);

  // 7) make frame (4-byte length header)
  const frame = new Uint8Array(4 + compressed.length);
  frame.set(u32(compressed.length), 0);
  frame.set(compressed, 4);

  // 8) XOR with key
  const xored = xorBytesWithKey(frame, key);

  // 9) keyed bitpack into printable chars
  const keyed = await getKeyedChars(key || "");
  const outStr = encodeBytesToChars(xored, keyed);
  return outStr;
}

async function decodeAndDecompress(str, key) {
  // keyed set
  const keyed = await getKeyedChars(key || "");

  // bit-decode to bytes
  const bytes = decodeCharsToBytes(str, keyed);

  // XOR descramble
  const descr = xorBytesWithKey(bytes, key);

  // read frame length
  if (descr.length < 4) throw new Error("Frame too small");
  const clen = (descr[0]<<24)|(descr[1]<<16)|(descr[2]<<8)|descr[3];
  if (descr.length < 4 + clen) throw new Error("Frame truncated or invalid compressed length");
  const compressed = descr.slice(4, 4 + clen);

  // inflate
  const preframe = pako.inflate(compressed);

  // parse preframe: dict, huffEntries, bitLen, data
  const { dict, huffEntries, dataBitLen, data } = parseFrameRaw(preframe);

  // build canonical mapping from huffEntries (array of {sym, len})
  const lengthsMap = {};
  for (const he of huffEntries) lengthsMap[he.sym] = he.len;
  const canonical = buildCanonicalCodes(lengthsMap);
  const byLen = canonical.byLen || {};

  // decode Huffman bitstream into token bytes
  const tokenBytes = huffmanDecodeFromBits(data, dataBitLen, byLen);

  // detokenize using dict (dynamic + static merged earlier)
  const text = detokenizeFromBytesWithDict(tokenBytes, dict);
  return text;
}

/* --- XOR helper --- */
function xorBytesWithKey(u8, keyStr) {
  if (!keyStr) return u8;
  const k = enc.encode(keyStr);
  if (k.length === 0) return u8;
  const out = new Uint8Array(u8.length);
  for (let i = 0; i < u8.length; i++) out[i] = u8[i] ^ k[i % k.length];
  return out;
}

/* --- UI wiring (same as before, with updated functions) --- */
const inputEl = document.getElementById("input");
const outputEl = document.getElementById("output");
const keyEl = document.getElementById("key");
const statsEl = document.getElementById("stats");
const loadingSpan = document.getElementById("loading");
const encBtn = document.getElementById("encodeBtn");
const decBtn = document.getElementById("decodeBtn");

let suppress = false;
let initDone = false;

// Build charset (safe when UI elements are absent)
let _initTimer = null;
_initTimer = setTimeout(async () => {
  if (loadingSpan) loadingSpan.textContent = "building alphabet — this can take 0.5–2s depending on CPU";
  await new Promise(r => setTimeout(r, 50));
  BLOCK_CHARS = buildBlockChars();
  if (loadingSpan) loadingSpan.textContent = "alphabet ready";
  initDone = true;
  if (loadingSpan) setTimeout(()=>loadingSpan.remove(), 800);
  try { if (inputEl && inputEl.value) debouncedEncode(); } catch (e) {}
}, 10);

function debounce(fn, ms = 220) {
  let t;
  return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
}

async function doEncodeUI() {
  if (!initDone) { statsEl.textContent = "Still initializing alphabet — wait a moment."; return; }
  if (suppress) return;
  suppress = true;
  try {
    statsEl.textContent = "Encoding (mining dict + huffman + compress) ...";
    const key = keyEl.value || "";
    const out = await compressAndEncode(inputEl.value, key);
    outputEl.value = out;
    const o = inputEl.value.length;
    const e = out.length;
    const pct = o ? Math.round((1 - (e / o)) * 100) : 0;
    statsEl.textContent = `Original ${o} chars → Encoded ${e} chars · approx ${pct}% smaller`;
  } catch (err) {
    statsEl.innerHTML = '<span class="err">Encode error: ' + (err && err.message ? err.message : String(err)) + '</span>';
    console.error(err);
  } finally { suppress = false; }
}

async function doDecodeUI() {
  if (!initDone) { statsEl.textContent = "Still initializing alphabet — wait a moment."; return; }
  if (suppress) return;
  suppress = true;
  try {
    statsEl.textContent = "Decoding ...";
    const key = keyEl.value || "";
    const out = await decodeAndDecompress(outputEl.value, key);
    inputEl.value = out;
    statsEl.textContent = `Decoded length: ${out.length} chars`;
  } catch (err) {
    statsEl.innerHTML = '<span class="err">Decode error: ' + (err && err.message ? err.message : String(err)) + '</span>';
    console.error(err);
  } finally { suppress = false; }
}

const debouncedEncode = debounce(doEncodeUI, 380);
const debouncedDecode = debounce(doDecodeUI, 380);

// Named handlers so they can be removed by cleanup
const _inputHandler = () => debouncedEncode();
const _outputHandler = () => debouncedDecode();
const _keyHandler = () => { debouncedEncode(); debouncedDecode(); };
const _encBtnHandler = (e) => { doEncodeUI(); };
const _decBtnHandler = (e) => { doDecodeUI(); };
const _windowLoadHandler = () => {
  try {
    if (outputEl && outputEl.value) debouncedDecode();
    else if (inputEl && inputEl.value) debouncedEncode();
  } catch (e) {}
};

if (inputEl) inputEl.addEventListener("input", _inputHandler);
if (outputEl) outputEl.addEventListener("input", _outputHandler);
if (keyEl) keyEl.addEventListener("input", _keyHandler);
if (encBtn) encBtn.addEventListener("click", _encBtnHandler);
if (decBtn) decBtn.addEventListener("click", _decBtnHandler);

window.addEventListener("load", _windowLoadHandler);
// Expose programmatic API compatible with v5/kolbe manager
window.encrypt = async (text, key) => {
  if (text == "") return "";
  return await compressAndEncode(text, key);
};

window.decrypt = async (str, key) => {
  if (str == "") return "";
  return await decodeAndDecompress(str, key);
};

// cleanup hook used by manager when unloading versions
window.cleanup = async () => {
  try {
    if (inputEl) inputEl.removeEventListener("input", _inputHandler);
    if (outputEl) outputEl.removeEventListener("input", _outputHandler);
    if (keyEl) keyEl.removeEventListener("input", _keyHandler);
    if (encBtn) encBtn.removeEventListener("click", _encBtnHandler);
    if (decBtn) decBtn.removeEventListener("click", _decBtnHandler);
    window.removeEventListener("load", _windowLoadHandler);
    if (_initTimer) clearTimeout(_initTimer);
  } catch (e) {
    console.warn('cleanup failed', e);
  }
};

})();