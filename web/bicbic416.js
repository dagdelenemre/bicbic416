// BicBic416 — JavaScript uygulaması (tarayıcı ve Node).
// Eğitim amaçlıdır; gerçek gizli veriler için kullanmayın.
// C uygulamasıyla aynı sonuçları verdiği web/test.mjs ile doğrulanır.
//
// İçerik: BicBic416 blok şifresi ve CTR modu, BicBic-Hash, ChaCha20 (iki katmanlı mod için)
// ve parolalı metin şifreleme. Metin biçimi, komut satırı aracının .bb416 dosya biçimiyle
// aynıdır (ayrıntı: tool/bicbic_file.h). Şifreleme sürüm 2 üretir (ek yük 36 bayt):
//   0xB2 | tur + katman bayrağı | yineleme/1000 (2) | tuz (16) | şifreli veri | HMAC-SHA256 ilk 16 bayt
// Çözme sürüm 1 ve 2'yi açar. Sayfa bu baytları base64 olarak gösterir; base64'ten
// çözülüp kaydedilen dosya `bicbic coz` ile açılabilir (ve tersi).

export const BLOCK = 52, KEY = 52, NONCE = 44, MAX_ROUNDS = 32;
export const DEFAULT_ROUNDS = 16, DEFAULT_ITERS = 600000, MAX_ITERS = 10000000;

const ROT = [3, 16, 29, 10, 23, 4, 17, 30, 11, 24, 5, 18, 31];
const KS_MUL = 0x2545f491, KS_GOLD = 0x9e3779b9;

const rotl = (x, r) => (r & 31) ? ((x << r) | (x >>> (32 - r))) >>> 0 : x >>> 0;
const rotr = (x, r) => rotl(x, (32 - r) & 31);

function bitrev(x) {
  x = (((x >>> 1) & 0x55555555) | ((x & 0x55555555) << 1)) >>> 0;
  x = (((x >>> 2) & 0x33333333) | ((x & 0x33333333) << 2)) >>> 0;
  x = (((x >>> 4) & 0x0f0f0f0f) | ((x & 0x0f0f0f0f) << 4)) >>> 0;
  x = (((x >>> 8) & 0x00ff00ff) | ((x & 0x00ff00ff) << 8)) >>> 0;
  return ((x >>> 16) | (x << 16)) >>> 0;
}

function mulinv(a) {
  let inv = a >>> 0;
  for (let k = 0; k < 5; k++) inv = Math.imul(inv, (2 - Math.imul(a, inv)) >>> 0) >>> 0;
  return inv;
}

const load = (b, off = 0) => {
  const S = new Uint32Array(13);
  for (let i = 0; i < 13; i++) {
    const p = off + 4 * i;
    S[i] = (b[p] | (b[p + 1] << 8) | (b[p + 2] << 16) | (b[p + 3] << 24)) >>> 0;
  }
  return S;
};

function store(S, out, off = 0) {
  for (let i = 0; i < 13; i++) {
    const w = S[i], p = off + 4 * i;
    out[p] = w & 255; out[p + 1] = (w >>> 8) & 255; out[p + 2] = (w >>> 16) & 255; out[p + 3] = w >>> 24;
  }
}

// ---- Tur adımları 4–6 (SPEC.md §4); Uint32Array yazımı otomatik mod 2^32 ----
function step4(S) {
  for (let i = 0; i < 6; i++) {
    const j = 12 - i;
    S[j] = S[j] + S[i];
    S[i] ^= rotl(S[j], 7);
  }
}
function step5(S) {
  let t = 0;
  for (let i = 0; i < 13; i++) if (i !== 6) t = (t + S[i]) >>> 0;
  S[6] = S[6] + t;
  for (let i = 0; i < 13; i++) if (i !== 6) S[i] ^= rotl(S[6], i + 1);
}
function step6(S) {
  for (let i = 0; i < 6; i++) { const t = S[i]; S[i] = S[12 - i]; S[12 - i] = t; }
  S[6] = bitrev(S[6]);
}
function step4inv(S) {
  for (let i = 0; i < 6; i++) {
    const j = 12 - i;
    S[i] ^= rotl(S[j], 7);
    S[j] = S[j] - S[i];
  }
}
function step5inv(S) {
  for (let i = 0; i < 13; i++) if (i !== 6) S[i] ^= rotl(S[6], i + 1);
  let t = 0;
  for (let i = 0; i < 13; i++) if (i !== 6) t = (t + S[i]) >>> 0;
  S[6] = S[6] - t;
}

// ---- Anahtar planı (SPEC.md §6) ----
function ksMix(K) {
  for (let i = 0; i < 13; i++) {
    let x = Math.imul(K[i], KS_MUL) >>> 0;
    x = (x ^ (x >>> 16)) >>> 0;
    K[i] = rotl(x, ROT[i]);
  }
  step4(K); step5(K); step6(K);
}

export function init(key, rounds = DEFAULT_ROUNDS) {
  if (!(key instanceof Uint8Array) || key.length !== KEY) throw new Error("anahtar 52 bayt olmalı");
  if (!Number.isInteger(rounds) || rounds < 1 || rounds > MAX_ROUNDS) throw new Error("tur 1..32 olmalı");
  const K = load(key);
  let n = 0;
  const next = () => {
    K[0] ^= Math.imul(n + 1, KS_GOLD) >>> 0;
    ksMix(K); ksMix(K);
    n++;
    return Uint32Array.from(K);
  };
  const rk = [], mk = [], mkinv = [];
  for (let r = 0; r < rounds; r++) {
    rk.push(next());
    const m = next().map((w) => (w | 1) >>> 0);
    mk.push(m);
    mkinv.push(m.map(mulinv));
  }
  rk.push(next());
  return { rounds, rk, mk, mkinv };
}

function encryptWords(ctx, S) {
  const R = ctx.rounds;
  for (let r = 0; r < R; r++) {
    const rk = ctx.rk[r], mk = ctx.mk[r];
    for (let i = 0; i < 13; i++) {
      let x = Math.imul((S[i] ^ rk[i]) >>> 0, mk[i]) >>> 0;
      x = (x ^ (x >>> 16)) >>> 0;
      S[i] = rotl(x, ROT[i]);
    }
    step4(S); step5(S); step6(S);
  }
  for (let i = 0; i < 13; i++) S[i] ^= ctx.rk[R][i];
}

export function encryptBlock(ctx, block) {
  const S = load(block), out = new Uint8Array(BLOCK);
  encryptWords(ctx, S);
  store(S, out);
  return out;
}

export function decryptBlock(ctx, block) {
  const R = ctx.rounds, S = load(block), out = new Uint8Array(BLOCK);
  for (let i = 0; i < 13; i++) S[i] ^= ctx.rk[R][i];
  for (let r = R - 1; r >= 0; r--) {
    step6(S); step5inv(S); step4inv(S);
    for (let i = 0; i < 13; i++) {
      let x = rotr(S[i], ROT[i]);
      x = (x ^ (x >>> 16)) >>> 0;
      S[i] = (Math.imul(x, ctx.mkinv[r][i]) ^ ctx.rk[r][i]) >>> 0;
    }
  }
  store(S, out);
  return out;
}

// CTR: sayaç bloğu = nonce (44) || sayaç (8, LE). Şifreleme = çözme.
export function ctrXor(ctx, nonce, counter, data) {
  const out = new Uint8Array(data.length), blk = new Uint8Array(BLOCK);
  blk.set(nonce, 0);
  let c = BigInt(counter);
  for (let off = 0; off < data.length; off += BLOCK, c++) {
    for (let b = 0; b < 8; b++) blk[NONCE + b] = Number((c >> BigInt(8 * b)) & 255n);
    const ks = encryptBlock(ctx, blk);
    const n = Math.min(BLOCK, data.length - off);
    for (let i = 0; i < n; i++) out[off + i] = data[off + i] ^ ks[i];
  }
  return out;
}

// ---- BicBic-Hash (SPEC.md §12): Miyaguchi–Preneel + Merkle–Damgård -------------
export const HASH_BYTES = 52;
const HASH_ROUNDS = 16;
const HASH_FINAL = new Uint8Array(BLOCK);
HASH_FINAL.set(new TextEncoder().encode("BicBic-Hash/son"));
let hashIV = null; // = E_0(0), ilk kullanımda hesaplanır

function hashCompress(h, m) {
  const e = encryptBlock(init(h, HASH_ROUNDS), m);
  for (let i = 0; i < BLOCK; i++) h[i] ^= e[i] ^ m[i];
}

// data: Uint8Array veya metin (UTF-8). 52 baytlık özet döndürür.
export function hash(data) {
  if (typeof data === "string") data = new TextEncoder().encode(data);
  if (!hashIV) hashIV = encryptBlock(init(new Uint8Array(KEY), HASH_ROUNDS), new Uint8Array(BLOCK));
  const h = hashIV.slice();
  const pad = (((-(data.length + 9)) % BLOCK) + BLOCK) % BLOCK;
  const m = new Uint8Array(data.length + 9 + pad);
  m.set(data);
  m[data.length] = 0x80;
  const bits = (BigInt(data.length) * 8n) & 0xffffffffffffffffn;
  for (let i = 0; i < 8; i++) m[m.length - 8 + i] = Number((bits >> BigInt(8 * i)) & 255n);
  for (let off = 0; off < m.length; off += BLOCK) hashCompress(h, m.subarray(off, off + BLOCK));
  hashCompress(h, HASH_FINAL);
  return h;
}

// ---- ChaCha20 (RFC 8439): iki katmanlı modun ikinci katmanı -----------------------
function quarter(x, a, b, c, d) {
  x[a] += x[b]; x[d] = rotl(x[d] ^ x[a], 16);
  x[c] += x[d]; x[b] = rotl(x[b] ^ x[c], 12);
  x[a] += x[b]; x[d] = rotl(x[d] ^ x[a], 8);
  x[c] += x[d]; x[b] = rotl(x[b] ^ x[c], 7);
}

export function chacha20Xor(key, nonce, counter, data) {
  const st = new Uint32Array(16), x = new Uint32Array(16), out = new Uint8Array(data.length);
  const kv = new DataView(key.buffer, key.byteOffset), nv = new DataView(nonce.buffer, nonce.byteOffset);
  st.set([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]);
  for (let i = 0; i < 8; i++) st[4 + i] = kv.getUint32(4 * i, true);
  st[12] = counter;
  for (let i = 0; i < 3; i++) st[13 + i] = nv.getUint32(4 * i, true);
  const ks = new Uint8Array(64), kd = new DataView(ks.buffer);
  for (let off = 0; off < data.length; off += 64) {
    x.set(st);
    for (let i = 0; i < 10; i++) {
      quarter(x, 0, 4, 8, 12); quarter(x, 1, 5, 9, 13); quarter(x, 2, 6, 10, 14); quarter(x, 3, 7, 11, 15);
      quarter(x, 0, 5, 10, 15); quarter(x, 1, 6, 11, 12); quarter(x, 2, 7, 8, 13); quarter(x, 3, 4, 9, 14);
    }
    for (let i = 0; i < 16; i++) kd.setUint32(4 * i, (x[i] + st[i]) >>> 0, true);
    const n = Math.min(64, data.length - off);
    for (let i = 0; i < n; i++) out[off + i] = data[off + i] ^ ks[i];
    st[12] = st[12] + 1;
  }
  return out;
}

// ---- Parolalı metin şifreleme (.bb416 biçimi; PBKDF2, HKDF, HMAC için WebCrypto) ----
const subtle = globalThis.crypto.subtle;
const V1_HEADER = 70, V1_TAG = 32, V2_FORMAT = 0xb2, V2_HEADER = 20, V2_TAG = 16;
const ITER_UNIT = 1000, MAX_TWO_LAYER = 2 ** 38;
const V2_INFO = new TextEncoder().encode("BicBic416 v2 anahtarlar");

async function pbkdf2(password, salt, iters, bytes) {
  const base = await subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(await subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: iters }, base, bytes * 8));
}

const hmacKey = (raw) => subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);

// Sürüm 2: ana sır = PBKDF2(32), anahtarlar = HKDF(ana sır) → BicBic416 52 | HMAC 32 | ChaCha20 32.
async function keysV2(password, salt, iters) {
  const master = await pbkdf2(password, salt, iters, 32);
  const hk = await subtle.importKey("raw", master, "HKDF", false, ["deriveBits"]);
  const dk = new Uint8Array(await subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: V2_INFO }, hk, 116 * 8));
  master.fill(0);
  const keys = { enc: dk.slice(0, 52), mac: await hmacKey(dk.slice(52, 84)), chacha: dk.slice(84, 116) };
  dk.fill(0);
  return keys;
}

// Şifreli metnin başlığını okur (doğrulamadan). Geçersizse hata fırlatır.
export function inspect(bytes) {
  if (bytes.length >= V2_HEADER + V2_TAG && bytes[0] === V2_FORMAT && !(bytes[1] & 0x80)) {
    const iterations = (bytes[2] | (bytes[3] << 8)) * ITER_UNIT;
    const info = { version: 2, rounds: bytes[1] & 0x3f, layers: bytes[1] & 0x40 ? 2 : 1, iterations,
                   headerLen: V2_HEADER, tagLen: V2_TAG };
    if (info.rounds >= 1 && info.rounds <= MAX_ROUNDS && iterations >= 1 && iterations <= MAX_ITERS) return info;
  } else if (bytes.length >= V1_HEADER + V1_TAG && bytes[0] === 0x42 && bytes[1] === 0x42 &&
             bytes[2] === 0x34 && bytes[3] === 0x31 && bytes[4] === 1) {
    const iterations = new DataView(bytes.buffer, bytes.byteOffset).getUint32(6, true);
    const info = { version: 1, rounds: bytes[5], layers: 1, iterations, headerLen: V1_HEADER, tagLen: V1_TAG };
    if (info.rounds >= 1 && info.rounds <= MAX_ROUNDS && iterations >= 1 && iterations <= MAX_ITERS) return info;
  }
  throw new Error("bu bir BicBic416 şifreli metni değil veya eksik kopyalanmış");
}

// Her zaman sürüm 2 üretir. layers: 1 (BicBic416) veya 2 (BicBic416 + ChaCha20).
export async function encryptText(text, password,
                                  { rounds = DEFAULT_ROUNDS, iterations = DEFAULT_ITERS, layers = 1 } = {}) {
  if (!password) throw new Error("anahtar (parola) boş olamaz");
  if (!Number.isInteger(rounds) || rounds < 1 || rounds > MAX_ROUNDS) throw new Error("tur sayısı 1..32 olmalı");
  if (layers !== 1 && layers !== 2) throw new Error("katman sayısı 1 veya 2 olmalı");
  if (!Number.isInteger(iterations) || iterations < ITER_UNIT || iterations > MAX_ITERS || iterations % ITER_UNIT)
    throw new Error("yineleme sayısı 1000'in katı olmalı (1000..10 000 000)");
  const data = new TextEncoder().encode(text);
  if (layers === 2 && data.length > MAX_TWO_LAYER) throw new Error("iki katmanlı modda en fazla 256 GiB");

  const out = new Uint8Array(V2_HEADER + data.length + V2_TAG);
  out[0] = V2_FORMAT;
  out[1] = rounds | (layers === 2 ? 0x40 : 0);
  out[2] = (iterations / ITER_UNIT) & 255;
  out[3] = (iterations / ITER_UNIT) >> 8;
  globalThis.crypto.getRandomValues(out.subarray(4, V2_HEADER)); // tuz

  const k = await keysV2(password, out.slice(4, V2_HEADER), iterations);
  let ct = ctrXor(init(k.enc, rounds), new Uint8Array(NONCE), 0, data);
  if (layers === 2) ct = chacha20Xor(k.chacha, new Uint8Array(12), 0, ct);
  out.set(ct, V2_HEADER);
  const tag = new Uint8Array(await subtle.sign("HMAC", k.mac, out.subarray(0, V2_HEADER + data.length)));
  out.set(tag.subarray(0, V2_TAG), V2_HEADER + data.length);
  k.enc.fill(0);
  k.chacha.fill(0);
  return out;
}

// Sürüm 1 ve 2'yi açar. Önce etiket doğrulanır; tutmazsa hiçbir şey çözülmez.
export async function decryptText(bytes, password) {
  const info = inspect(bytes);
  const body = bytes.subarray(0, bytes.length - info.tagLen), tag = bytes.subarray(bytes.length - info.tagLen);
  const ct = bytes.subarray(info.headerLen, bytes.length - info.tagLen);
  let enc, chacha = null, mac, nonce;

  if (info.version === 2) {
    const k = await keysV2(password, bytes.slice(4, V2_HEADER), info.iterations);
    ({ enc, mac } = k);
    chacha = k.chacha;
    nonce = new Uint8Array(NONCE);
  } else {
    const dk = await pbkdf2(password, bytes.slice(10, 26), info.iterations, 84);
    enc = dk.slice(0, KEY);
    mac = await hmacKey(dk.slice(KEY));
    nonce = bytes.slice(26, V1_HEADER);
    dk.fill(0);
  }

  const expect = new Uint8Array(await subtle.sign("HMAC", mac, body));
  let diff = 0;
  for (let i = 0; i < info.tagLen; i++) diff |= expect[i] ^ tag[i]; // sabit zamanlı karşılaştırma
  if (diff) throw new Error("yanlış anahtar veya metin değiştirilmiş");

  let plain = ctrXor(init(enc, info.rounds), nonce, 0, ct);
  if (info.layers === 2) plain = chacha20Xor(chacha, new Uint8Array(12), 0, plain);
  enc.fill(0);
  if (chacha) chacha.fill(0);
  return new TextDecoder("utf-8", { fatal: false }).decode(plain);
}

export function randomKeyText(len = 24) {
  const abc = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
  const r = new Uint32Array(len);
  globalThis.crypto.getRandomValues(r);
  let s = "";
  for (let i = 0; i < len; i++) s += abc[r[i] % abc.length]; // 57^24 ≈ 2^140; küçük modülo yanlılığı önemsiz
  return s;
}

export const toBase64 = (b) => {
  let s = "";
  for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode.apply(null, b.subarray(i, i + 0x8000));
  return btoa(s);
};
export const fromBase64 = (t) => {
  const s = atob(t.replace(/\s+/g, ""));
  const b = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) b[i] = s.charCodeAt(i);
  return b;
};
