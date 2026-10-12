// BicBic416 — JavaScript uygulaması (tarayıcı ve Node).
// Eğitim amaçlıdır; gerçek gizli veriler için kullanmayın.
// C uygulamasıyla aynı sonuçları verdiği web/test.mjs ile doğrulanır.
//
// Metin biçimi, komut satırı aracının .bb416 dosya biçimiyle aynıdır (tool/bicbic_file.h):
//   "BB41" | sürüm 1 | tur | PBKDF2 yineleme (LE) | tuz 16 | nonce 44 | şifreli veri | HMAC-SHA256 32
// Sayfa bunu base64 olarak gösterir; base64'ten çözülen bayt dizisi doğrudan
// `bicbic coz` ile açılabilir (ve tersi).

export const BLOCK = 52, KEY = 52, NONCE = 44, MAX_ROUNDS = 32;
export const DEFAULT_ROUNDS = 16, DEFAULT_ITERS = 600000, MAX_ITERS = 10000000;
const HEADER = 70, TAG = 32, SALT = 16;

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

// ---- Parolalı metin şifreleme (.bb416 biçimi, WebCrypto ile PBKDF2 + HMAC) ----
const subtle = globalThis.crypto.subtle;

async function deriveKeys(password, salt, iters) {
  const base = await subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const dk = new Uint8Array(await subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: iters }, base, 84 * 8));
  const macKey = await subtle.importKey("raw", dk.slice(KEY), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
  return { encKey: dk.slice(0, KEY), macKey };
}

export async function encryptText(text, password, { rounds = DEFAULT_ROUNDS, iterations = DEFAULT_ITERS } = {}) {
  if (!password) throw new Error("anahtar (parola) boş olamaz");
  const data = new TextEncoder().encode(text);
  const out = new Uint8Array(HEADER + data.length + TAG);
  out.set([0x42, 0x42, 0x34, 0x31, 1, rounds], 0);
  new DataView(out.buffer).setUint32(6, iterations, true);
  globalThis.crypto.getRandomValues(out.subarray(10, HEADER)); // tuz + nonce
  const salt = out.slice(10, 26), nonce = out.slice(26, HEADER);
  const { encKey, macKey } = await deriveKeys(password, salt, iterations);
  out.set(ctrXor(init(encKey, rounds), nonce, 0, data), HEADER);
  const tag = new Uint8Array(await subtle.sign("HMAC", macKey, out.subarray(0, HEADER + data.length)));
  out.set(tag, HEADER + data.length);
  encKey.fill(0);
  return out;
}

export async function decryptText(bytes, password) {
  if (bytes.length < HEADER + TAG || bytes[0] !== 0x42 || bytes[1] !== 0x42 || bytes[2] !== 0x34 ||
      bytes[3] !== 0x31 || bytes[4] !== 1)
    throw new Error("bu bir BicBic416 şifreli metni değil veya eksik kopyalanmış");
  const rounds = bytes[5], iters = new DataView(bytes.buffer, bytes.byteOffset).getUint32(6, true);
  if (rounds < 1 || rounds > MAX_ROUNDS || iters < 1 || iters > MAX_ITERS)
    throw new Error("başlık geçersiz");
  const body = bytes.subarray(0, bytes.length - TAG), tag = bytes.subarray(bytes.length - TAG);
  const { encKey, macKey } = await deriveKeys(password, bytes.slice(10, 26), iters);
  if (!(await subtle.verify("HMAC", macKey, tag, body)))
    throw new Error("yanlış anahtar veya metin değiştirilmiş");
  const plain = ctrXor(init(encKey, rounds), bytes.slice(26, HEADER), 0, bytes.subarray(HEADER, bytes.length - TAG));
  encKey.fill(0);
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
