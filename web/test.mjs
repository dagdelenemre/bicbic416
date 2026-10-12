// JS uygulamasını C uygulamasına ve bağımsız referanslara karşı doğrular:
//  1. tests/test_kat.c'deki tüm sabit vektörler (blok, zincir, CTR)
//  2. tests/test_hash.c'deki BicBic-Hash vektörleri
//  3. ChaCha20, Node'un OpenSSL uygulamasıyla aynı
//  4. JS ile şifrelenen metin `bicbic coz` ile, `bicbic sifrele` çıktısı JS ile açılır
//     (tek ve iki katman); `bicbic hash` = JS hash
//  5. sürüm 1 örnek dosyası açılır
//  6. yanlış anahtar ve değiştirilmiş metin reddedilir
// Kullanım: node web/test.mjs   (önce: make tool)
import { execFileSync } from "node:child_process";
import { createCipheriv } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import * as S from "./bicbic416.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const hex = (b) => Buffer.from(b).toString("hex");
let fails = 0, checks = 0;
const check = (ok, msg) => { checks++; if (!ok) { fails++; console.log("HATA:", msg); } };

// 1. KAT
const src = readFileSync(path.join(root, "tests/test_kat.c"), "utf8");
const pattern = (p) => [
  Uint8Array.from({ length: 52 }, (_, i) => (p === 0 ? 0 : p === 1 ? i : 0xff)),
  Uint8Array.from({ length: 52 }, (_, i) => (p === 0 ? 0 : p === 1 ? 0x80 + i : 0x80)),
];
for (const m of src.matchAll(/\{\s*(\d),\s*(\d+),\s*"([0-9a-f]{104})"\s*\}/g)) {
  const [key, pt] = pattern(+m[1]);
  const ctx = S.init(key, +m[2]);
  const ct = S.encryptBlock(ctx, pt);
  check(hex(ct) === m[3] && hex(S.decryptBlock(ctx, ct)) === hex(pt), `blok desen ${m[1]} R ${m[2]}`);
}
const joined = (name) => {
  const m = src.match(new RegExp(`static void ${name}\\(void\\)[\\s\\S]*?hex_eq\\([^,]+,[^,]+,\\s*((?:"[0-9a-f]+"\\s*)+)\\)`));
  return [...m[1].matchAll(/"([0-9a-f]+)"/g)].map((x) => x[1]).join("");
};
{
  const ctx = S.init(new Uint8Array(52), 16);
  let b = new Uint8Array(52);
  for (let i = 0; i < 10000; i++) b = S.encryptBlock(ctx, b);
  check(hex(b) === joined("test_chain"), "zincir");
  const ctx2 = S.init(Uint8Array.from({ length: 52 }, (_, i) => i), 16);
  const nonce = Uint8Array.from({ length: 44 }, (_, i) => 0xa0 + i);
  check(hex(S.ctrXor(ctx2, nonce, 1, Uint8Array.from({ length: 100 }, (_, i) => i))) === joined("test_ctr"), "CTR");
}
console.log(`KAT: ${checks - fails}/${checks} vektör C ile aynı`);

// 2. BicBic-Hash: tests/test_hash.c'deki vektörler
{
  const hsrc = readFileSync(path.join(root, "tests/test_hash.c"), "utf8");
  const two = String.raw`"([0-9a-f]{52})"\s*"([0-9a-f]{52})"`;
  let n = 0;
  for (const m of hsrc.matchAll(new RegExp(String.raw`\{\s*"([^"]*)",\s*(?:\d+|sizeof\([^)]*\) - 1),\s*` + two, "g"))) {
    check(hex(S.hash(m[1])) === m[2] + m[3], `hash ${JSON.stringify(m[1])}`);
    n++;
  }
  const pat = Uint8Array.from({ length: 1000 }, (_, i) => (i * 7 + 3) & 255);
  for (const m of hsrc.matchAll(new RegExp(String.raw`\{\s*(\d+),\s*` + two, "g"))) {
    check(hex(S.hash(pat.subarray(0, +m[1]))) === m[2] + m[3], `hash desen ${m[1]}`);
    n++;
  }
  check(n === 16, `16 hash vektörü bekleniyordu, ${n} bulundu`);
  console.log(`BicBic-Hash: ${n} vektör C ile aynı`);
}

// 3. ChaCha20: Node'un OpenSSL uygulamasıyla karşılaştırma
{
  const key = Uint8Array.from({ length: 32 }, (_, i) => (i * 13 + 1) & 255);
  const nonce = Uint8Array.from({ length: 12 }, (_, i) => (i * 7 + 3) & 255);
  for (const [len, counter] of [[0, 0], [1, 0], [64, 0], [65, 1], [1000, 7], [4096, 123456]]) {
    const data = Uint8Array.from({ length: len }, (_, i) => (i * 31 + 5) & 255);
    const iv = Buffer.concat([Buffer.from(new Uint32Array([counter]).buffer), Buffer.from(nonce)]);
    const ref = createCipheriv("chacha20", key, iv).update(data);
    check(hex(S.chacha20Xor(key, nonce, counter, data)) === hex(ref), `ChaCha20 ${len}/${counter}`);
  }
  console.log("ChaCha20: Node (OpenSSL) ile aynı");
}

// 4. Komut satırı aracıyla karşılıklı uyumluluk (tek ve iki katman, sürüm 1 dosyası)
const exe = path.join(root, process.platform === "win32" ? "build/bicbic.exe" : "build/bicbic");
if (existsSync(exe)) {
  const dir = path.join(root, "build/tmp_web");
  mkdirSync(dir, { recursive: true });
  const env = { ...process.env, BICBIC_PAROLA: "Web-Anahtar ğüşıöç 2026" };
  const text = "Merhaba BicBic416! Türkçe: ğüşıöçİ — emoji 🔐\n".repeat(20);

  for (const layers of [1, 2]) {
    const fromJs = await S.encryptText(text, env.BICBIC_PAROLA, { iterations: 2000, layers });
    check(fromJs.length === new TextEncoder().encode(text).length + 36, "ek yük 36 bayt");
    writeFileSync(path.join(dir, "js.bb416"), fromJs);
    execFileSync(exe, ["coz", "-z", path.join(dir, "js.bb416"), path.join(dir, "js.txt")], { env, stdio: "pipe" });
    check(readFileSync(path.join(dir, "js.txt"), "utf8") === text, `JS → bicbic (${layers} katman)`);

    writeFileSync(path.join(dir, "c.txt"), text);
    const args = ["sifrele", "-z", "-i", "2000", ...(layers === 2 ? ["-2"] : []),
                  path.join(dir, "c.txt"), path.join(dir, "c.bb416")];
    execFileSync(exe, args, { env, stdio: "pipe" });
    const cBytes = new Uint8Array(readFileSync(path.join(dir, "c.bb416")));
    check(S.inspect(cBytes).layers === layers, "katman bayrağı");
    check((await S.decryptText(cBytes, env.BICBIC_PAROLA)) === text, `bicbic → JS (${layers} katman)`);
  }

  const out = execFileSync(exe, ["hash", path.join(dir, "c.txt")], { stdio: "pipe" }).toString();
  check(out.slice(0, 104) === hex(S.hash(text)), "bicbic hash = JS hash");
  rmSync(dir, { recursive: true, force: true });
  console.log("Komut satırı aracıyla iki yönlü uyumluluk sınandı (1 ve 2 katman, hash)");
} else {
  console.log("build/bicbic bulunamadı; araç uyumluluk testi atlandı (make tool)");
}

// 5. Sürüm 1 biçimindeki örnek dosya (v0.1.0 ile oluşturuldu) açılmaya devam etmeli
{
  const v1 = new Uint8Array(readFileSync(path.join(root, "tests/data/v1_ornek.bb416")));
  const expect = readFileSync(path.join(root, "tests/data/v1_ornek.txt"), "utf8");
  check(S.inspect(v1).version === 1, "v1 başlığı");
  check((await S.decryptText(v1, "v1-ornek-parola")) === expect, "v1 dosyası açılır");
}

// 6. Reddetme
{
  for (const layers of [1, 2]) {
    const enc = await S.encryptText("gizli", "dogru", { iterations: 1000, layers });
    let err = "";
    try { await S.decryptText(enc, "yanlis"); } catch (e) { err = e.message; }
    check(err.includes("yanlış anahtar"), "yanlış anahtar reddedilmeli");
    for (const [at, mask] of [[1, 0x40], [1, 0x18], [5, 1], [20, 1], [enc.length - 1, 1]]) {
      const t = enc.slice(); t[at] ^= mask;
      err = "";
      try { await S.decryptText(t, "dogru"); } catch (e) { err = e.message; }
      check(err !== "", `değiştirilmiş metin reddedilmeli (bayt ${at})`);
    }
    check((await S.decryptText(S.fromBase64(S.toBase64(enc)), "dogru")) === "gizli", "base64 gidiş-dönüş");
  }
  let err = "";
  try { await S.encryptText("x", "p", { iterations: 1500 }); } catch (e) { err = e.message; }
  check(err.includes("1000"), "1000'in katı olmayan yineleme reddedilmeli");
}

// 7. Log kayıtları (SPEC.md §14): ortak vektörler, kurcalama, anahtar değiştirme, C aracıyla uyum
{
  const vec = JSON.parse(readFileSync(path.join(root, "tests/data/record_vectors.json"), "utf8"));
  for (const v of vec.kayitlar) {
    const s = await S.RecordCipher.create(v.anahtar);
    check(s.keyId === v.kimlik, "kayıt anahtar kimliği");
    const msg = Buffer.from(v.mesaj_hex, "hex"), aad = Buffer.from(v.ek_hex, "hex");
    check((await s.encrypt(msg, aad, { nonce: Buffer.from(v.nonce, "hex") })) === v.kayit, "kayıt vektörü = C");
    check(hex(await s.decryptBytes(v.kayit, aad)) === v.mesaj_hex, "kayıt vektörü açılır");
  }
  for (const h of vec.hashler) check(hex(S.hash(Buffer.from(h.mesaj_hex, "hex"))) === h.hash, "hash vektörü");

  const key = S.generateRecordKey(), s = await S.RecordCipher.create(key);
  const tok = await s.encrypt("kullanici=ayşe ip=203.0.113.7", "web-1");
  check((await s.decrypt(tok, "web-1")) === "kullanici=ayşe ip=203.0.113.7", "kayıt gidiş-dönüş");
  const rejects = async (fn) => { try { await fn(); return false; } catch { return true; } };
  check(await rejects(() => s.decrypt(tok, "web-2")), "yanlış ek bilgi reddedilir");
  for (let i = 8; i < tok.length; i += 7) {
    const bad = tok.slice(0, i) + (tok[i] === "A" ? "B" : "A") + tok.slice(i + 1);
    check(await rejects(() => s.decrypt(bad, "web-1")), `değiştirilmiş kayıt reddedilir (${i})`);
  }
  const ring = await S.RecordCipher.create([S.generateRecordKey(), key]);
  check((await ring.decrypt(tok, "web-1")).startsWith("kullanici="), "anahtar halkası eski kaydı açar");
  const fields = await s.encryptFields({ olay: "giris", ip: "203.0.113.7" }, ["ip"]);
  check(fields.olay === "giris" && fields.ip.startsWith("bb416r1:"), "alan şifreleme");
  check((await s.decryptLine(`x ip=${fields.ip} y`)) === "x ip=203.0.113.7 y", "satır çözme");

  if (existsSync(exe)) {
    const env = { ...process.env, BICBIC_ANAHTAR: key };
    const lines = ["giriş başarılı kullanici=ayşe", "ikinci satır"];
    const jsTokens = (await Promise.all(lines.map((l) => s.encrypt(l)))).join("\n") + "\n";
    const cOut = execFileSync(exe, ["log-coz"], { input: jsTokens, env }).toString().replace(/\r\n/g, "\n");
    check(cOut === lines.join("\n") + "\n", "JS kaydı → bicbic log-coz");
    const cTokens = execFileSync(exe, ["log-sifrele"], { input: lines.join("\n") + "\n", env }).toString();
    const back = await Promise.all(cTokens.trim().split(/\r?\n/).map((t) => s.decrypt(t)));
    check(back.join("\n") === lines.join("\n"), "bicbic log-sifrele → JS");
  }
  console.log("Log kayıtları: C ve Python ile aynı vektörler, C aracıyla iki yönlü uyumluluk");
}

console.log(fails ? `BAŞARISIZ: ${fails} hata` : `TAMAM (${checks} kontrol)`);
process.exit(fails ? 1 : 0);
