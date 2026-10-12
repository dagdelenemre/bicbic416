// JS uygulamasını C uygulamasına karşı doğrular:
//  1. tests/test_kat.c'deki tüm sabit vektörler (blok, zincir, CTR)
//  2. JS ile şifrelenen metin `bicbic coz` ile, `bicbic sifrele` çıktısı JS ile açılır
//  3. yanlış anahtar ve değiştirilmiş metin reddedilir
// Kullanım: node web/test.mjs   (önce: make tool)
import { execFileSync } from "node:child_process";
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

// 2. Komut satırı aracıyla karşılıklı uyumluluk
const exe = path.join(root, process.platform === "win32" ? "build/bicbic.exe" : "build/bicbic");
if (existsSync(exe)) {
  const dir = path.join(root, "build/tmp_web");
  mkdirSync(dir, { recursive: true });
  const env = { ...process.env, BICBIC_PAROLA: "Web-Anahtar ğüşıöç 2026" };
  const text = "Merhaba BicBic416! Türkçe: ğüşıöçİ — emoji 🔐\n".repeat(20);

  const fromJs = await S.encryptText(text, env.BICBIC_PAROLA, { iterations: 2000 });
  writeFileSync(path.join(dir, "js.bb416"), fromJs);
  execFileSync(exe, ["coz", "-z", path.join(dir, "js.bb416"), path.join(dir, "js.txt")], { env, stdio: "pipe" });
  check(readFileSync(path.join(dir, "js.txt"), "utf8") === text, "JS → bicbic.exe");

  writeFileSync(path.join(dir, "c.txt"), text);
  execFileSync(exe, ["sifrele", "-z", "-i", "2000", path.join(dir, "c.txt"), path.join(dir, "c.bb416")], { env, stdio: "pipe" });
  const back = await S.decryptText(new Uint8Array(readFileSync(path.join(dir, "c.bb416"))), env.BICBIC_PAROLA);
  check(back === text, "bicbic.exe → JS");
  rmSync(dir, { recursive: true, force: true });
  console.log("Komut satırı aracıyla iki yönlü uyumluluk sınandı");
} else {
  console.log("build/bicbic bulunamadı; uyumluluk testi atlandı (make tool)");
}

// 3. Reddetme
{
  const enc = await S.encryptText("gizli", "dogru", { iterations: 1000 });
  let err = "";
  try { await S.decryptText(enc, "yanlis"); } catch (e) { err = e.message; }
  check(err.includes("yanlış anahtar"), "yanlış anahtar reddedilmeli");
  const t = enc.slice(); t[75] ^= 1;
  err = "";
  try { await S.decryptText(t, "dogru"); } catch (e) { err = e.message; }
  check(err.includes("değiştirilmiş"), "değiştirilmiş metin reddedilmeli");
  check((await S.decryptText(S.fromBase64(S.toBase64(enc)), "dogru")) === "gizli", "base64 gidiş-dönüş");
}

console.log(fails ? `BAŞARISIZ: ${fails} hata` : `TAMAM (${checks} kontrol)`);
process.exit(fails ? 1 : 0);
