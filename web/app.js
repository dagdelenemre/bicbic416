// Sayfa davranışı. Şifre: bicbic416.js. Her şey tarayıcıda çalışır.
import { encryptText, decryptText, randomKeyText, toBase64, fromBase64 } from "./bicbic416.js";

const $ = (id) => document.getElementById(id);
const key = $("key"), input = $("input"), output = $("output"), status = $("status");
const busyButtons = [$("enc"), $("dec")];

const say = (msg, kind = "") => { status.textContent = msg; status.className = kind; };

async function run(fn, busyMsg) {
  if (!key.value) { say("Önce bir anahtar girin veya üretin.", "err"); key.focus(); return; }
  if (!input.value.trim()) { say("Girdi boş.", "err"); input.focus(); return; }
  busyButtons.forEach((b) => (b.disabled = true));
  say(busyMsg);
  await new Promise((r) => setTimeout(r, 20)); // durum yazısı ekrana çıksın
  const t0 = performance.now();
  try {
    output.value = await fn();
    say(`Tamam (${Math.round(performance.now() - t0)} ms).`, "ok");
  } catch (e) {
    output.value = "";
    say(e.message.charAt(0).toUpperCase() + e.message.slice(1) + ".", "err");
  } finally {
    busyButtons.forEach((b) => (b.disabled = false));
  }
}

$("enc").onclick = () => run(async () => {
  const rounds = Math.min(32, Math.max(1, parseInt($("rounds").value, 10) || 16));
  const iterations = Math.min(10000000, Math.max(1000, parseInt($("iters").value, 10) || 600000));
  return toBase64(await encryptText(input.value, key.value, { rounds, iterations }));
}, "Şifreleniyor…");

$("dec").onclick = () => run(async () => {
  let bytes;
  try { bytes = fromBase64(input.value.trim()); }
  catch { throw new Error("girdi geçerli bir şifreli metin değil (base64 bekleniyor)"); }
  return decryptText(bytes, key.value);
}, "Çözülüyor…");

$("gen").onclick = () => {
  key.value = randomKeyText();
  key.type = "text";
  $("show").textContent = "Gizle";
  say("Rastgele anahtar üretildi. Saklayın: bu anahtar olmadan metin çözülemez.", "ok");
};

$("show").onclick = () => {
  const hidden = key.type === "password";
  key.type = hidden ? "text" : "password";
  $("show").textContent = hidden ? "Gizle" : "Göster";
};

$("copy").onclick = async () => {
  if (!output.value) return;
  try { await navigator.clipboard.writeText(output.value); say("Panoya kopyalandı.", "ok"); }
  catch { output.select(); say("Kopyalamak için Ctrl+C kullanın.", ""); }
};

$("swap").onclick = () => {
  if (!output.value) return;
  input.value = output.value;
  output.value = "";
  say("");
};
