// Sayfa davranışı. Şifre ve hash: bicbic416.js. Her şey tarayıcıda çalışır.
import { encryptText, decryptText, inspect, hash, randomKeyText, toBase64, fromBase64 } from "./bicbic416.js";

const $ = (id) => document.getElementById(id);
const key = $("key"), input = $("input"), output = $("output"), status = $("status");
const busyButtons = [$("enc"), $("dec")];

const say = (msg, kind = "") => { status.textContent = msg; status.className = kind; };
const capitalize = (s) => s.charAt(0).toUpperCase() + s.slice(1);

async function run(fn, busyMsg) {
  if (!key.value) { say("Önce bir anahtar girin veya üretin.", "err"); key.focus(); return; }
  if (!input.value.trim()) { say("Girdi boş.", "err"); input.focus(); return; }
  busyButtons.forEach((b) => (b.disabled = true));
  say(busyMsg);
  await new Promise((r) => setTimeout(r, 20)); // durum yazısı ekrana çıksın
  const t0 = performance.now();
  try {
    const { text, detail } = await fn();
    output.value = text;
    say(`Tamam — ${detail} (${Math.round(performance.now() - t0)} ms).`, "ok");
  } catch (e) {
    output.value = "";
    say(capitalize(e.message) + ".", "err");
  } finally {
    busyButtons.forEach((b) => (b.disabled = false));
  }
}

const describe = (info) =>
  `${info.layers === 2 ? "iki katman (BicBic416 + ChaCha20)" : "tek katman (BicBic416)"}, ${info.rounds} tur` +
  (info.version === 1 ? ", eski biçim (v1)" : "");

$("enc").onclick = () => run(async () => {
  const rounds = Math.min(32, Math.max(1, parseInt($("rounds").value, 10) || 16));
  const iters = Math.min(10000000, Math.max(1000, parseInt($("iters").value, 10) || 600000));
  const iterations = Math.round(iters / 1000) * 1000;
  const layers = $("layers2").checked ? 2 : 1;
  const bytes = await encryptText(input.value, key.value, { rounds, iterations, layers });
  return { text: toBase64(bytes), detail: describe(inspect(bytes)) };
}, "Şifreleniyor…");

$("dec").onclick = () => run(async () => {
  let bytes;
  try { bytes = fromBase64(input.value.trim()); }
  catch { throw new Error("girdi geçerli bir şifreli metin değil (base64 bekleniyor)"); }
  const info = inspect(bytes);
  return { text: await decryptText(bytes, key.value), detail: "çözüldü: " + describe(info) };
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

async function copy(textarea, done) {
  if (!textarea.value) return;
  try { await navigator.clipboard.writeText(textarea.value); done("Panoya kopyalandı."); }
  catch { textarea.select(); done("Kopyalamak için Ctrl+C kullanın."); }
}

$("copy").onclick = () => copy(output, (m) => say(m, "ok"));

$("swap").onclick = () => {
  if (!output.value) return;
  input.value = output.value;
  output.value = "";
  say("");
};

// ---- BicBic-Hash: yazdıkça güncellenir ----
const hin = $("hin"), hout = $("hout");
let hashTimer = 0;
const fitHash = () => {
  hout.style.height = "auto";
  hout.style.height = hout.scrollHeight + 2 + "px"; // 104 karakter her ekran genişliğinde tam görünsün
};
const updateHash = () => {
  hout.value = Array.from(hash(hin.value), (b) => b.toString(16).padStart(2, "0")).join("");
  fitHash();
};
window.addEventListener("resize", fitHash);
hin.addEventListener("input", () => {
  clearTimeout(hashTimer);
  hashTimer = setTimeout(updateHash, 120);
});
$("hcopy").onclick = () => copy(hout, (m) => {
  const b = $("hcopy");
  b.textContent = m.startsWith("Panoya") ? "Kopyalandı" : "Ctrl+C ile kopyalayın";
  setTimeout(() => (b.textContent = "Kopyala"), 1500);
});
updateHash();
