/* ============================================================
   Crypt-OS  |  Software Swiss Army
   script.js — Hash Analyzer & Decryptor (client-side)
   ============================================================ */

"use strict";

// ── Speed chart ────────────────────────────────────────────
const canvas   = document.getElementById('speedChart');
const ctx      = canvas.getContext('2d');
const speedHistory = Array(60).fill(0);

function resizeCanvas() {
  canvas.width  = canvas.parentElement.clientWidth - 4;
  canvas.height = 80;
}
resizeCanvas();
window.addEventListener('resize', () => { resizeCanvas(); drawChart(); });

function drawChart() {
  const W = canvas.width, H = canvas.height;
  ctx.clearRect(0, 0, W, H);

  // Grid lines
  ctx.strokeStyle = '#1e2d3e';
  ctx.lineWidth   = 1;
  for (let i = 0; i <= 4; i++) {
    const y = H * i / 4;
    ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke();
  }

  // Line
  const max = Math.max(...speedHistory, 1);
  ctx.strokeStyle = '#29b6f6';
  ctx.lineWidth   = 2.5;
  ctx.lineJoin    = 'round';
  ctx.beginPath();
  speedHistory.forEach((v, i) => {
    const x = (i / (speedHistory.length - 1)) * W;
    const y = H - (v / max) * (H - 4) - 2;
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  ctx.stroke();

  // Dots at data points (sparse)
  ctx.fillStyle = '#29b6f6';
  [0, 10, 20, 30, 40, 50, 59].forEach(i => {
    const x = (i / (speedHistory.length - 1)) * W;
    const y = H - (speedHistory[i] / max) * (H - 4) - 2;
    ctx.beginPath(); ctx.arc(x, y, 4, 0, Math.PI * 2); ctx.fill();
  });
}
drawChart();

// ── Log helper ─────────────────────────────────────────────
const logEl = document.getElementById('activityLog');
function addLog(msg, type = '') {
  const empty = logEl.querySelector('.log-empty');
  if (empty) empty.remove();
  const d = document.createElement('div');
  d.className = 'log-entry ' + type;
  const ts = new Date().toLocaleTimeString('nl-NL', { hour12: false });
  d.textContent = `[${ts}] ${msg}`;
  logEl.prepend(d);
}

// ── CPU / Threads simulation ───────────────────────────────
let running       = false;
let cpuTarget     = 0;
let threadTarget  = 0;
let cpuCurrent    = 0;
let threadCurrent = 0;

function updateResources() {
  cpuCurrent    = lerp(cpuCurrent,    cpuTarget,    0.08);
  threadCurrent = lerp(threadCurrent, threadTarget, 0.1);

  document.getElementById('cpuVal').textContent     = Math.round(cpuCurrent) + '%';
  document.getElementById('threadsVal').textContent = Math.round(threadCurrent) + '/16';
  document.getElementById('cpuBar').style.width     = cpuCurrent + '%';
  document.getElementById('threadsBar').style.width = (threadCurrent / 16) * 100 + '%';

  if (running) {
    speedHistory.push(Math.round(cpuCurrent * 45000 + Math.random() * 5000));
    if (speedHistory.length > 60) speedHistory.shift();
    drawChart();
  }
}
function lerp(a, b, t) { return a + (b - a) * t; }
setInterval(updateResources, 1000);

// ── Hash type detection ───────────────────────────────────
function detectHashType(hash) {
  const h = hash.trim();
  if (!h) return null;

  if (/^[a-f0-9]{32}$/i.test(h))  return { name: 'MD5',    bits: 128 };
  if (/^[a-f0-9]{40}$/i.test(h))  return { name: 'SHA-1',  bits: 160 };
  if (/^[a-f0-9]{56}$/i.test(h))  return { name: 'SHA-224',bits: 224 };
  if (/^[a-f0-9]{64}$/i.test(h))  return { name: 'SHA-256',bits: 256 };
  if (/^[a-f0-9]{96}$/i.test(h))  return { name: 'SHA-384',bits: 384 };
  if (/^[a-f0-9]{128}$/i.test(h)) return { name: 'SHA-512',bits: 512 };
  if (/^\$2[aby]\$\d{2}\$/.test(h))return { name: 'bcrypt', bits: null };
  if (/^\$argon2/.test(h))         return { name: 'Argon2', bits: null };
  if (/^[a-f0-9]{32}:[a-f0-9]{32}$/i.test(h)) return { name: 'MD5 + Salt', bits: 128 };
  if (/^[A-Za-z0-9+/=]{24}$/.test(h)) return { name: 'Base64 (possible)', bits: null };
  if (/^[A-Z2-7=]{8,}$/.test(h))  return { name: 'Base32 (possible)', bits: null };

  return { name: 'Unknown / Custom', bits: null };
}

// ── Analyze Type ──────────────────────────────────────────
function analyzeType() {
  const hash = document.getElementById('hashInput').value.trim();
  const resultBox = document.getElementById('resultBox');

  if (!hash) {
    showResult('⚠ Voer eerst een hash in.', 'error');
    addLog('Analyze geannuleerd: geen input.', 'err');
    return;
  }

  const type = detectHashType(hash);
  const lines = [
    `HASH TYPE ANALYSIS`,
    `──────────────────`,
    `Input      : ${hash.slice(0, 32)}${hash.length > 32 ? '…' : ''}`,
    `Length     : ${hash.length} chars`,
    `Detected   : ${type ? type.name : 'Onbekend'}`,
    type && type.bits ? `Bit length : ${type.bits}-bit` : '',
    `Entropy    : ${estimateEntropy(hash).toFixed(2)} bits/char`,
    `Charset    : ${detectCharset(hash)}`,
  ].filter(Boolean).join('\n');

  showResult(lines, 'info');
  addLog(`Hash geanalyseerd → ${type ? type.name : 'Onbekend'}`, 'info');
}

function estimateEntropy(s) {
  const freq = {};
  for (const c of s) freq[c] = (freq[c] || 0) + 1;
  return Object.values(freq).reduce((e, f) => {
    const p = f / s.length;
    return e - p * Math.log2(p);
  }, 0);
}

function detectCharset(s) {
  if (/^[a-f0-9]+$/i.test(s)) return 'Hexadecimaal';
  if (/^[A-Za-z0-9+/=]+$/.test(s)) return 'Base64';
  if (/^[A-Z2-7=]+$/.test(s)) return 'Base32';
  return 'Mixed / Binary';
}

// ── Start Decryption ──────────────────────────────────────
let decryptTimeout = null;

function startDecryption() {
  const hash = document.getElementById('hashInput').value.trim();
  if (!hash) {
    showResult('⚠ Geen hash ingevoerd. Probeer opnieuw.', 'error');
    addLog('Decryptie mislukt: leeg veld.', 'err');
    return;
  }

  if (running) {
    stopDecryption();
    return;
  }

  const type = detectHashType(hash);
  addLog(`Decryptie gestart voor ${type ? type.name : 'onbekend'} hash.`, '');
  addLog(`Hash: ${hash.slice(0, 20)}…`, '');

  running      = true;
  cpuTarget    = 60 + Math.random() * 35;
  threadTarget = 8 + Math.floor(Math.random() * 8);

  document.querySelector('.btn-primary').textContent = 'STOP';
  showResult(
    `DECRYPTING...\n──────────────\nType   : ${type ? type.name : 'Onbekend'}\nStatus : Bezig...\nProbing rainbow tables & wordlists…`,
    ''
  );

  // Simulate a process
  let elapsed = 0;
  const interval = setInterval(() => {
    elapsed++;
    addLog(`Thread probe [${elapsed * 3}/${Math.round(threadTarget) * 3}]…`);
    if (elapsed >= Math.round(threadTarget)) {
      clearInterval(interval);
      finishDecryption(hash, type);
    }
  }, 800);

  decryptTimeout = interval;
}

function finishDecryption(hash, type) {
  running      = false;
  cpuTarget    = 0;
  threadTarget = 0;
  document.querySelector('.btn-primary').textContent = 'START DECRYPTION';

  // For MD5 / SHA-1 we can try a simple reverse lookup via an open API
  if (type && (type.name === 'MD5' || type.name === 'SHA-1')) {
    addLog(`Querying online lookup voor ${type.name}…`, 'info');
    fetchHashLookup(hash, type.name);
  } else {
    showResult(
      `RESULTAAT\n──────────────\nType   : ${type ? type.name : 'Onbekend'}\nStatus : Hash type is niet omkeerbaar via brute-force.\n\nTip: gebruik gespecialiseerde tools (Hashcat/John) voor dit type.`,
      'error'
    );
    addLog(`Decryptie afgerond – type niet direct reverseerbaar.`, 'info');
  }
}

async function fetchHashLookup(hash, typeName) {
  try {
    // MD5Decrypt public API (no auth needed for simple lookups)
    const url = `https://md5decrypt.net/Api/api.php?hash=${hash}&hash_type=${typeName.toLowerCase().replace('-','')}&email=null&code=null`;
    const resp = await fetch(url);
    const text = (await resp.text()).trim();

    if (text && text !== '404' && text.length < 200) {
      showResult(
        `✓ GEVONDEN!\n──────────────\nType     : ${typeName}\nHash     : ${hash}\nPlaintext: ${text}`,
        'ok'
      );
      addLog(`Plaintext gevonden: "${text}"`, 'ok');
    } else {
      showResult(
        `✗ NIET GEVONDEN\n──────────────\nType   : ${typeName}\nHash   : ${hash}\nResultaat: Niet in database — probeer Hashcat.`,
        'error'
      );
      addLog('Niet gevonden in online database.', 'err');
    }
  } catch (e) {
    // fallback
    showResult(
      `✗ OFFLINE\n──────────────\nType   : ${typeName}\nNetwerk lookup mislukt. Controleer verbinding.\nHash   : ${hash}`,
      'error'
    );
    addLog('Netwerkfout bij online lookup.', 'err');
  }
}

function stopDecryption() {
  if (decryptTimeout) clearInterval(decryptTimeout);
  running      = false;
  cpuTarget    = 0;
  threadTarget = 0;
  document.querySelector('.btn-primary').textContent = 'START DECRYPTION';
  showResult('⏹ Decryptie gestopt door gebruiker.', 'error');
  addLog('Decryptie gestopt.', 'err');
}

// ── Result helper ─────────────────────────────────────────
function showResult(text, type) {
  const box = document.getElementById('resultBox');
  box.textContent = text;
  box.className   = 'result-box ' + type;
  box.classList.remove('hidden');
}

// ── Init ──────────────────────────────────────────────────
addLog('Systeem gestart.', 'ok');
addLog('Crypt-OS gereed.', 'ok');
