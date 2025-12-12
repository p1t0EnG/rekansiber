<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>IOC Checker — RA Security</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap" rel="stylesheet">
  <style>
    body { font-family: Inter, system-ui, Arial; margin: 0; background: #07102a; color: #e6eef9; }
    .wrap { max-width: 980px; margin: 48px auto; padding: 24px; }
    h1 { font-size: 28px; margin-bottom: 12px; color: #fff; }
    .form { display:flex; gap:8px; margin-bottom: 18px; }
    input[type="text"] { flex:1; padding:10px 12px; border-radius:8px; border:1px solid rgba(255,255,255,0.06); background: rgba(255,255,255,0.02); color: #fff; }
    button { padding:10px 16px; border-radius:8px; border:none; background:#1f6feb; color:#fff; font-weight:600; cursor:pointer; }
    .result { background: rgba(255,255,255,0.02); padding:16px; border-radius:8px; margin-top:12px; }
    .provider { border-bottom:1px dashed rgba(255,255,255,0.04); padding:8px 0; }
    pre { white-space:pre-wrap; word-break:break-word; margin:0; color:#dbeafe; font-size:13px; }
    .muted { color: #9fb7ff; font-size:13px; }
  </style>
</head>
<body>
  <div class="wrap">
    <h1>IOC Checker — RA Security</h1>
    <p class="muted">Masukkan satu IP / domain / atau hash. Hasil akan dikumpulkan dari beberapa layanan.</p>

    <div class="form">
      <input id="ioc" type="text" placeholder="Contoh: 1.2.3.4 atau example.com atau 44f1..." />
      <button id="checkBtn">Check</button>
    </div>

    <div id="loading" class="muted" style="display:none">Memeriksa... mohon tunggu.</div>
    <div id="error" style="color:#ffb4b4; display:none;"></div>

    <div id="out" class="result" style="display:none"></div>
  </div>

<script>
const base = "" ; // kosong = relative path; jika backend di subdomain, isi base URL: e.g. "https://ioc.yourdomain.com"
const checkBtn = document.getElementById('checkBtn');
const iocInput = document.getElementById('ioc');
const out = document.getElementById('out');
const loading = document.getElementById('loading');
const error = document.getElementById('error');

function showError(msg){
  error.style.display = 'block';
  error.innerText = msg;
  loading.style.display = 'none';
  out.style.display = 'none';
}

function renderResult(data){
  out.style.display = 'block';
  loading.style.display = 'none';
  error.style.display = 'none';
  out.innerHTML = `<div class="muted">IOC: ${data.ioc} — type: ${data.type}</div><hr/>`;

  const res = data.results || {};
  for (const [provider, v] of Object.entries(res)) {
    const provEl = document.createElement('div');
    provEl.className = 'provider';
    const title = document.createElement('div');
    title.innerHTML = `<strong>${provider}</strong> ${v && v.ok === false ? '<span style="color:#ffb4b4"> (error)</span>' : ''}`;
    provEl.appendChild(title);
    const pre = document.createElement('pre');
    // pretty print JSON or display error
    if (!v) {
      pre.innerText = 'No data';
    } else if (v.error) {
      pre.innerText = v.error;
    } else {
      try {
        pre.innerText = JSON.stringify(v.data || v, null, 2);
      } catch(e){
        pre.innerText = String(v);
      }
    }
    provEl.appendChild(pre);
    out.appendChild(provEl);
  }
}

async function doCheck(){
  const ioc = iocInput.value.trim();
  if (!ioc) { showError('Masukkan IP/domain/hash terlebih dahulu'); return; }
  loading.style.display = 'block';
  out.style.display = 'none';
  error.style.display = 'none';

  try {
    const url = base + '/ioc/check?ioc=' + encodeURIComponent(ioc);
    const r = await fetch(url, { method: 'GET' });
    if (!r.ok) {
      const txt = await r.text();
      showError('Upstream error: ' + r.status + ' ' + txt);
      return;
    }
    const data = await r.json();
    renderResult(data);
  } catch (e) {
    showError('Network error: ' + e.message);
  }
}

checkBtn.addEventListener('click', doCheck);
iocInput.addEventListener('keypress', function(e){
  if (e.key === 'Enter') doCheck();
});
</script>
</body>
</html>
