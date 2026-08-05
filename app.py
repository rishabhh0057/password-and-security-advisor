"""
Password Security Advisor - Flask Application
Serves the web UI and exposes JSON API endpoints for password analysis.
"""

import os
from flask import Flask, request, jsonify, render_template_string
from password_checker import analyze_password, generate_strong_password

app = Flask(__name__)

PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Password Security Advisor</title>
<style>
  :root {
    --bg: #0f1220;
    --card: #171b2e;
    --border: #262b45;
    --text: #e9ebf7;
    --muted: #9aa0c0;
    --accent: #6c5ce7;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    font-family: 'Segoe UI', Roboto, Arial, sans-serif;
    background: radial-gradient(circle at top, #1b1f38, #0f1220 60%);
    color: var(--text);
    min-height: 100vh;
    display: flex;
    justify-content: center;
    padding: 40px 16px;
  }
  .wrap { width: 100%; max-width: 560px; }
  h1 { font-size: 1.6rem; margin-bottom: 4px; }
  p.sub { color: var(--muted); margin-top: 0; margin-bottom: 24px; }
  .card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 24px;
    margin-bottom: 20px;
  }
  .input-row { display: flex; gap: 8px; }
  input[type=text], input[type=password] {
    flex: 1;
    padding: 12px 14px;
    border-radius: 10px;
    border: 1px solid var(--border);
    background: #10142a;
    color: var(--text);
    font-size: 1rem;
  }
  input:focus { outline: 2px solid var(--accent); }
  button {
    cursor: pointer;
    border: none;
    border-radius: 10px;
    padding: 12px 16px;
    font-size: 0.95rem;
    font-weight: 600;
  }
  .btn-primary { background: var(--accent); color: white; }
  .btn-ghost { background: #232849; color: var(--text); }
  .btn-toggle { background: transparent; color: var(--muted); border: 1px solid var(--border); }
  .row { display: flex; gap: 10px; margin-top: 10px; flex-wrap: wrap; }
  .meter-track {
    height: 10px;
    border-radius: 6px;
    background: #10142a;
    overflow: hidden;
    margin-top: 16px;
  }
  .meter-fill {
    height: 100%;
    width: 0%;
    transition: width 0.35s ease, background 0.35s ease;
  }
  .strength-label { margin-top: 8px; font-weight: 700; }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-top: 18px; }
  .stat {
    background: #10142a;
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 10px 12px;
    font-size: 0.85rem;
    color: var(--muted);
  }
  .stat b { color: var(--text); display: block; font-size: 1rem; }
  ul.feedback { margin: 16px 0 0; padding-left: 20px; color: var(--muted); }
  ul.feedback li { margin-bottom: 6px; }
  .checkline { display: flex; align-items: center; gap: 8px; font-size: 0.85rem; color: var(--muted); margin-top: 12px;}
  .footer-note { color: var(--muted); font-size: 0.8rem; text-align: center; margin-top: 20px; }
  .gen-output {
    margin-top: 12px;
    background: #10142a;
    border: 1px dashed var(--border);
    border-radius: 10px;
    padding: 12px;
    font-family: 'Consolas', monospace;
    word-break: break-all;
  }
</style>
</head>
<body>
<div class="wrap">
  <h1>🔐 Password Security Advisor</h1>
  <p class="sub">Check password strength, breach exposure, and get an instant secure password.</p>

  <div class="card">
    <div class="input-row">
      <input type="password" id="pwInput" placeholder="Type a password to analyze..." autocomplete="new-password" />
      <button class="btn-ghost" id="toggleVis">👁</button>
    </div>

    <div class="checkline">
      <input type="checkbox" id="breachCheck" checked />
      <label for="breachCheck">Check against known data breaches (HaveIBeenPwned)</label>
    </div>

    <div class="meter-track"><div class="meter-fill" id="meterFill"></div></div>
    <div class="strength-label" id="strengthLabel">Enter a password above</div>

    <div class="grid" id="statsGrid" style="display:none;">
      <div class="stat">Entropy<b id="statEntropy">-</b></div>
      <div class="stat">Est. crack time<b id="statCrack">-</b></div>
      <div class="stat">Length<b id="statLength">-</b></div>
      <div class="stat">Breach status<b id="statBreach">-</b></div>
    </div>

    <ul class="feedback" id="feedbackList"></ul>
  </div>

  <div class="card">
    <div class="row" style="justify-content: space-between; align-items:center;">
      <strong>Need a strong password instead?</strong>
      <button class="btn-primary" id="genBtn">Generate</button>
    </div>
    <div class="gen-output" id="genOutput" style="display:none;"></div>
  </div>

  <p class="footer-note">Nothing is stored. Breach checks use k-anonymity — only a partial hash is ever sent.</p>
</div>

<script>
const pwInput = document.getElementById('pwInput');
const toggleVis = document.getElementById('toggleVis');
const breachCheck = document.getElementById('breachCheck');
const meterFill = document.getElementById('meterFill');
const strengthLabel = document.getElementById('strengthLabel');
const statsGrid = document.getElementById('statsGrid');
const feedbackList = document.getElementById('feedbackList');
const genBtn = document.getElementById('genBtn');
const genOutput = document.getElementById('genOutput');

let debounceTimer;

toggleVis.addEventListener('click', () => {
  pwInput.type = pwInput.type === 'password' ? 'text' : 'password';
});

function colorForScore(score) {
  if (score >= 80) return '#2ecc71';
  if (score >= 60) return '#6c5ce7';
  if (score >= 40) return '#f1c40f';
  if (score >= 20) return '#e67e22';
  return '#e74c3c';
}

async function analyze() {
  const password = pwInput.value;
  if (!password) {
    meterFill.style.width = '0%';
    strengthLabel.textContent = 'Enter a password above';
    statsGrid.style.display = 'none';
    feedbackList.innerHTML = '';
    return;
  }

  try {
    const res = await fetch('/api/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password, check_breach: breachCheck.checked })
    });
    const data = await res.json();
    if (data.error) return;

    meterFill.style.width = data.score + '%';
    meterFill.style.background = colorForScore(data.score);
    strengthLabel.textContent = `${data.strength} (${data.score}/100)`;
    strengthLabel.style.color = colorForScore(data.score);

    statsGrid.style.display = 'grid';
    document.getElementById('statEntropy').textContent = data.entropy_bits + ' bits';
    document.getElementById('statCrack').textContent = data.crack_time_estimate;
    document.getElementById('statLength').textContent = data.length + ' chars';

    let breachText = 'Not checked';
    if (data.breach_info.pwned === true) breachText = `Found (${data.breach_info.count.toLocaleString()}x)`;
    else if (data.breach_info.pwned === false) breachText = 'Not found ✓';
    else if (data.breach_info.error) breachText = 'Unavailable';
    document.getElementById('statBreach').textContent = breachText;

    feedbackList.innerHTML = '';
    data.feedback.forEach(f => {
      const li = document.createElement('li');
      li.textContent = f;
      feedbackList.appendChild(li);
    });
  } catch (e) {
    console.error(e);
  }
}

pwInput.addEventListener('input', () => {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(analyze, 350);
});
breachCheck.addEventListener('change', analyze);

genBtn.addEventListener('click', async () => {
  const res = await fetch('/api/generate');
  const data = await res.json();
  genOutput.style.display = 'block';
  genOutput.textContent = data.password;
});
</script>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(PAGE)


@app.route("/api/check", methods=["POST"])
def api_check():
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    check_breach = data.get("check_breach", True)

    if not password:
        return jsonify({"error": "No password provided"}), 400

    result = analyze_password(password, check_breach=check_breach)
    return jsonify(result)


@app.route("/api/generate", methods=["GET"])
def api_generate():
    length = request.args.get("length", default=16, type=int)
    password = generate_strong_password(length)
    return jsonify({"password": password})


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
