// ─── Data ────────────────────────────────────────────────────────────────────
const SERVICES = {
  21:'FTP', 22:'SSH', 23:'Telnet', 25:'SMTP', 53:'DNS',
  80:'HTTP', 110:'POP3', 143:'IMAP', 443:'HTTPS', 445:'SMB',
  3306:'MySQL', 3389:'RDP', 5900:'VNC', 8080:'HTTP-Alt', 8443:'HTTPS-Alt',
  27017:'MongoDB', 6379:'Redis', 5432:'PostgreSQL', 1433:'MSSQL',
  111:'RPC', 135:'MS-RPC', 139:'NetBIOS', 161:'SNMP',
};
const RISK = {
  21:'high', 23:'high', 445:'high', 3389:'high', 5900:'high',
  139:'high', 111:'high', 135:'high', 161:'high', 27017:'high',
  6379:'high', 1433:'high', 25:'med', 110:'med', 143:'med',
  3306:'med', 5432:'med', 8080:'med', 80:'low', 443:'low', 22:'low', 53:'low',
};
const NOTES = {
  21:'Transmits credentials in plaintext — use SFTP instead',
  22:'Encrypted SSH — ensure key-based auth, disable root login',
  23:'CRITICAL: Plaintext Telnet, disable immediately',
  25:'SMTP relay — verify it is not an open relay',
  53:'DNS — check for zone transfer vulnerability',
  80:'Unencrypted HTTP — redirect to HTTPS',
  443:'HTTPS — verify TLS version and certificate',
  445:'SMB — major ransomware attack vector, restrict access',
  3306:'MySQL exposed — restrict to localhost only',
  3389:'RDP — common brute-force target, use NLA + VPN',
  5900:'VNC — ensure strong password, restrict by IP',
  8080:'Alternate HTTP — check for exposed admin panels',
  139:'Legacy NetBIOS — disable if not needed',
  27017:'MongoDB — should never be publicly exposed',
  6379:'Redis — no auth by default, critical exposure',
};
const DEMO_OPEN = [22, 80, 443, 8080, 3306, 21, 23, 139, 445, 3389];

let openPorts = [], scanStart;
const term = document.getElementById('terminal');

// ─── Terminal helpers ─────────────────────────────────────────────────────────
function log(text, cls = '') {
  const d = document.createElement('div');
  d.className = 'line ' + cls;
  d.textContent = text;
  term.appendChild(d);
  term.scrollTop = term.scrollHeight;
}
function clearTerm() { term.innerHTML = ''; }

// ─── Scan ─────────────────────────────────────────────────────────────────────
function startScan() {
  const host = document.getElementById('host').value.trim();
  const p1   = parseInt(document.getElementById('p1').value);
  const p2   = parseInt(document.getElementById('p2').value);
  if (!host)      { alert('Enter a target host.'); return; }
  if (p1 >= p2)   { alert('Start port must be less than end port.'); return; }
  if (p2 - p1 > 9999) { alert('Max range is 10,000 ports for demo.'); return; }

  openPorts = [];
  clearTerm();
  document.getElementById('scanBtn').disabled = true;
  document.getElementById('statsRow').style.display = 'none';
  document.getElementById('aiPanel').style.display  = 'none';
  document.getElementById('askBtn').style.display   = 'none';

  log('╔══════════════════════════════════════════════╗', 'dim');
  log('║          PYTHON PORT SCANNER  v1.0           ║', 'head');
  log('╚══════════════════════════════════════════════╝', 'dim');
  log('');
  log('  [*] Target   : ' + host, 'info');
  log('  [*] Range    : ' + p1 + ' – ' + p2, 'info');
  log('  [*] Protocol : TCP (connect scan)', 'info');
  log('  [*] Started  : ' + new Date().toLocaleTimeString(), 'dim');
  log('');
  log('  Scanning...', 'dim');
  log('');

  scanStart = Date.now();
  simulateScan(host, p1, p2);
}

function simulateScan(host, p1, p2) {
  const total = p2 - p1 + 1;
  const realOpen = DEMO_OPEN.filter(p => p >= p1 && p <= p2);
  let done = 0;
  const batchSize = Math.max(1, Math.floor(total / 60));

  function tick() {
    for (let i = 0; i < batchSize && done < total; i++, done++) {
      const port = p1 + done;
      // Open if in demo list, or rare random hit for realism
      const isOpen = realOpen.includes(port) || (done > 0 && done % 313 === 0 && Math.random() < 0.5);
      if (isOpen) {
        openPorts.push(port);
        const svc = SERVICES[port] || 'unknown';
        log('  [OPEN]  ' + String(port).padEnd(6) + '  →  ' + svc, 'open');
      }
      if (done % Math.max(1, Math.floor(total / 8)) === 0) {
        const pct = Math.round((done / total) * 100);
        log('  [....] Scanned ' + done + '/' + total + ' (' + pct + '%)', 'dim');
      }
    }
    if (done < total) {
      setTimeout(tick, 18);
    } else {
      finishScan(host);
    }
  }
  tick();
}

function finishScan(host) {
  const elapsed = ((Date.now() - scanStart) / 1000).toFixed(1);
  log('');
  log('  ══════════════════════════════════════════════', 'dim');
  log('  [✓] Scan complete in ' + elapsed + 's', 'info');
  log('  [✓] ' + openPorts.length + ' open port(s) found', openPorts.length > 0 ? 'open' : 'dim');
  log('  ══════════════════════════════════════════════', 'dim');

  document.getElementById('scanBtn').disabled = false;
  document.getElementById('sPorts').textContent = openPorts.length;
  document.getElementById('sTime').textContent  = elapsed + 's';
  document.getElementById('statsRow').style.display = 'grid';

  runAI(host);
}

// ─── AI Analysis ──────────────────────────────────────────────────────────────
function runAI(host) {
  const panel = document.getElementById('aiPanel');
  panel.style.display = 'block';
  document.getElementById('aiSpinner').style.display = 'inline-block';
  document.getElementById('aiText').textContent = 'Sending results to Claude AI for threat assessment...';
  document.getElementById('portBody').innerHTML = '';
  document.getElementById('riskFill').style.width = '0%';

  const portList = openPorts.length
    ? openPorts.map(p => p + ' (' + (SERVICES[p] || 'unknown') + ')').join(', ')
    : 'no open ports found';

  const prompt =
    'You are a network security analyst. A TCP port scan of host "' + host + '" found these open ports: ' + portList + '.\n\n' +
    'Provide a concise security assessment in exactly 3 sentences:\n' +
    '1. Overall risk level (use exactly one of: Low / Medium / High / Critical) and the main reason.\n' +
    '2. Which open port is the most dangerous and what specific attack it enables.\n' +
    '3. The single most important hardening action to take right now.\n\n' +
    'Be direct and technical. No markdown, no bullet points, plain paragraphs only.';

  fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model: 'claude-sonnet-4-6',
      max_tokens: 300,
      messages: [{ role: 'user', content: prompt }]
    })
  })
  .then(r => r.json())
  .then(data => {
    const text = data.content?.[0]?.text || 'Analysis unavailable.';
    showAIResult(text);
  })
  .catch(() => {
    showAIResult('AI analysis unavailable — check your internet connection or API key configuration.');
  });
}

function showAIResult(text) {
  document.getElementById('aiSpinner').style.display = 'none';
  document.getElementById('aiText').textContent = text;

  const word = (text.match(/\b(Critical|High|Medium|Low)\b/i) || ['Low'])[0].toLowerCase();
  const map = {
    critical: { w: '95%', c: '#f85149', label: 'Critical' },
    high:     { w: '72%', c: '#f85149', label: 'High' },
    medium:   { w: '48%', c: '#d29922', label: 'Medium' },
    low:      { w: '20%', c: '#3fb950', label: 'Low' },
  };
  const r = map[word] || map.low;
  document.getElementById('riskFill').style.width = r.w;
  document.getElementById('riskFill').style.background = r.c;
  document.getElementById('sRisk').textContent = r.label;

  buildPortTable();
  document.getElementById('askBtn').style.display = 'inline-block';
}

function buildPortTable() {
  const tbody = document.getElementById('portBody');
  tbody.innerHTML = '';
  if (!openPorts.length) return;
  openPorts.forEach(p => {
    const svc  = SERVICES[p] || 'unknown';
    const risk = RISK[p] || 'low';
    const note = NOTES[p] || 'Monitor for unusual traffic';
    const tr = document.createElement('tr');
    tr.innerHTML =
      '<td class="port">' + p + '</td>' +
      '<td>' + svc + '</td>' +
      '<td class="' + risk + '">' + risk.toUpperCase() + '</td>' +
      '<td style="color:#8b949e">' + note + '</td>';
    tbody.appendChild(tr);
  });
}

function openGitHub() {
  window.open('https://github.com/YOUR_USERNAME/cybersecurity-projects', '_blank');
}
