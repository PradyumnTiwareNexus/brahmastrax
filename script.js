/* ─────────────── CONFIG ─────────────── */
// If you self-host the backend (Replit deployment), set your URL here:
const AI_BACKEND_URL = ''; // e.g. 'https://brahmastrax.yourusername.repl.co'

/* ─────────────── MATRIX BACKGROUND ─────────────── */
(function initMatrix() {
  const canvas = document.getElementById('matrix-canvas');
  const ctx = canvas.getContext('2d');
  const chars = '01$#{}[]<>ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
  const fs = 14;
  let w, h, cols, drops;
  function resize() {
    w = canvas.width = window.innerWidth;
    h = canvas.height = window.innerHeight;
    const nc = Math.floor(w / fs);
    if (!drops || nc > cols) { drops = (drops || []).concat(Array(nc - (cols || 0)).fill(1)); }
    else { drops = drops.slice(0, nc); }
    cols = nc;
  }
  function draw() {
    ctx.fillStyle = 'rgba(2,4,8,0.05)';
    ctx.fillRect(0, 0, w, h);
    ctx.fillStyle = '#22d3a0';
    ctx.font = fs + 'px "JetBrains Mono",monospace';
    for (let i = 0; i < drops.length; i++) {
      ctx.fillText(chars[Math.floor(Math.random() * chars.length)], i * fs, drops[i] * fs);
      if (drops[i] * fs > h && Math.random() > 0.975) drops[i] = 0;
      drops[i]++;
    }
  }
  resize();
  window.addEventListener('resize', resize);
  setInterval(draw, 50);
})();

/* ─────────────── NAV / TABS ─────────────── */
const TABS = ['subdomain', 'dork', 'endpoint', 'ai'];
let activeTab = 'subdomain';

function setTab(id) {
  activeTab = id;
  document.querySelectorAll('.tab-btn').forEach(b => {
    const isActive = b.dataset.tab === id;
    b.classList.toggle('active', isActive);
    if (id === 'ai') b.classList.toggle('ai-tab', isActive);
    else b.classList.remove('ai-tab');
  });
  document.querySelectorAll('.tab-panel').forEach(p => {
    p.classList.toggle('active', p.id === 'tab-' + id);
  });
  document.querySelectorAll('.mobile-tab-btn').forEach(b => {
    const isActive = b.dataset.tab === id;
    b.classList.toggle('active', isActive);
    if (id === 'ai') b.classList.toggle('ai-tab', isActive);
    else b.classList.remove('ai-tab');
    if (isActive && id === 'ai') b.classList.add('ai-tab');
  });
  closeMobileMenu();
}

// Mobile menu
const mobileBtn = document.getElementById('mobile-menu-btn');
const mobileMenu = document.getElementById('mobile-menu');
function closeMobileMenu() { mobileMenu.classList.remove('open'); }
mobileBtn.addEventListener('click', () => mobileMenu.classList.toggle('open'));

// Wire up all tab buttons
document.querySelectorAll('[data-tab]').forEach(b => {
  b.addEventListener('click', () => setTab(b.dataset.tab));
});

/* ─────────────── TOAST ─────────────── */
const toast = document.getElementById('copied-toast');
function showToast(msg = 'Copied!') {
  toast.textContent = msg;
  toast.classList.add('show');
  setTimeout(() => toast.classList.remove('show'), 2000);
}

/* ─────────────── PROXY / SCANNER UTILS ─────────────── */
const PROXIES = [
  u => `https://corsproxy.io/?url=${encodeURIComponent(u)}`,
  u => `https://cors.eu.org/${u}`,
  u => `https://api.allorigins.win/raw?url=${encodeURIComponent(u)}`,
  u => `https://api.codetabs.com/v1/proxy?quest=${encodeURIComponent(u)}`,
  u => `https://thingproxy.freeboard.io/fetch/${u}`,
];

async function proxyFetch(url, ms = 13000, large = false) {
  const list = large ? [...PROXIES].reverse() : PROXIES;
  let last = new Error('All proxies failed');
  for (const make of list) {
    try {
      const r = await fetch(make(url), { signal: AbortSignal.timeout(ms) });
      if (r.ok) return r;
      last = new Error('HTTP ' + r.status);
    } catch (e) { last = e; }
  }
  throw last;
}

function isValidSub(raw, domain) {
  if (!raw) return false;
  const s = raw.trim().toLowerCase();
  if (s.includes('@') || s.includes('/') || s.includes(':') || s.startsWith('*')) return false;
  if (!/^[a-z0-9][a-z0-9.\-]*[a-z0-9]$/.test(s) && s !== domain) return false;
  if (s !== domain && !s.endsWith('.' + domain)) return false;
  if (s === domain) return false;
  if (s.split('.').some(l => l.length > 63)) return false;
  return true;
}

/* ─────────────── SUBDOMAIN SOURCES ─────────────── */
async function fetchHackerTarget(d) {
  try {
    const url = `https://api.hackertarget.com/hostsearch/?q=${d}`;
    let text;
    try { const r = await fetch(url, { signal: AbortSignal.timeout(13000) }); text = await r.text(); }
    catch { const r = await proxyFetch(url, 18000); text = await r.text(); }
    if (!text || text.includes('API count exceeded') || text.includes('API Key Required')) return [];
    if (text.startsWith('error') || text.startsWith('<')) return [];
    return text.trim().split('\n').filter(l => l.includes(','))
      .map(l => { const [s, ip] = l.split(','); return { subdomain: s.trim().toLowerCase(), ip: (ip || '').trim(), source: 'HackerTarget' }; })
      .filter(r => isValidSub(r.subdomain, d));
  } catch { return []; }
}

async function fetchURLScan(d) {
  try {
    const r = await proxyFetch(`https://urlscan.io/api/v1/search/?q=page.domain:${d}&size=100`);
    const data = await r.json();
    const seen = new Set(), out = [];
    for (const x of (data.results || [])) {
      const s = (x?.page?.domain || '').toLowerCase();
      if (s && isValidSub(s, d) && !seen.has(s)) { seen.add(s); out.push({ subdomain: s, ip: x?.page?.ip || '', source: 'URLScan.io' }); }
    }
    return out;
  } catch { return []; }
}

async function fetchCrtSh(d) {
  try {
    const r = await fetch(`https://crt.sh/?q=%.${d}&output=json`);
    const data = await r.json();
    const seen = new Set(), out = [];
    for (const e of data) {
      for (const n of (e.name_value || '').split('\n')) {
        const s = n.trim().replace(/^\*\./, '').toLowerCase();
        if (s && isValidSub(s, d) && !seen.has(s)) { seen.add(s); out.push({ subdomain: s, ip: '', source: 'crt.sh' }); }
      }
    }
    return out;
  } catch { return []; }
}

async function fetchJLDC(d) {
  try {
    let data = null;
    const url = `https://jldc.me/anubis/subdomains/${d}`;
    try { const r = await fetch(url, { signal: AbortSignal.timeout(13000) }); if (r.ok) data = await r.json(); } catch {}
    if (!data) { try { const r = await proxyFetch(url, 15000); data = await r.json(); } catch { return []; } }
    if (!Array.isArray(data)) return [];
    const seen = new Set(), out = [];
    for (const s of data) {
      const sub = (s || '').toLowerCase().trim();
      if (sub && isValidSub(sub, d) && !seen.has(sub)) { seen.add(sub); out.push({ subdomain: sub, ip: '', source: 'JLDC' }); }
    }
    return out;
  } catch { return []; }
}

async function fetchCertSpotter(d) {
  try {
    const r = await proxyFetch(`https://api.certspotter.com/v1/issuances?domain=${d}&include_subdomains=true&expand=dns_names`);
    const data = await r.json();
    if (!Array.isArray(data)) return [];
    const seen = new Set(), out = [];
    for (const c of data) {
      for (const n of (c.dns_names || [])) {
        const s = n.replace(/^\*\./, '').toLowerCase().trim();
        if (s && isValidSub(s, d) && !seen.has(s)) { seen.add(s); out.push({ subdomain: s, ip: '', source: 'CertSpotter' }); }
      }
    }
    return out;
  } catch { return []; }
}

async function fetchRapidDNS(d) {
  try {
    const r = await proxyFetch(`https://rapiddns.io/subdomain/${d}?full=1`);
    const html = await r.text();
    const seen = new Set(), out = [];
    for (const m of html.matchAll(/<td>([a-z0-9][a-z0-9.\-]*\.[a-z]{2,})<\/td>/gi)) {
      const s = m[1].toLowerCase();
      if (isValidSub(s, d) && !seen.has(s)) { seen.add(s); out.push({ subdomain: s, ip: '', source: 'RapidDNS' }); }
    }
    return out;
  } catch { return []; }
}

async function fetchDNSRepo(d) {
  try {
    const r = await proxyFetch(`https://dnsrepo.noc.org/?domain=${d}`);
    const html = await r.text();
    const seen = new Set(), out = [];
    for (const m of html.matchAll(/([a-z0-9][a-z0-9.\-]*\.[a-z]{2,})/gi)) {
      const s = m[1].toLowerCase();
      if (isValidSub(s, d) && !seen.has(s)) { seen.add(s); out.push({ subdomain: s, ip: '', source: 'DNSRepo' }); }
    }
    return out;
  } catch { return []; }
}

async function fetchWaybackSub(d) {
  try {
    const r = await proxyFetch(`https://web.archive.org/cdx/search/cdx?url=*.${d}/*&output=text&fl=original&collapse=urlkey&limit=15000`, 25000, true);
    const text = await r.text();
    const seen = new Set(), out = [];
    for (const line of text.trim().split('\n')) {
      try { const u = new URL(line.trim()); const h = u.hostname.toLowerCase(); if (isValidSub(h, d) && !seen.has(h)) { seen.add(h); out.push({ subdomain: h, ip: '', source: 'Wayback' }); } } catch {}
    }
    return out;
  } catch { return []; }
}

async function fetchGitHub(d) {
  try {
    const r = await proxyFetch(`https://api.github.com/search/code?q=%22${d}%22&per_page=100`);
    const data = await r.json();
    const seen = new Set(), out = [];
    const regex = new RegExp(`[a-z0-9][a-z0-9.\\-]*\\.${d.replace(/\./g, '\\.')}`, 'gi');
    for (const item of (data.items || [])) {
      const text = [item.html_url || '', item.name || '', item.path || '', item.repository?.full_name || ''].join(' ');
      for (const m of (text.match(regex) || [])) {
        const s = m.toLowerCase();
        if (isValidSub(s, d) && !seen.has(s)) { seen.add(s); out.push({ subdomain: s, ip: '', source: 'GitHub' }); }
      }
    }
    return out;
  } catch { return []; }
}

async function fetchShodan(d) {
  try {
    const r = await proxyFetch(`https://www.shodan.io/search?query=hostname%3A${d}&facets=domain`);
    const html = await r.text();
    const seen = new Set(), out = [];
    const regex = new RegExp(`[a-z0-9][a-z0-9.\\-]*\\.${d.replace(/\./g, '\\.')}`, 'gi');
    for (const m of (html.match(regex) || [])) {
      const s = m.toLowerCase();
      if (isValidSub(s, d) && !seen.has(s)) { seen.add(s); out.push({ subdomain: s, ip: '', source: 'Shodan' }); }
    }
    return out;
  } catch { return []; }
}

async function fetchCensys(d) {
  try {
    const r = await proxyFetch(`https://search.censys.io/certificates?q=parsed.names%3A${d}&per_page=100`);
    const html = await r.text();
    const seen = new Set(), out = [];
    const regex = new RegExp(`[a-z0-9][a-z0-9.\\-]*\\.${d.replace(/\./g, '\\.')}`, 'gi');
    for (const m of (html.match(regex) || [])) {
      const s = m.toLowerCase();
      if (isValidSub(s, d) && !seen.has(s)) { seen.add(s); out.push({ subdomain: s, ip: '', source: 'Censys' }); }
    }
    return out;
  } catch { return []; }
}

const SUBDOMAIN_SOURCES = [
  { id: 'hackertarget', name: 'HackerTarget', fn: fetchHackerTarget },
  { id: 'urlscan', name: 'URLScan.io', fn: fetchURLScan },
  { id: 'crtsh', name: 'crt.sh', fn: fetchCrtSh },
  { id: 'jldc', name: 'JLDC', fn: fetchJLDC },
  { id: 'certspotter', name: 'CertSpotter', fn: fetchCertSpotter },
  { id: 'rapiddns', name: 'RapidDNS', fn: fetchRapidDNS },
  { id: 'dnsrepo', name: 'DNSRepo', fn: fetchDNSRepo },
  { id: 'wayback', name: 'Wayback', fn: fetchWaybackSub },
  { id: 'github', name: 'GitHub', fn: fetchGitHub },
  { id: 'shodan', name: 'Shodan', fn: fetchShodan },
  { id: 'censys', name: 'Censys', fn: fetchCensys },
];

/* ─────────────── ENDPOINT SOURCES ─────────────── */
async function fetchWayback(d) {
  try {
    const r = await proxyFetch(`https://web.archive.org/cdx/search/cdx?url=*.${d}/*&output=json&fl=original,statuscode&collapse=urlkey&limit=3000`, 20000, true);
    const data = await r.json();
    if (!Array.isArray(data)) return [];
    const seen = new Set(), out = [];
    for (const row of data.slice(1)) {
      const url = (row[0] || '').trim();
      if (url && !seen.has(url)) { seen.add(url); out.push({ url, status: (row[1] || '').trim(), source: 'Wayback Machine' }); }
    }
    return out;
  } catch { return []; }
}

async function fetchCommonCrawl(d) {
  try {
    const idxR = await proxyFetch('https://index.commoncrawl.org/collinfo.json', 8000);
    const idx = await idxR.json();
    const latest = idx[0]?.cdx_api || 'https://index.commoncrawl.org/CC-MAIN-2024-10-index';
    const r = await proxyFetch(`${latest}?url=*.${d}/*&output=json&fl=url,status&limit=2000`, 20000, true);
    const text = await r.text();
    const seen = new Set(), out = [];
    for (const line of text.trim().split('\n')) {
      try { const obj = JSON.parse(line); const url = obj.url?.trim(); if (url && !seen.has(url)) { seen.add(url); out.push({ url, status: obj.status || '', source: 'Common Crawl' }); } } catch {}
    }
    return out;
  } catch { return []; }
}

async function fetchOTX(d) {
  try {
    const r = await proxyFetch(`https://otx.alienvault.com/api/v1/indicators/domain/${d}/url_list?limit=500`);
    const data = await r.json();
    const seen = new Set(), out = [];
    for (const x of (data.url_list || [])) {
      const url = x.url?.trim();
      if (url && !seen.has(url)) { seen.add(url); out.push({ url, status: '', source: 'AlienVault OTX' }); }
    }
    return out;
  } catch { return []; }
}

async function fetchURLScanEp(d) {
  try {
    const r = await proxyFetch(`https://urlscan.io/api/v1/search/?q=page.domain:${d}&size=100`);
    const data = await r.json();
    const seen = new Set(), out = [];
    for (const x of (data.results || [])) {
      const url = x?.page?.url?.trim();
      if (url && !seen.has(url)) { seen.add(url); out.push({ url, status: String(x?.page?.status || ''), source: 'URLScan.io' }); }
    }
    return out;
  } catch { return []; }
}

const ENDPOINT_SOURCES = [
  { id: 'wayback', name: 'Wayback Machine', fn: fetchWayback },
  { id: 'commoncrawl', name: 'Common Crawl', fn: fetchCommonCrawl },
  { id: 'otx', name: 'AlienVault OTX', fn: fetchOTX },
  { id: 'urlscan', name: 'URLScan.io', fn: fetchURLScanEp },
];

/* ─────────────── DORK CATEGORIES ─────────────── */
const DORK_CATEGORIES = [
  { id:'sensitive', title:'Sensitive Files & Data', color:'text-red-400', style:'color:#f87171;border-color:rgba(248,113,113,.3);background:rgba(248,113,113,.1)', dorks:[
    {label:'Config / ENV files', query:'site:{domain} ext:env | ext:config | ext:cfg | ext:ini'},
    {label:'SQL dump files', query:'site:{domain} ext:sql | ext:sql.gz | ext:db'},
    {label:'Backup files', query:'site:{domain} ext:bak | ext:backup | ext:old | ext:orig'},
    {label:'Log files', query:'site:{domain} ext:log'},
    {label:'Password files', query:'site:{domain} intitle:"index of" "passwd" | "password"'},
    {label:'Private keys', query:'site:{domain} ext:pem | ext:key | ext:ppk'},
    {label:'Database credential files', query:'site:{domain} "DB_PASSWORD" | "DB_USER" | "DATABASE_URL"'},
    {label:'WordPress config', query:'site:{domain} inurl:wp-config.php | inurl:wp-config.php.bak'},
    {label:'Secrets in YAML', query:'site:{domain} ext:yaml | ext:yml "password:" | "secret:" | "token:"'},
    {label:'Credentials in JSON', query:'site:{domain} ext:json "password" | "secret" | "api_key" | "access_token"'},
  ]},
  { id:'login', title:'Admin & Login Panels', style:'color:#c084fc;border-color:rgba(192,132,252,.3);background:rgba(192,132,252,.1)', dorks:[
    {label:'Admin panels', query:'site:{domain} inurl:admin | inurl:administrator | inurl:wp-admin'},
    {label:'Login pages', query:'site:{domain} inurl:login | inurl:signin | inurl:auth'},
    {label:'Dashboard pages', query:'site:{domain} inurl:dashboard | inurl:panel | inurl:control'},
    {label:'Portal login', query:'site:{domain} inurl:portal | inurl:sso | inurl:idp'},
    {label:'Jenkins login', query:'site:{domain} inurl:jenkins | inurl:/j_acegi_security_check'},
    {label:'Grafana login', query:'site:{domain} inurl:grafana | inurl:grafana/login'},
    {label:'Bitbucket / Jira', query:'site:{domain} inurl:jira | inurl:bitbucket | inurl:confluence/login'},
  ]},
  { id:'api', title:'APIs & Endpoints', style:'color:#22d3ee;border-color:rgba(34,211,238,.3);background:rgba(34,211,238,.1)', dorks:[
    {label:'API endpoints', query:'site:{domain} inurl:/api/ | inurl:/v1/ | inurl:/v2/ | inurl:/rest/'},
    {label:'GraphQL', query:'site:{domain} inurl:graphql | inurl:graphiql'},
    {label:'Swagger UI', query:'site:{domain} inurl:swagger | inurl:api-docs | inurl:openapi'},
    {label:'API keys in JS', query:'site:{domain} ext:js "apiKey" | "api_key" | "secret"'},
    {label:'Exposed endpoints', query:'site:{domain} intitle:"index of" "/api"'},
    {label:'Postman collections', query:'site:{domain} ext:json "postman_collection"'},
    {label:'API tokens in URL', query:'site:{domain} inurl:?token= | inurl:?api_key= | inurl:?access_token='},
  ]},
  { id:'database', title:'Database / SQL', style:'color:#60a5fa;border-color:rgba(96,165,250,.3);background:rgba(96,165,250,.1)', dorks:[
    {label:'SQL Files', query:'site:{domain} ext:sql | ext:db | ext:sqlite'},
    {label:'Database Config', query:'site:{domain} ext:inc | ext:cfg "db" | "database"'},
    {label:'phpMyAdmin', query:'site:{domain} inurl:phpmyadmin'},
    {label:'Connection strings', query:'site:{domain} "connectionString" | "connection_string" | "connstr"'},
  ]},
  { id:'backup', title:'Backup Files', style:'color:#fbbf24;border-color:rgba(251,191,36,.3);background:rgba(251,191,36,.1)', dorks:[
    {label:'Common backups', query:'site:{domain} ext:bak | ext:backup | ext:old | ext:orig'},
    {label:'Archive files', query:'site:{domain} ext:tar.gz | ext:zip | ext:rar | ext:7z'},
    {label:'Copy files', query:'site:{domain} ext:~ | ext:copy'},
  ]},
  { id:'errors', title:'Error Pages', style:'color:#fb7185;border-color:rgba(251,113,133,.3);background:rgba(251,113,133,.1)', dorks:[
    {label:'SQL Errors', query:'site:{domain} "syntax error in" | "mysql_fetch"'},
    {label:'Stack traces', query:'site:{domain} "Stack trace:" | "Exception in"'},
    {label:'Debug info', query:'site:{domain} "DEBUG" | "Traceback"'},
  ]},
  { id:'exposed', title:'Directory Listing', style:'color:#facc15;border-color:rgba(250,204,21,.3);background:rgba(250,204,21,.1)', dorks:[
    {label:'Index of /', query:'site:{domain} intitle:"index of /"'},
    {label:'Git exposed', query:'site:{domain} inurl:/.git'},
    {label:'.htaccess exposed', query:'site:{domain} inurl:.htaccess | inurl:.htpasswd'},
    {label:'Exposed uploads', query:'site:{domain} intitle:"index of" "uploads" | "files"'},
    {label:'DS_Store files', query:'site:{domain} inurl:.DS_Store'},
  ]},
  { id:'javascript', title:'JavaScript Files', style:'color:#34d399;border-color:rgba(52,211,153,.3);background:rgba(52,211,153,.1)', dorks:[
    {label:'JS Sourcemaps', query:'site:{domain} ext:map'},
    {label:'Bundle files', query:'site:{domain} inurl:bundle.js | inurl:main.js | inurl:app.js'},
    {label:'Config JS', query:'site:{domain} inurl:config.js | inurl:env.js'},
  ]},
  { id:'mobile', title:'Mobile/API Endpoints', style:'color:#f472b6;border-color:rgba(244,114,182,.3);background:rgba(244,114,182,.1)', dorks:[
    {label:'Mobile APIs', query:'site:{domain} inurl:/mobile/api | inurl:/app/api | inurl:/ios/ | inurl:/android/'},
    {label:'APK files', query:'site:{domain} ext:apk | ext:ipa'},
    {label:'Mobile configs', query:'site:{domain} "firebase" | "app-ads.txt" | "apple-app-site-association"'},
  ]},
  { id:'cloud', title:'Cloud Storage', style:'color:#38bdf8;border-color:rgba(56,189,248,.3);background:rgba(56,189,248,.1)', dorks:[
    {label:'S3 Buckets', query:'site:s3.amazonaws.com "{domain}"'},
    {label:'Google Drive', query:'site:drive.google.com "{domain}"'},
    {label:'Azure Storage', query:'site:storage.googleapis.com "{domain}"'},
  ]},
  { id:'dev', title:'Dev/Staging', style:'color:#e879f9;border-color:rgba(232,121,249,.3);background:rgba(232,121,249,.1)', dorks:[
    {label:'Dev subdomains', query:'site:dev.{domain} | site:staging.{domain} | site:test.{domain}'},
    {label:'Internal subdomains', query:'site:internal.{domain} | site:intranet.{domain} | site:vpn.{domain}'},
    {label:'Beta subdomains', query:'site:beta.{domain} | site:alpha.{domain} | site:preview.{domain}'},
  ]},
  { id:'wordpress', title:'WordPress', style:'color:#818cf8;border-color:rgba(129,140,248,.3);background:rgba(129,140,248,.1)', dorks:[
    {label:'WP Admin', query:'site:{domain} inurl:wp-admin'},
    {label:'WP Content', query:'site:{domain} inurl:wp-content/uploads'},
    {label:'WP Config', query:'site:{domain} inurl:wp-config'},
  ]},
  { id:'jenkins', title:'Jenkins/CI', style:'color:#fb923c;border-color:rgba(251,146,60,.3);background:rgba(251,146,60,.1)', dorks:[
    {label:'CI subdomains', query:'site:jenkins.{domain} | site:gitlab.{domain} | site:ci.{domain}'},
    {label:'Travis CI', query:'site:{domain} inurl:.travis.yml'},
    {label:'Circle CI', query:'site:{domain} inurl:circleci'},
  ]},
  { id:'email', title:'Email/SMTP', style:'color:#a78bfa;border-color:rgba(167,139,250,.3);background:rgba(167,139,250,.1)', dorks:[
    {label:'Mail subdomains', query:'site:mail.{domain} | site:smtp.{domain} | site:webmail.{domain}'},
    {label:'Webmail interfaces', query:'site:{domain} inurl:webmail | inurl:roundcube | inurl:horde'},
  ]},
  { id:'upload', title:'File Upload', style:'color:#a3e635;border-color:rgba(163,230,53,.3);background:rgba(163,230,53,.1)', dorks:[
    {label:'Upload paths', query:'site:{domain} inurl:upload | inurl:up | inurl:file_upload'},
    {label:'File managers', query:'site:{domain} inurl:elfinder | inurl:ckeditor'},
  ]},
  { id:'auth', title:'Auth Bypass', style:'color:#f43f5e;border-color:rgba(244,63,94,.3);background:rgba(244,63,94,.1)', dorks:[
    {label:'Reset password', query:'site:{domain} inurl:reset | inurl:recover | inurl:forgot'},
    {label:'OTP / MFA', query:'site:{domain} inurl:2fa | inurl:mfa | inurl:totp | inurl:otp'},
  ]},
  { id:'ssrf', title:'SSRF', style:'color:#ef4444;border-color:rgba(239,68,68,.3);background:rgba(239,68,68,.1)', dorks:[
    {label:'URL parameters', query:'site:{domain} inurl:url= | inurl:target= | inurl:dest='},
    {label:'Fetch/Proxy paths', query:'site:{domain} inurl:fetch= | inurl:proxy= | inurl:redirect='},
  ]},
  { id:'xss', title:'XSS', style:'color:#f59e0b;border-color:rgba(245,158,11,.3);background:rgba(245,158,11,.1)', dorks:[
    {label:'Search parameters', query:'site:{domain} inurl:q= | inurl:search= | inurl:query='},
    {label:'Reflective params', query:'site:{domain} inurl:name= | inurl:id= | inurl:keyword='},
  ]},
  { id:'redirect', title:'Open Redirect', style:'color:#06b6d4;border-color:rgba(6,182,212,.3);background:rgba(6,182,212,.1)', dorks:[
    {label:'Redirect parameters', query:'site:{domain} inurl:next= | inurl:return_to= | inurl:redirect_uri='},
    {label:'Continue paths', query:'site:{domain} inurl:continue= | inurl:go='},
  ]},
  { id:'takeover', title:'Subdomain Takeover', style:'color:#a855f7;border-color:rgba(168,85,247,.3);background:rgba(168,85,247,.1)', dorks:[
    {label:'Not found errors', query:'site:*.{domain} "404 Not Found" | "No such app"'},
    {label:'Heroku/GitHub', query:'site:*.{domain} "There is no app configured at that hostname" | "GitHub Pages"'},
  ]},
];

/* ─────────────── SUBDOMAIN TAB ─────────────── */
(function initSubdomainTab() {
  const activeSubs = new Set(SUBDOMAIN_SOURCES.map(s => s.id));
  const sourceStats = {};
  let results = [], scanning = false, filterVal = '';
  SUBDOMAIN_SOURCES.forEach(s => { sourceStats[s.id] = { count: 0, status: 'idle' }; });

  const container = document.getElementById('tab-subdomain');
  const domainInput = container.querySelector('#sub-domain-input');
  const scanBtn = container.querySelector('#sub-scan-btn');
  const sourceTogglesEl = container.querySelector('#sub-sources');
  const resultsArea = container.querySelector('#sub-results-area');
  const filterInput = container.querySelector('#sub-filter');
  const copyBtn = container.querySelector('#sub-copy');
  const exportBtn = container.querySelector('#sub-export');
  const statSubs = container.querySelector('#stat-subs');
  const statResolved = container.querySelector('#stat-resolved');
  const statIps = container.querySelector('#stat-ips');
  const statSources = container.querySelector('#stat-sources');
  const statsGrid = container.querySelector('#sub-stats-grid');
  const progressWrap = container.querySelector('#sub-progress-wrap');
  const progressFill = container.querySelector('#sub-progress-fill');
  const progressPct = container.querySelector('#sub-progress-pct');
  const scanSources = container.querySelector('#sub-scan-sources');

  // Build source toggles
  SUBDOMAIN_SOURCES.forEach(s => {
    const btn = document.createElement('button');
    btn.className = 'src-btn active';
    btn.dataset.id = s.id;
    btn.innerHTML = `<span class="src-dot"></span>${s.name}`;
    btn.addEventListener('click', () => {
      if (scanning) return;
      if (activeSubs.has(s.id)) activeSubs.delete(s.id);
      else activeSubs.add(s.id);
      btn.classList.toggle('active', activeSubs.has(s.id));
      updateSourceDot(btn, activeSubs.has(s.id));
    });
    sourceTogglesEl.appendChild(btn);
  });

  function updateSourceDot(btn, active) {
    btn.querySelector('.src-dot').style.background = active ? 'var(--emerald)' : '#334155';
    btn.querySelector('.src-dot').style.boxShadow = active ? '0 0 8px var(--emerald)' : 'none';
  }

  function updateScanSourceDots() {
    if (!scanSources) return;
    scanSources.innerHTML = '';
    SUBDOMAIN_SOURCES.filter(s => activeSubs.has(s.id)).forEach(s => {
      const st = sourceStats[s.id];
      const el = document.createElement('div');
      el.className = 'scan-src';
      const dotClass = st.status === 'loading' ? 'dot-loading' : st.status === 'done' ? 'dot-done' : st.status === 'error' ? 'dot-error' : 'dot-idle';
      el.innerHTML = `<span class="dot ${dotClass}"></span>${s.name}`;
      scanSources.appendChild(el);
    });
  }

  function renderTable() {
    const filtered = results.filter(r =>
      r.subdomain.includes(filterVal.toLowerCase()) ||
      (r.ip && r.ip.includes(filterVal)) ||
      r.source.toLowerCase().includes(filterVal.toLowerCase())
    );
    const tbody = resultsArea.querySelector('tbody');
    if (filtered.length === 0) {
      tbody.innerHTML = `<tr><td colspan="4" class="empty-row">${scanning ? 'Awaiting results...' : 'No results found.'}</td></tr>`;
      return;
    }
    tbody.innerHTML = filtered.map((r, i) => `
      <tr>
        <td class="td-num">${i + 1}</td>
        <td class="td-sub"><a href="http://${r.subdomain}" target="_blank" rel="noreferrer">${r.subdomain}</a></td>
        <td class="td-ip">${r.ip ? `<span>${r.ip}</span>` : '-'}</td>
        <td class="td-source">${r.source}</td>
      </tr>
    `).join('');
  }

  function updateStats() {
    const completed = Object.values(sourceStats).filter(s => s.status === 'done' || s.status === 'error').length;
    const active = activeSubs.size;
    const pct = active === 0 ? 0 : (completed / active) * 100;
    const resolvedCount = results.filter(r => r.ip).length;
    const uniqueIps = new Set(results.map(r => r.ip).filter(Boolean)).size;
    statSubs.textContent = results.length;
    statResolved.textContent = resolvedCount;
    statIps.textContent = uniqueIps;
    statSources.textContent = `${completed}/${active}`;
    progressFill.style.width = pct + '%';
    progressPct.textContent = Math.round(pct) + '%';
    updateScanSourceDots();
  }

  scanBtn.addEventListener('click', async () => {
    let domain = domainInput.value.trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '').trim();
    if (!domain) return;
    domainInput.value = domain;
    scanning = true;
    results = [];
    SUBDOMAIN_SOURCES.forEach(s => { sourceStats[s.id] = { count: 0, status: activeSubs.has(s.id) ? 'loading' : 'idle' }; });
    scanBtn.disabled = true;
    scanBtn.innerHTML = '<span class="spinner"></span>SCANNING';
    statsGrid.style.display = 'grid';
    progressWrap.style.display = 'block';
    resultsArea.style.display = 'block';
    renderTable();
    updateStats();

    const promises = SUBDOMAIN_SOURCES.filter(s => activeSubs.has(s.id)).map(async source => {
      try {
        const res = await source.fn(domain);
        sourceStats[source.id] = { count: res.length, status: 'done' };
        const btn = sourceTogglesEl.querySelector(`[data-id="${source.id}"]`);
        if (btn) {
          const countEl = btn.querySelector('.src-count') || document.createElement('span');
          if (res.length > 0) {
            countEl.className = 'src-count';
            countEl.textContent = res.length;
            if (!btn.querySelector('.src-count')) btn.appendChild(countEl);
          }
        }
        updateStats();
        return res;
      } catch {
        sourceStats[source.id] = { count: 0, status: 'error' };
        updateStats();
        return [];
      }
    });

    const settled = await Promise.allSettled(promises);
    const allResults = settled.filter(r => r.status === 'fulfilled').flatMap(r => r.value);
    const uniqueMap = new Map();
    allResults.forEach(r => {
      if (!uniqueMap.has(r.subdomain)) uniqueMap.set(r.subdomain, { ...r, sources: new Set([r.source]) });
      else { const e = uniqueMap.get(r.subdomain); e.sources.add(r.source); if (!e.ip && r.ip) e.ip = r.ip; }
    });
    results = Array.from(uniqueMap.values()).map(r => ({ ...r, source: Array.from(r.sources).join(', ') }));

    scanning = false;
    progressWrap.style.display = 'none';
    scanBtn.disabled = false;
    scanBtn.textContent = 'LAUNCH SCAN';
    updateStats();
    renderTable();
  });

  domainInput.addEventListener('keydown', e => { if (e.key === 'Enter') scanBtn.click(); });
  filterInput.addEventListener('input', e => { filterVal = e.target.value; renderTable(); });
  copyBtn.addEventListener('click', () => { navigator.clipboard.writeText(results.map(r => r.subdomain).join('\n')); showToast('Copied!'); });
  exportBtn.addEventListener('click', () => {
    const blob = new Blob([results.map(r => r.subdomain).join('\n')], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = `subdomains_${domainInput.value}.txt`; a.click();
    URL.revokeObjectURL(url);
  });
})();

/* ─────────────── ENDPOINT TAB ─────────────── */
(function initEndpointTab() {
  const activeSubs = new Set(ENDPOINT_SOURCES.map(s => s.id));
  const sourceStats = {};
  let results = [], scanning = false, filterVal = '';
  ENDPOINT_SOURCES.forEach(s => { sourceStats[s.id] = { count: 0, status: 'idle' }; });

  const container = document.getElementById('tab-endpoint');
  const domainInput = container.querySelector('#ep-domain-input');
  const scanBtn = container.querySelector('#ep-scan-btn');
  const sourceTogglesEl = container.querySelector('#ep-sources');
  const resultsArea = container.querySelector('#ep-results-area');
  const filterInput = container.querySelector('#ep-filter');
  const copyBtn = container.querySelector('#ep-copy');
  const copyPathsBtn = container.querySelector('#ep-copy-paths');
  const exportBtn = container.querySelector('#ep-export');
  const statEps = container.querySelector('#stat-eps');
  const statSrcHit = container.querySelector('#stat-src-hit');
  const statTarget = container.querySelector('#stat-target');
  const statsGrid = container.querySelector('#ep-stats-grid');
  const progressWrap = container.querySelector('#ep-progress-wrap');
  const progressFill = container.querySelector('#ep-progress-fill');
  const progressPct = container.querySelector('#ep-progress-pct');

  ENDPOINT_SOURCES.forEach(s => {
    const btn = document.createElement('button');
    btn.className = 'src-btn active';
    btn.dataset.id = s.id;
    btn.innerHTML = `<span class="src-dot"></span>${s.name}`;
    btn.addEventListener('click', () => {
      if (scanning) return;
      if (activeSubs.has(s.id)) activeSubs.delete(s.id);
      else activeSubs.add(s.id);
      btn.classList.toggle('active', activeSubs.has(s.id));
    });
    sourceTogglesEl.appendChild(btn);
  });

  function statusClass(st) {
    if (!st) return '';
    if (st.startsWith('2')) return 's2xx';
    if (st.startsWith('3')) return 's3xx';
    if (st.startsWith('4')) return 's4xx';
    if (st.startsWith('5')) return 's5xx';
    return '';
  }

  function renderTable() {
    const filtered = results.filter(r =>
      r.url.toLowerCase().includes(filterVal.toLowerCase()) ||
      (r.status && r.status.includes(filterVal)) ||
      r.source.toLowerCase().includes(filterVal.toLowerCase())
    );
    const tbody = resultsArea.querySelector('tbody');
    if (filtered.length === 0) {
      tbody.innerHTML = `<tr><td colspan="4" class="empty-row">${scanning ? 'Awaiting results...' : 'No results found.'}</td></tr>`;
      return;
    }
    tbody.innerHTML = filtered.map((r, i) => `
      <tr>
        <td class="td-num">${i + 1}</td>
        <td class="td-url" style="max-width:400px;word-break:break-all"><a href="${r.url}" target="_blank" rel="noreferrer">${r.url}</a></td>
        <td>${r.status ? `<span class="status-badge ${statusClass(r.status)}">${r.status}</span>` : '-'}</td>
        <td class="td-source">${r.source}</td>
      </tr>
    `).join('');
  }

  scanBtn.addEventListener('click', async () => {
    let domain = domainInput.value.trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '').trim();
    if (!domain) return;
    domainInput.value = domain;
    scanning = true;
    results = [];
    ENDPOINT_SOURCES.forEach(s => { sourceStats[s.id] = { count: 0, status: activeSubs.has(s.id) ? 'loading' : 'idle' }; });
    scanBtn.disabled = true;
    scanBtn.innerHTML = '<span class="spinner"></span>SCANNING';
    statsGrid.style.display = 'grid';
    progressWrap.style.display = 'block';
    resultsArea.style.display = 'block';
    statTarget.textContent = domain;
    renderTable();

    const promises = ENDPOINT_SOURCES.filter(s => activeSubs.has(s.id)).map(async source => {
      try {
        const res = await source.fn(domain);
        sourceStats[source.id] = { count: res.length, status: 'done' };
        const completed = Object.values(sourceStats).filter(s => s.status === 'done' || s.status === 'error').length;
        const pct = (completed / activeSubs.size) * 100;
        progressFill.style.width = pct + '%';
        progressPct.textContent = Math.round(pct) + '%';
        statSrcHit.textContent = `${completed}/${activeSubs.size}`;
        return res;
      } catch {
        sourceStats[source.id] = { count: 0, status: 'error' };
        return [];
      }
    });

    const settled = await Promise.allSettled(promises);
    const allResults = settled.filter(r => r.status === 'fulfilled').flatMap(r => r.value);
    const uniqueMap = new Map();
    allResults.forEach(r => {
      if (!uniqueMap.has(r.url)) uniqueMap.set(r.url, { ...r, sources: new Set([r.source]) });
      else { const e = uniqueMap.get(r.url); e.sources.add(r.source); if (!e.status && r.status) e.status = r.status; }
    });
    results = Array.from(uniqueMap.values()).map(r => ({ ...r, source: Array.from(r.sources).join(', ') }));

    scanning = false;
    progressWrap.style.display = 'none';
    scanBtn.disabled = false;
    scanBtn.textContent = 'LAUNCH SCAN';
    statEps.textContent = results.length;
    const completed = Object.values(sourceStats).filter(s => s.status === 'done' || s.status === 'error').length;
    statSrcHit.textContent = `${completed}/${activeSubs.size}`;
    renderTable();
  });

  domainInput.addEventListener('keydown', e => { if (e.key === 'Enter') scanBtn.click(); });
  filterInput.addEventListener('input', e => { filterVal = e.target.value; renderTable(); });
  copyBtn.addEventListener('click', () => { navigator.clipboard.writeText(results.map(r => r.url).join('\n')); showToast('Copied!'); });
  copyPathsBtn.addEventListener('click', () => {
    const paths = new Set(results.map(r => { try { return new URL(r.url).pathname; } catch { return ''; } }).filter(p => p && p !== '/'));
    navigator.clipboard.writeText(Array.from(paths).join('\n'));
    showToast('API Paths Copied!');
  });
  exportBtn.addEventListener('click', () => {
    const blob = new Blob([results.map(r => r.url).join('\n')], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = `endpoints_${domainInput.value}.txt`; a.click();
    URL.revokeObjectURL(url);
  });
})();

/* ─────────────── DORK TAB ─────────────── */
(function initDorkTab() {
  const container = document.getElementById('tab-dork');
  const domainInput = container.querySelector('#dork-domain-input');
  const genBtn = container.querySelector('#dork-gen-btn');
  const dorkGrid = container.querySelector('#dork-grid');
  let targetDomain = '';

  genBtn.addEventListener('click', () => {
    const d = domainInput.value.trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '').trim();
    if (!d) return;
    targetDomain = d;
    renderDorks();
  });
  domainInput.addEventListener('keydown', e => { if (e.key === 'Enter') genBtn.click(); });

  function renderDorks() {
    dorkGrid.innerHTML = '';
    dorkGrid.style.display = 'grid';
    DORK_CATEGORIES.forEach(cat => {
      const card = document.createElement('div');
      card.className = 'dork-card';
      const trigger = document.createElement('button');
      trigger.className = 'dork-trigger';
      trigger.innerHTML = `
        <span class="dork-badge" style="${cat.style}">${cat.id}</span>
        <span class="dork-cat-title">${cat.title}</span>
        <span class="dork-cat-count">(${cat.dorks.length})</span>
        <span class="dork-chevron">▼</span>
      `;
      const body = document.createElement('div');
      body.className = 'dork-body';
      cat.dorks.forEach(dork => {
        const q = dork.query.replace(/\{domain\}/g, targetDomain);
        const googleUrl = `https://www.google.com/search?q=${encodeURIComponent(q)}`;
        const item = document.createElement('div');
        item.className = 'dork-item';
        item.innerHTML = `
          <div class="dork-item-header">
            <span class="dork-label">${dork.label}</span>
            <div class="dork-actions">
              <button class="dork-btn copy-dork" title="Copy">📋</button>
              <a class="dork-btn open-btn" href="${googleUrl}" target="_blank" rel="noreferrer" title="Open in Google">🔗</a>
            </div>
          </div>
          <code class="dork-query">${q}</code>
        `;
        item.querySelector('.copy-dork').addEventListener('click', () => { navigator.clipboard.writeText(q); showToast('Query Copied!'); });
        body.appendChild(item);
      });
      trigger.addEventListener('click', () => {
        const open = body.classList.toggle('open');
        trigger.classList.toggle('open', open);
      });
      card.appendChild(trigger);
      card.appendChild(body);
      dorkGrid.appendChild(card);
    });
  }
})();

/* ─────────────── AI TAB ─────────────── */
(function initAITab() {
  const container = document.getElementById('tab-ai');
  const messagesEl = container.querySelector('#ai-messages');
  const input = container.querySelector('#ai-input');
  const sendBtn = container.querySelector('#ai-send-btn');
  const newSessionBtn = container.querySelector('#ai-new-session');
  const aiNotice = container.querySelector('#ai-notice');

  // Check if backend is available
  const backendUrl = AI_BACKEND_URL.replace(/\/$/, '');
  let conversationId = null;
  let streaming = false;
  const messageHistory = [];

  if (!backendUrl) {
    if (aiNotice) aiNotice.style.display = 'block';
    input.disabled = true;
    sendBtn.disabled = true;
    return;
  }
  if (aiNotice) aiNotice.style.display = 'none';

  function addMessage(role, content, streaming = false) {
    const existing = document.getElementById('ai-empty-state');
    if (existing) existing.remove();
    const div = document.createElement('div');
    div.className = `msg ${role}`;
    div.id = streaming ? 'streaming-msg' : '';
    div.innerHTML = `
      ${role === 'assistant' ? '<div class="msg-avatar avatar-ai">🤖</div>' : ''}
      <div class="msg-bubble ${role === 'assistant' ? 'bubble-ai' : 'bubble-user'}">${content}${streaming ? '<span class="ai-cursor"></span>' : ''}</div>
      ${role === 'user' ? '<div class="msg-avatar avatar-user">👤</div>' : ''}
    `;
    messagesEl.appendChild(div);
    messagesEl.scrollTop = messagesEl.scrollHeight;
    return div;
  }

  async function send() {
    const content = input.value.trim();
    if (!content || streaming) return;
    input.value = '';
    addMessage('user', content);

    // Create conversation if needed
    if (!conversationId) {
      try {
        const r = await fetch(`${backendUrl}/api/openai/conversations`, {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ title: 'Recon Session' })
        });
        const data = await r.json();
        conversationId = data.id;
      } catch { addMessage('assistant', 'Error: Could not connect to AI backend.'); return; }
    }

    streaming = true;
    sendBtn.disabled = true;
    let streamDiv = null;
    let streamContent = '';
    streamDiv = addMessage('assistant', '', true);
    const bubble = streamDiv.querySelector('.msg-bubble');

    try {
      const res = await fetch(`${backendUrl}/api/openai/conversations/${conversationId}/messages`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content })
      });
      if (!res.ok) throw new Error('Failed');
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let done = false;
      while (!done) {
        const { value, done: rd } = await reader.read();
        done = rd;
        if (value) {
          const chunk = decoder.decode(value, { stream: true });
          for (const line of chunk.split('\n')) {
            if (line.startsWith('data: ')) {
              try {
                const data = JSON.parse(line.slice(6));
                if (data.content) { streamContent += data.content; bubble.innerHTML = streamContent + '<span class="ai-cursor"></span>'; messagesEl.scrollTop = messagesEl.scrollHeight; }
                if (data.done) done = true;
              } catch {}
            }
          }
        }
      }
      bubble.innerHTML = streamContent;
    } catch (e) {
      bubble.innerHTML = 'Error: Failed to get AI response.';
    } finally {
      streaming = false;
      sendBtn.disabled = false;
      messagesEl.scrollTop = messagesEl.scrollHeight;
    }
  }

  sendBtn.addEventListener('click', send);
  input.addEventListener('keydown', e => { if (e.key === 'Enter') send(); });
  newSessionBtn.addEventListener('click', () => {
    conversationId = null;
    messagesEl.innerHTML = `<div class="ai-empty" id="ai-empty-state"><div class="ai-empty-icon">🤖</div><p>System initialized. Awaiting queries.</p></div>`;
  });
})();
