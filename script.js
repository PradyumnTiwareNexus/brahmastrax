/* =========================================================
   BrahmastraX — Advanced Recon & Dorking Platform
   created by pradyumntiwarenexus
   Standalone Vanilla JS — no build tools required
   ========================================================= */

/* ── CORS Proxies ── */
const PROXY_LIST = [
  u => `https://corsproxy.io/?url=${encodeURIComponent(u)}`,
  u => `https://cors.eu.org/${u}`,
  u => `https://api.allorigins.win/raw?url=${encodeURIComponent(u)}`,
  u => `https://api.codetabs.com/v1/proxy?quest=${encodeURIComponent(u)}`,
  u => `https://thingproxy.freeboard.io/fetch/${u}`,
];
const PROXY_LIST_LARGE = [
  u => `https://cors.eu.org/${u}`,
  u => `https://api.allorigins.win/raw?url=${encodeURIComponent(u)}`,
  u => `https://api.codetabs.com/v1/proxy?quest=${encodeURIComponent(u)}`,
  u => `https://thingproxy.freeboard.io/fetch/${u}`,
  u => `https://corsproxy.io/?url=${encodeURIComponent(u)}`,
];

async function proxyFetch(targetUrl, timeoutMs = 13000, large = false) {
  const list = large ? PROXY_LIST_LARGE : PROXY_LIST;
  let lastErr = new Error("All proxies failed");
  for (const make of list) {
    try {
      const res = await fetch(make(targetUrl), { signal: AbortSignal.timeout(timeoutMs) });
      if (res.ok) return res;
      lastErr = new Error("HTTP " + res.status);
    } catch (e) { lastErr = e; }
  }
  throw lastErr;
}

/* ── Validator ── */
function isValidSubdomain(raw, domain) {
  if (!raw) return false;
  const s = raw.trim().toLowerCase();
  if (s.includes("@") || s.includes("/") || s.includes(":") || s.startsWith("*")) return false;
  if (!/^[a-z0-9][a-z0-9.\-]*[a-z0-9]$/.test(s) && s !== domain) return false;
  if (s !== domain && !s.endsWith("." + domain)) return false;
  if (s === domain) return false;
  if (s.split(".").some(l => l.length > 63)) return false;
  return true;
}

/* ── Subdomain Fetchers ── */
async function fetchHackerTarget(domain, timeoutMs = 13000) {
  const htUrl = `https://api.hackertarget.com/hostsearch/?q=${domain}`;
  let text;
  try {
    const res = await fetch(htUrl, { signal: AbortSignal.timeout(timeoutMs) });
    text = await res.text();
  } catch {
    try { const r2 = await proxyFetch(htUrl, timeoutMs + 5000); text = await r2.text(); }
    catch { return []; }
  }
  if (!text) return [];
  if (text.includes("API count exceeded") || text.includes("API Key Required") || text.includes("Increase Quota")) {
    const err = new Error("quota"); err.quota = true; throw err;
  }
  if (text.startsWith("error") || text.startsWith("<") || !text.includes(",")) return [];
  return text.trim().split("\n").filter(l => l.includes(","))
    .map(l => { const [sub, ip] = l.split(","); return { subdomain: sub.trim().toLowerCase(), ip: (ip || "").trim(), source: "hackertarget" }; })
    .filter(r => isValidSubdomain(r.subdomain, domain));
}

async function fetchURLScan(domain, timeoutMs = 13000) {
  try {
    const res = await proxyFetch(`https://urlscan.io/api/v1/search/?q=page.domain:${domain}&size=100`, timeoutMs);
    let data; try { data = await res.json(); } catch { return []; }
    const seen = new Set(); const out = [];
    for (const r of (data.results || [])) {
      const sub = (r?.page?.domain || "").toLowerCase();
      if (sub && isValidSubdomain(sub, domain) && !seen.has(sub)) { seen.add(sub); out.push({ subdomain: sub, ip: r?.page?.ip || "", source: "urlscan" }); }
    }
    return out;
  } catch { return []; }
}

async function fetchCrtSh(domain, timeoutMs = 40000) {
  const directUrl = `https://crt.sh/?q=%.${domain}&output=json`;
  const crtUrl = `https://crt.sh/?q=%25.${domain}&output=json`;
  let res = null;
  try { const r = await fetch(directUrl, { signal: AbortSignal.timeout(timeoutMs) }); if (r.ok) res = r; } catch {}
  if (!res) { try { const r = await fetch(`https://corsproxy.io/?url=${encodeURIComponent(crtUrl)}`, { signal: AbortSignal.timeout(timeoutMs) }); if (r.ok) res = r; } catch {} }
  if (!res) return [];
  let text; try { text = await res.text(); } catch { return []; }
  if (!text || text.trimStart()[0] !== "[") return [];
  let data; try { data = JSON.parse(text); } catch { return []; }
  if (!Array.isArray(data)) return [];
  const seen = new Set(); const out = [];
  for (const entry of data) {
    for (const name of (entry.name_value || "").split("\n")) {
      const sub = name.trim().replace(/^\*\./, "").toLowerCase();
      if (sub && isValidSubdomain(sub, domain) && !seen.has(sub)) { seen.add(sub); out.push({ subdomain: sub, ip: "", source: "crtsh" }); }
    }
  }
  return out;
}

async function fetchJLDC(domain, timeoutMs = 13000) {
  try {
    const res = await proxyFetch(`https://dns.bufferover.run/dns?q=.${domain}`, timeoutMs);
    const data = await res.json();
    const seen = new Set(); const out = [];
    for (const record of [...(data.FDNS_A || []), ...(data.RDNS || [])]) {
      const parts = record.split(","); const sub = (parts[1] || parts[0] || "").toLowerCase().trim();
      const ip = parts.length > 1 ? parts[0].trim() : "";
      if (sub && isValidSubdomain(sub, domain) && !seen.has(sub)) { seen.add(sub); out.push({ subdomain: sub, ip, source: "jldc" }); }
    }
    return out;
  } catch { return []; }
}

async function fetchCertSpotter(domain, timeoutMs = 13000) {
  try {
    const res = await proxyFetch(`https://api.certspotter.com/v1/issuances?domain=${domain}&include_subdomains=true&expand=dns_names`, timeoutMs);
    const data = await res.json();
    if (!Array.isArray(data)) return [];
    const seen = new Set(); const out = [];
    for (const cert of data) {
      for (const name of (cert.dns_names || [])) {
        const sub = name.replace(/^\*\./, "").toLowerCase().trim();
        if (sub && isValidSubdomain(sub, domain) && !seen.has(sub)) { seen.add(sub); out.push({ subdomain: sub, ip: "", source: "certspotter" }); }
      }
    }
    return out;
  } catch { return []; }
}

async function fetchRapidDNS(domain, timeoutMs = 13000) {
  try {
    const res = await proxyFetch(`https://rapiddns.io/subdomain/${domain}?full=1`, timeoutMs);
    const html = await res.text();
    const matches = html.matchAll(/<td>([a-z0-9][a-z0-9.\-]*\.[a-z]{2,})<\/td>/gi);
    const seen = new Set(); const out = [];
    for (const m of matches) {
      const sub = m[1].toLowerCase();
      if (isValidSubdomain(sub, domain) && !seen.has(sub)) { seen.add(sub); out.push({ subdomain: sub, ip: "", source: "rapiddns" }); }
    }
    return out;
  } catch { return []; }
}

async function fetchDNSRepo(domain, timeoutMs = 13000) {
  try {
    const res = await proxyFetch(`https://dnsrepo.noc.org/?domain=${domain}`, timeoutMs);
    const html = await res.text();
    const matches = html.matchAll(/([a-z0-9][a-z0-9.\-]*\.[a-z]{2,})/gi);
    const seen = new Set(); const out = [];
    for (const m of matches) {
      const sub = m[1].toLowerCase();
      if (isValidSubdomain(sub, domain) && !seen.has(sub)) { seen.add(sub); out.push({ subdomain: sub, ip: "", source: "dnsrepo" }); }
    }
    return out;
  } catch { return []; }
}

async function fetchWaybackSub(domain, timeoutMs = 25000) {
  try {
    const res = await proxyFetch(
      `https://web.archive.org/cdx/search/cdx?url=*.${domain}/*&output=text&fl=original&collapse=urlkey&limit=15000`,
      timeoutMs, true
    );
    const text = await res.text();
    const seen = new Set(); const out = [];
    for (const line of text.trim().split("\n")) {
      try {
        const url = new URL(line.trim());
        const host = url.hostname.toLowerCase();
        if (isValidSubdomain(host, domain) && !seen.has(host)) {
          seen.add(host); out.push({ subdomain: host, ip: "", source: "wayback_sub" });
        }
      } catch {}
    }
    return out;
  } catch { return []; }
}

async function fetchGitHub(domain, timeoutMs = 15000) {
  try {
    const res = await proxyFetch(`https://api.github.com/search/code?q=%22${domain}%22&per_page=100`, timeoutMs);
    const data = await res.json();
    const seen = new Set(); const out = [];
    const escaped = domain.replace(/\./g, "\\.");
    const regex = new RegExp(`[a-z0-9][a-z0-9.\\-]*\\.${escaped}`, "gi");
    for (const item of (data.items || [])) {
      const text = [item.html_url || "", item.name || "", item.path || "", item.repository?.full_name || ""].join(" ");
      for (const m of (text.match(regex) || [])) {
        const sub = m.toLowerCase();
        if (isValidSubdomain(sub, domain) && !seen.has(sub)) { seen.add(sub); out.push({ subdomain: sub, ip: "", source: "github" }); }
      }
    }
    return out;
  } catch { return []; }
}

async function fetchShodan(domain, timeoutMs = 15000) {
  try {
    const res = await proxyFetch(`https://www.shodan.io/search?query=hostname%3A${domain}&facets=domain`, timeoutMs);
    const html = await res.text();
    const seen = new Set(); const out = [];
    const escaped = domain.replace(/\./g, "\\.");
    const regex = new RegExp(`[a-z0-9][a-z0-9.\\-]*\\.${escaped}`, "gi");
    for (const m of (html.match(regex) || [])) {
      const sub = m.toLowerCase();
      if (isValidSubdomain(sub, domain) && !seen.has(sub)) { seen.add(sub); out.push({ subdomain: sub, ip: "", source: "shodan" }); }
    }
    return out;
  } catch { return []; }
}

async function fetchCensys(domain, timeoutMs = 15000) {
  try {
    const res = await proxyFetch(`https://search.censys.io/certificates?q=parsed.names%3A${domain}&per_page=100`, timeoutMs);
    const html = await res.text();
    const seen = new Set(); const out = [];
    const escaped = domain.replace(/\./g, "\\.");
    const regex = new RegExp(`[a-z0-9][a-z0-9.\\-]*\\.${escaped}`, "gi");
    for (const m of (html.match(regex) || [])) {
      const sub = m.toLowerCase();
      if (isValidSubdomain(sub, domain) && !seen.has(sub)) { seen.add(sub); out.push({ subdomain: sub, ip: "", source: "censys" }); }
    }
    return out;
  } catch { return []; }
}

/* ── Endpoint Fetchers ── */
async function fetchWayback(domain, timeoutMs = 20000) {
  try {
    const res = await proxyFetch(`https://web.archive.org/cdx/search/cdx?url=*.${domain}/*&output=json&fl=original,statuscode&collapse=urlkey&limit=3000`, timeoutMs, true);
    const data = await res.json();
    if (!Array.isArray(data)) return [];
    const seen = new Set(); const out = [];
    for (const row of data.slice(1)) {
      const url = (row[0] || "").trim(); const status = (row[1] || "").trim();
      if (url && !seen.has(url)) { seen.add(url); out.push({ url, status, source: "wayback" }); }
    }
    return out;
  } catch { return []; }
}

async function fetchCommonCrawl(domain, timeoutMs = 20000) {
  try {
    const idxRes = await proxyFetch("https://index.commoncrawl.org/collinfo.json", 8000);
    const indexes = await idxRes.json();
    const latest = indexes[0]?.cdx_api || "https://index.commoncrawl.org/CC-MAIN-2024-10-index";
    const res = await proxyFetch(`${latest}?url=*.${domain}/*&output=json&fl=url,status&limit=2000`, timeoutMs, true);
    const text = await res.text();
    const seen = new Set(); const out = [];
    for (const line of text.trim().split("\n")) {
      try { const obj = JSON.parse(line); const url = obj.url?.trim(); const status = obj.status || ""; if (url && !seen.has(url)) { seen.add(url); out.push({ url, status, source: "commoncrawl" }); } } catch {}
    }
    return out;
  } catch { return []; }
}

async function fetchOTX(domain, timeoutMs = 13000) {
  try {
    const res = await proxyFetch(`https://otx.alienvault.com/api/v1/indicators/domain/${domain}/url_list?limit=500`, timeoutMs);
    const data = await res.json();
    const seen = new Set(); const out = [];
    for (const r of (data.url_list || [])) {
      const url = r.url?.trim();
      if (url && !seen.has(url)) { seen.add(url); out.push({ url, status: "", source: "otx" }); }
    }
    return out;
  } catch { return []; }
}

async function fetchURLScanEp(domain, timeoutMs = 13000) {
  try {
    const res = await proxyFetch(`https://urlscan.io/api/v1/search/?q=page.domain:${domain}&size=100`, timeoutMs);
    const data = await res.json();
    const seen = new Set(); const out = [];
    for (const r of (data.results || [])) {
      const url = r?.page?.url?.trim();
      if (url && !seen.has(url)) { seen.add(url); out.push({ url, status: String(r?.page?.status || ""), source: "urlscan" }); }
    }
    return out;
  } catch { return []; }
}

/* ── Google Dork Data ── */
const DORK_CATEGORIES = [
  { id: "sensitive", title: "Sensitive Files & Data", emoji: "📁", color: "rgba(248,113,113,0.15)", border: "rgba(248,113,113,0.3)", textColor: "#f87171",
    dorks: [
      { label: "Config/ENV files", query: "site:{domain} ext:env | ext:config | ext:cfg | ext:ini" },
      { label: "SQL dump files", query: "site:{domain} ext:sql | ext:sql.gz | ext:db" },
      { label: "Backup files", query: "site:{domain} ext:bak | ext:backup | ext:old | ext:orig" },
      { label: "Log files", query: "site:{domain} ext:log" },
      { label: "Password files", query: 'site:{domain} intitle:"index of" "passwd" | "password"' },
    ]
  },
  { id: "login", title: "Login & Admin Panels", emoji: "🔐", color: "rgba(139,92,246,0.15)", border: "rgba(139,92,246,0.3)", textColor: "#a78bfa",
    dorks: [
      { label: "Admin panels", query: "site:{domain} inurl:admin | inurl:administrator | inurl:wp-admin" },
      { label: "Login pages", query: "site:{domain} inurl:login | inurl:signin | inurl:auth" },
      { label: "Dashboard pages", query: "site:{domain} inurl:dashboard | inurl:panel | inurl:control" },
      { label: "phpMyAdmin", query: "site:{domain} inurl:phpmyadmin" },
      { label: "CMS login", query: "site:{domain} inurl:wp-login | inurl:joomla | inurl:drupal" },
    ]
  },
  { id: "api", title: "APIs & Endpoints", emoji: "🔌", color: "rgba(99,179,255,0.15)", border: "rgba(99,179,255,0.3)", textColor: "#63b3ff",
    dorks: [
      { label: "API endpoints", query: "site:{domain} inurl:/api/ | inurl:/v1/ | inurl:/v2/ | inurl:/rest/" },
      { label: "GraphQL", query: "site:{domain} inurl:graphql | inurl:graphiql" },
      { label: "Swagger UI", query: "site:{domain} inurl:swagger | inurl:api-docs | inurl:openapi" },
      { label: 'API keys in JS', query: 'site:{domain} ext:js "apiKey" | "api_key" | "secret"' },
      { label: "Exposed endpoints", query: 'site:{domain} intitle:"index of" "/api"' },
    ]
  },
  { id: "exposed", title: "Exposed Directories", emoji: "📂", color: "rgba(251,191,36,0.15)", border: "rgba(251,191,36,0.3)", textColor: "#fbbf24",
    dorks: [
      { label: "Directory listing", query: 'site:{domain} intitle:"index of /"' },
      { label: "Git exposed", query: "site:{domain} inurl:/.git" },
      { label: ".htaccess exposed", query: "site:{domain} inurl:.htaccess | inurl:.htpasswd" },
      { label: "Exposed uploads", query: 'site:{domain} intitle:"index of" "uploads" | "files"' },
      { label: "DS_Store files", query: "site:{domain} inurl:.DS_Store" },
    ]
  },
  { id: "subdomains", title: "Subdomains & Infrastructure", emoji: "🌐", color: "rgba(52,211,153,0.15)", border: "rgba(52,211,153,0.3)", textColor: "#34d399",
    dorks: [
      { label: "Dev/Staging subdomains", query: "site:dev.{domain} | site:staging.{domain} | site:test.{domain}" },
      { label: "Internal subdomains", query: "site:internal.{domain} | site:intranet.{domain} | site:vpn.{domain}" },
      { label: "All subdomains", query: "site:*.{domain}" },
      { label: "Beta subdomains", query: "site:beta.{domain} | site:alpha.{domain} | site:preview.{domain}" },
    ]
  },
  { id: "cloud", title: "Cloud & Storage", emoji: "☁️", color: "rgba(56,189,248,0.15)", border: "rgba(56,189,248,0.3)", textColor: "#38bdf8",
    dorks: [
      { label: "S3 buckets", query: 'site:s3.amazonaws.com "{domain}"' },
      { label: "Azure Blob", query: 'site:blob.core.windows.net "{domain}"' },
      { label: "GCP Bucket", query: 'site:storage.googleapis.com "{domain}"' },
      { label: "Firebase DB", query: 'site:firebaseio.com "{domain}"' },
      { label: "Cloud credentials", query: 'site:{domain} "aws_access_key" | "aws_secret" | "AZURE_"' },
    ]
  },
  { id: "errors", title: "Error Pages & Debug Info", emoji: "⚠️", color: "rgba(251,146,60,0.15)", border: "rgba(251,146,60,0.3)", textColor: "#fb923c",
    dorks: [
      { label: "Stack traces", query: 'site:{domain} "stack trace" | "traceback" | "exception"' },
      { label: "PHP errors", query: 'site:{domain} "PHP Parse error" | "PHP Warning" | "PHP Fatal"' },
      { label: "SQL errors", query: 'site:{domain} "sql syntax" | "mysql_fetch" | "ORA-01"' },
      { label: "Debug mode", query: 'site:{domain} "debug=true" | "debug=1" | "APP_DEBUG"' },
      { label: "Server info", query: 'site:{domain} intitle:"phpinfo" "PHP Version"' },
    ]
  },
  { id: "documents", title: "Documents & Reports", emoji: "📄", color: "rgba(236,72,153,0.15)", border: "rgba(236,72,153,0.3)", textColor: "#ec4899",
    dorks: [
      { label: "PDF documents", query: 'site:{domain} ext:pdf "confidential" | "internal"' },
      { label: "Excel files", query: "site:{domain} ext:xlsx | ext:xls | ext:csv" },
      { label: "Word documents", query: "site:{domain} ext:doc | ext:docx" },
      { label: "Presentation files", query: "site:{domain} ext:ppt | ext:pptx" },
      { label: 'Sensitive docs', query: 'site:{domain} ext:pdf | ext:doc "password" | "credentials"' },
    ]
  },
];

const SRC_LABELS = {
  hackertarget: "HackerTarget", urlscan: "URLScan.io", crtsh: "crt.sh", jldc: "JLDC",
  certspotter: "CertSpotter", rapiddns: "RapidDNS", dnsrepo: "DNSRepo",
  wayback_sub: "Wayback", github: "GitHub", shodan: "Shodan", censys: "Censys",
  wayback: "Wayback", commoncrawl: "CommonCrawl", otx: "AlienVault OTX",
};

const QUOTES = [
  { text: "Recon is 80% of the hack — know your target better than they know themselves.", by: "— The Hacker's Mindset" },
  { text: "The quieter you become, the more you are able to hear.", by: "— Kali Linux motto" },
  { text: "Every system is hackable if you take enough time to understand it.", by: "— Unknown" },
  { text: "A bug bounty hunter is just a hacker with permission and patience.", by: "— Community Wisdom" },
  { text: "Reconnaissance is the phase where patience pays dividends in vulnerabilities.", by: "— Bug Bounty Handbook" },
  { text: "Finding a subdomain is easy. Finding the one that matters is the art.", by: "— Recon Philosophy" },
  { text: "Automation finds quantity. Curiosity finds quality.", by: "— Bug Hunter's Creed" },
  { text: "Most critical vulnerabilities aren't in fancy code — they're in forgotten endpoints.", by: "— OWASP Insight" },
  { text: "One man's forgotten staging server is another man's P1.", by: "— Bug Bounty Folklore" },
];
const RANDOM_QUOTE = QUOTES[Math.floor(Math.random() * QUOTES.length)];

/* ── App State ── */
const state = {
  tab: "subdomain",
  drawerOpen: false,

  // Subdomain
  subDomain: "",
  subResults: [],
  subScanning: false,
  subProgress: 0,
  subShowProgress: false,
  subSrcStatus: {},
  subFilter: "",
  subPage: 0,
  subSources: {
    hackertarget: true, urlscan: true, crtsh: true, jldc: true,
    certspotter: true, rapiddns: true, dnsrepo: true,
    wayback_sub: true, github: true, shodan: true, censys: true,
  },

  // Endpoint
  epDomain: "",
  epResults: [],
  epScanning: false,
  epProgress: 0,
  epShowProgress: false,
  epSrcStatus: {},
  epFilter: "",
  epPage: 0,
  epSources: { wayback: true, commoncrawl: true, otx: true, urlscan: true },
  epChips: new Set(),
  epFilterOpen: false,
  epStatsDomain: "",

  // Dork
  dorkDomain: "",
  dorkSearch: "",
};

const PAGE_SIZE = 100;
const EP_PAGE_SIZE = 100;
const EP_LABELS = { wayback: "Wayback Machine", commoncrawl: "Common Crawl", otx: "AlienVault OTX", urlscan: "URLScan.io" };

/* ── Toast ── */
let toastTimer;
function showToast(msg, type = "success") {
  const el = document.getElementById("toast");
  clearTimeout(toastTimer);
  el.textContent = msg;
  el.className = `toast show ${type}`;
  toastTimer = setTimeout(() => { el.className = "toast"; }, 3000);
}

/* ── Particle Canvas ── */
function initParticles() {
  const c = document.getElementById("bg-canvas");
  const ctx = c.getContext("2d");
  let W = 0, H = 0, animId;
  function resize() { W = c.width = innerWidth; H = c.height = innerHeight; }
  resize();
  window.addEventListener("resize", resize);
  const particles = Array.from({ length: 90 }, () => ({
    x: Math.random() * W, y: Math.random() * H,
    vx: (Math.random() - 0.5) * 0.25, vy: (Math.random() - 0.5) * 0.25,
    r: Math.random() * 1.5 + 0.5, alpha: Math.random() * 0.5 + 0.1,
  }));
  function loop() {
    ctx.clearRect(0, 0, W, H);
    for (const p of particles) {
      p.x += p.vx; p.y += p.vy;
      if (p.x < 0 || p.x > W) p.vx *= -1;
      if (p.y < 0 || p.y > H) p.vy *= -1;
      ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(99,179,255,${p.alpha})`; ctx.fill();
    }
    for (let i = 0; i < particles.length; i++) for (let j = i + 1; j < particles.length; j++) {
      const dx = particles[i].x - particles[j].x, dy = particles[i].y - particles[j].y;
      const dist = Math.sqrt(dx * dx + dy * dy);
      if (dist < 130) {
        ctx.beginPath(); ctx.moveTo(particles[i].x, particles[i].y); ctx.lineTo(particles[j].x, particles[j].y);
        ctx.strokeStyle = `rgba(99,179,255,${0.06 * (1 - dist / 130)})`; ctx.lineWidth = 0.6; ctx.stroke();
      }
    }
    animId = requestAnimationFrame(loop);
  }
  loop();
}

/* ── SVG helpers ── */
const svgSearch = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>`;
const svgCopy = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>`;
const svgDownload = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>`;
const svgFilter = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/></svg>`;
const svgExtLink = `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="opacity:.5"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>`;
const svgGitHub = `<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.3 3.44 9.8 8.21 11.39.6.11.82-.26.82-.58v-2.03c-3.34.72-4.04-1.61-4.04-1.61-.55-1.38-1.34-1.75-1.34-1.75-1.09-.74.08-.73.08-.73 1.2.09 1.84 1.24 1.84 1.24 1.07 1.83 2.81 1.3 3.5 1 .11-.78.42-1.3.76-1.6-2.67-.3-5.47-1.33-5.47-5.93 0-1.31.47-2.38 1.24-3.22-.12-.3-.54-1.52.12-3.18 0 0 1.01-.32 3.3 1.23a11.5 11.5 0 0 1 3-.4c1.02.01 2.04.14 3 .4 2.29-1.55 3.3-1.23 3.3-1.23.66 1.66.24 2.88.12 3.18.77.84 1.24 1.91 1.24 3.22 0 4.61-2.81 5.63-5.48 5.92.43.37.81 1.1.81 2.22v3.29c0 .32.22.7.83.58C20.56 21.8 24 17.3 24 12c0-6.63-5.37-12-12-12z"/></svg>`;
const svgMedium = `<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M13.54 12a6.8 6.8 0 0 1-6.77 6.82A6.8 6.8 0 0 1 0 12a6.8 6.8 0 0 1 6.77-6.82A6.8 6.8 0 0 1 13.54 12zm7.42 0c0 3.54-1.51 6.42-3.38 6.42-1.87 0-3.39-2.88-3.39-6.42s1.52-6.42 3.39-6.42 3.38 2.88 3.38 6.42M24 12c0 3.17-.53 5.75-1.19 5.75-.66 0-1.19-2.58-1.19-5.75s.53-5.75 1.19-5.75C23.47 6.25 24 8.83 24 12z"/></svg>`;
const svgLinkedIn = `<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433a2.062 2.062 0 0 1-2.063-2.065 2.064 2.064 0 1 1 2.063 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"/></svg>`;
const svgX = `<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-4.714-6.231-5.401 6.231H2.748l7.73-8.835L1.254 2.25H8.08l4.259 5.629L18.244 2.25zm-1.161 17.52h1.833L7.084 4.126H5.117L17.083 19.77z"/></svg>`;
const svgPortfolio = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="m8 21 4-4 4 4"/><path d="M12 17v4"/></svg>`;

/* ── Filtered Results ── */
function getFilteredSub() {
  return state.subResults.filter(r => !state.subFilter || r.subdomain.includes(state.subFilter.toLowerCase()) || r.ip.includes(state.subFilter));
}
function getFilteredEp() {
  return state.epResults.filter(r => {
    const q = state.epFilter.toLowerCase();
    if (q && !r.url.toLowerCase().includes(q)) return false;
    if (state.epChips.has("js") && !r.url.match(/\.js(\?|$)/)) return false;
    if (state.epChips.has("config") && !r.url.match(/\.(env|config|cfg|ini|xml|yaml|yml|bak|backup|sql)(\?|$)/i)) return false;
    if (state.epChips.has("redirect") && !r.url.match(/redirect|return|next|url=/i)) return false;
    if (state.epChips.has("upload") && !r.url.match(/upload|file|attach/i)) return false;
    if (state.epChips.has("auth") && !r.url.match(/auth|login|oauth|token|sso/i)) return false;
    if (state.epChips.has("admin") && !r.url.match(/admin|panel|manage|dashboard/i)) return false;
    if (state.epChips.has("api") && !r.url.match(/\/api\/|\/v[0-9]+\/|rest|graphql/i)) return false;
    if (state.epChips.has("params") && !r.url.includes("?")) return false;
    return true;
  });
}

/* ── Status Badge ── */
function statusBadgeHTML(status) {
  const s = parseInt(status);
  if (!s) return `<span style="color:var(--muted);font-size:12px">—</span>`;
  const cls = s >= 200 && s < 300 ? "status-2xx" : s >= 300 && s < 400 ? "status-3xx" : s >= 400 && s < 500 ? "status-4xx" : "status-5xx";
  return `<span class="status-badge ${cls}">${status}</span>`;
}

/* ── Source Toggle HTML ── */
function subSourceToggleHTML() {
  return Object.keys(state.subSources).map(src => {
    const active = state.subSources[src];
    const st = state.subSrcStatus[src];
    const countBadge = (st && st.state === "done" && st.count !== undefined) ? `<span class="toggle-count">${st.count}</span>` : "";
    return `<label class="source-toggle ${active ? "active" : ""}" data-src="${src}">
      <input type="checkbox" ${active ? "checked" : ""} />
      <span class="dot"></span>${SRC_LABELS[src] || src}${countBadge}
    </label>`;
  }).join("");
}

function epSourceToggleHTML() {
  return Object.keys(state.epSources).map(src => {
    const active = state.epSources[src];
    const st = state.epSrcStatus[src];
    const countBadge = (st && st.state === "done" && st.count !== undefined) ? `<span class="toggle-count">${st.count}</span>` : "";
    return `<label class="source-toggle ${active ? "active" : ""}" data-src="${src}">
      <input type="checkbox" ${active ? "checked" : ""} />
      <span class="dot"></span>${EP_LABELS[src]}${countBadge}
    </label>`;
  }).join("");
}

/* ── Sub Table Rows ── */
function subTableRowsHTML(filtered) {
  if (filtered.length === 0) {
    return `<tr><td colspan="5"><div class="empty-state"><div class="empty-icon">◎</div><p>Enter a domain above and click <strong>Scan</strong><br/>to start discovering subdomains.</p></div></td></tr>`;
  }
  const visible = filtered.slice(0, (state.subPage + 1) * PAGE_SIZE);
  const remaining = filtered.length - (state.subPage + 1) * PAGE_SIZE;
  let rows = visible.map((r, i) => {
    const parts = r.subdomain.split(".");
    const subHl = parts.length > 2
      ? `<span class="highlight">${parts.slice(0, -2).join(".")}</span>.${parts.slice(-2).join(".")}`
      : `<span class="highlight">${r.subdomain}</span>`;
    const ip = r.ip ? `<span class="ip-pill">${r.ip}</span>` : `<span style="color:var(--muted)">—</span>`;
    const status = r.ip
      ? `<span class="status-pill resolved"><span class="status-dot"></span>Resolved</span>`
      : `<span class="status-pill none"><span class="status-dot"></span>—</span>`;
    return `<tr>
      <td class="td-index">${i + 1}</td>
      <td class="td-sub"><a class="sub-link" href="https://${r.subdomain}" target="_blank" rel="noopener">${subHl} ${svgExtLink}</a></td>
      <td class="td-ip">${ip}</td>
      <td><span class="source-badge ${r.source}">${SRC_LABELS[r.source] || r.source}</span></td>
      <td>${status}</td>
    </tr>`;
  }).join("");
  if (remaining > 0) {
    rows += `<tr><td colspan="5" style="padding:12px 0"><button class="show-more-btn" id="sub-show-more">Show more (${remaining} remaining)</button></td></tr>`;
  }
  return rows;
}

/* ── Ep Table Rows ── */
function epTableRowsHTML(filtered) {
  if (filtered.length === 0) {
    return `<tr><td colspan="4"><div class="empty-state"><div class="empty-icon">◎</div><p>Enter a domain above and click <strong>Scan</strong><br/>to start discovering endpoints.</p></div></td></tr>`;
  }
  const visible = filtered.slice(0, (state.epPage + 1) * EP_PAGE_SIZE);
  const remaining = filtered.length - (state.epPage + 1) * EP_PAGE_SIZE;
  let rows = visible.map((r, i) => `<tr>
    <td class="td-index">${i + 1}</td>
    <td class="ep-url-cell"><a href="${r.url}" target="_blank" rel="noopener">${r.url}</a></td>
    <td>${statusBadgeHTML(r.status)}</td>
    <td><span class="source-badge ${r.source}">${SRC_LABELS[r.source] || r.source}</span></td>
  </tr>`).join("");
  if (remaining > 0) {
    rows += `<tr><td colspan="4" style="padding:12px 0"><button class="show-more-btn" id="ep-show-more">Show more (${remaining} remaining)</button></td></tr>`;
  }
  return rows;
}

/* ── Progress HTML ── */
function subProgressHTML() {
  if (!state.subShowProgress) return "";
  const srcItems = Object.entries(state.subSrcStatus).map(([k, v]) => {
    const extra = v.state === "done" ? ` (${v.count})` : v.state === "error" ? " — failed" : v.state === "quota" ? " — rate limited" : "";
    return `<div class="src-item ${v.state}"><div class="src-dot"></div><span>${SRC_LABELS[k] || k}${extra}</span></div>`;
  }).join("");
  return `<div class="progress-wrap">
    <div class="progress-header">
      <div class="progress-title"><span class="spinner"></span>Scanning sources…</div>
      <span class="progress-pct">${state.subProgress}%</span>
    </div>
    <div class="progress-bar-bg"><div class="progress-bar-fill" style="width:${state.subProgress}%"></div></div>
    <div class="source-status">${srcItems}</div>
  </div>`;
}

function epProgressHTML() {
  if (!state.epShowProgress) return "";
  const srcItems = Object.entries(state.epSrcStatus).map(([k, v]) => {
    const extra = v.state === "done" ? ` (${v.count})` : v.state === "error" ? " — failed" : "";
    return `<div class="src-item ${v.state}"><div class="src-dot"></div><span>${EP_LABELS[k] || k}${extra}</span></div>`;
  }).join("");
  return `<div class="progress-wrap">
    <div class="progress-header">
      <div class="progress-title"><span class="spinner"></span>Scanning sources…</div>
      <span class="progress-pct">${state.epProgress}%</span>
    </div>
    <div class="progress-bar-bg"><div class="progress-bar-fill" style="width:${state.epProgress}%"></div></div>
    <div class="source-status">${srcItems}</div>
  </div>`;
}

/* ── Dork Tab HTML ── */
function buildDork(template) {
  const d = (state.dorkDomain.trim().replace(/^https?:\/\//, "").replace(/\/.*$/, "")) || "example.com";
  return template.replace(/\{domain\}/g, d);
}
function dorkGridHTML() {
  const q = state.dorkSearch.toLowerCase();
  const cats = DORK_CATEGORIES.map(cat => ({
    ...cat,
    dorks: cat.dorks.filter(d => !q || d.label.toLowerCase().includes(q) || d.query.toLowerCase().includes(q))
  })).filter(c => c.dorks.length > 0);

  if (cats.length === 0) return `<div class="empty-state"><div class="empty-icon">🔍</div><p>No dorks match your search.</p></div>`;

  return `<div class="dork-grid">${cats.map(cat => `
    <div class="dork-category">
      <div class="dork-category-title">
        <span style="background:${cat.color};border:1px solid ${cat.border};color:${cat.textColor};padding:4px 8px;border-radius:8px;font-size:13px">${cat.emoji}</span>
        ${cat.title}
      </div>
      <div class="dork-category-desc">${cat.dorks.length} dork${cat.dorks.length !== 1 ? "s" : ""}</div>
      <div class="dork-items">
        ${cat.dorks.map((d, idx) => `
          <div class="dork-item">
            <div class="dork-item-left">
              <div class="dork-item-label" style="color:${cat.textColor}">${d.label}</div>
              <div class="dork-query" data-cat="${cat.id}" data-idx="${idx}" title="Click to copy">${buildDork(d.query)}</div>
            </div>
            <div class="dork-btns">
              <button class="dork-run-btn" data-cat="${cat.id}" data-idx="${idx}">${svgSearch} Search</button>
              <button class="dork-copy-btn" data-cat="${cat.id}" data-idx="${idx}">${svgCopy}</button>
            </div>
          </div>`).join("")}
      </div>
    </div>`).join("")}</div>`;
}

/* ── EP Filter Menu ── */
function epFilterMenuHTML() {
  if (!state.epFilterOpen) return "";
  const chips = [
    { group: "File Types", items: [["js", "JS"], ["config", "Config / Backup"]] },
    { group: "Security", items: [["redirect", "Redirect"], ["upload", "Upload"], ["auth", "Auth"], ["admin", "Admin"]] },
    { group: "Discovery", items: [["api", "API"], ["params", "Has Params"]] },
  ];
  return `<div class="ep-filter-menu" id="ep-filter-menu">
    ${chips.map(g => `
      <div class="ep-filter-group">
        <div class="ep-filter-group-label">${g.group}</div>
        <div class="ep-filter-chips">
          ${g.items.map(([key, label]) => `<button class="ep-chip ${state.epChips.has(key) ? "active" : ""}" data-chip="${key}">${label}</button>`).join("")}
        </div>
      </div>`).join("")}
    <div class="ep-filter-footer"><button class="ep-filter-clear" id="ep-filter-clear">Clear all</button></div>
  </div>`;
}

/* ── Footer HTML ── */
function footerHTML() {
  return `<div class="social-footer">
    <div class="social-footer-inner">
      <div><span class="social-brand-name">Brahmastra</span></div>
      <div class="social-links">
        <a class="social-link" href="https://github.com/PradyumnTiwareNexus" target="_blank" rel="noopener">${svgGitHub} GitHub</a>
        <a class="social-link" href="https://pradyumntiwarenexus.medium.com/" target="_blank" rel="noopener">${svgMedium} Medium</a>
        <a class="social-link" href="https://www.linkedin.com/in/pradyumn-tiwarinexus-b270561b1/" target="_blank" rel="noopener">${svgLinkedIn} LinkedIn</a>
        <a class="social-link" href="https://x.com/pradyumnTiwari0" target="_blank" rel="noopener">${svgX} X / Twitter</a>
        <a class="social-link" href="https://github.com/PradyumnTiwareNexus" target="_blank" rel="noopener">${svgPortfolio} Portfolio</a>
      </div>
      <div class="social-copy">© 2026 Brahmastra · created by pradyumntiwarenexus · Advanced Recon & Dorking Platform</div>
    </div>
  </div>`;
}

/* ── Main Render ── */
function render() {
  const app = document.getElementById("app");
  const filteredSub = getFilteredSub();
  const filteredEp = getFilteredEp();
  const subResolved = state.subResults.filter(r => r.ip).length;
  const subUniqueIPs = new Set(state.subResults.filter(r => r.ip).map(r => r.ip)).size;
  const subSourcesHit = new Set(state.subResults.map(r => r.source)).size;

  let html = "";

  if (state.tab === "subdomain") {
    html = `
      <div class="hero">
        <h1>BrahmastraX</h1>
        <div class="hero-tagline"><span class="hero-tag">Advanced Recon &amp; Dorking Platform</span></div>
        <div class="hero-tagline" style="margin-top:0">
          <span class="hero-tag">Subdomain Discovery</span><span class="hero-sep">•</span>
          <span class="hero-tag">Endpoint Enumeration</span><span class="hero-sep">•</span>
          <span class="hero-tag">Google Dork Intelligence</span>
        </div>
        <p>BrahmastraX is a powerful bug bounty toolkit designed to uncover hidden attack surfaces by combining multiple passive intelligence sources with advanced Google dorking techniques — all in one streamlined interface, no setup required.</p>
        <div class="hero-quote">
          <span class="hero-quote-mark">"</span>${RANDOM_QUOTE.text}<span class="hero-quote-mark">"</span>
          <span class="hero-quote-by">${RANDOM_QUOTE.by}</span>
        </div>
      </div>

      <div class="search-card">
        <div class="input-row">
          <div class="input-wrap">
            <span class="icon">⌕</span>
            <input class="domain-input" id="sub-domain-input" type="text" placeholder="e.g. example.com" value="${state.subDomain}" />
          </div>
          <button class="scan-btn" id="sub-scan-btn" ${state.subScanning ? "disabled" : ""}>
            <span class="btn-inner">${state.subScanning ? '<span class="spinner"></span> Scanning…' : `${svgSearch} Scan`}</span>
          </button>
        </div>
        <div class="source-row" id="sub-source-row">${subSourceToggleHTML()}</div>
      </div>

      <div class="stats-row">
        <div class="stat-card"><div class="stat-label">Subdomains</div><div class="stat-value">${state.subResults.length}</div></div>
        <div class="stat-card"><div class="stat-label">Resolved</div><div class="stat-value">${subResolved}</div></div>
        <div class="stat-card"><div class="stat-label">Sources Hit</div><div class="stat-value">${subSourcesHit}</div></div>
        <div class="stat-card"><div class="stat-label">Unique IPs</div><div class="stat-value">${subUniqueIPs}</div></div>
      </div>

      ${subProgressHTML()}

      <div class="table-section">
        <div class="table-header">
          <div class="section-title">Results <span>${filteredSub.length > 0 ? `(${filteredSub.length})` : ""}</span></div>
          <div class="table-actions">
            <input class="filter-input" id="sub-filter-input" type="text" placeholder="Filter…" value="${state.subFilter}" />
            <button class="action-btn" id="sub-copy-btn">${svgCopy} Copy</button>
            <button class="action-btn" id="sub-export-btn">${svgDownload} Export .txt</button>
          </div>
        </div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>#</th><th>Subdomain</th><th>IP Address</th><th>Source</th><th>Status</th></tr></thead>
            <tbody id="sub-tbody">${subTableRowsHTML(filteredSub)}</tbody>
          </table>
        </div>
      </div>`;
  }

  else if (state.tab === "endpoint") {
    const epStats = state.epResults.length > 0 ? `
      <div class="stats-row">
        <div class="stat-card"><div class="stat-label">Endpoints Found</div><div class="stat-value">${state.epResults.length}</div></div>
        <div class="stat-card"><div class="stat-label">Sources Hit</div><div class="stat-value">${new Set(state.epResults.map(r => r.source)).size}</div></div>
        <div class="stat-card"><div class="stat-label">Domain</div><div class="stat-value" style="font-size:1.1rem;word-break:break-all">${state.epStatsDomain || "—"}</div></div>
      </div>` : "";

    html = `
      <div class="hero" style="padding-bottom:28px">
        <h1 style="font-size:clamp(32px,6vw,56px)">Endpoint Recon</h1>
        <div class="hero-tagline">
          <span class="hero-tag">Wayback Machine</span><span class="hero-sep">·</span>
          <span class="hero-tag">Common Crawl</span><span class="hero-sep">·</span>
          <span class="hero-tag">AlienVault OTX</span><span class="hero-sep">·</span>
          <span class="hero-tag">URLScan.io</span>
        </div>
        <p>Discover known endpoints, paths, and URLs for a domain from historical web archives and passive sources — no active scanning.</p>
      </div>

      <div class="search-card">
        <div class="input-row">
          <div class="input-wrap">
            <span class="icon">⌕</span>
            <input class="domain-input" id="ep-domain-input" type="text" placeholder="e.g. example.com" value="${state.epDomain}" />
          </div>
          <button class="scan-btn" id="ep-scan-btn" ${state.epScanning ? "disabled" : ""}>
            <span class="btn-inner">${state.epScanning ? '<span class="spinner"></span> Scanning…' : `${svgSearch} Scan`}</span>
          </button>
        </div>
        <div class="source-row" id="ep-source-row">${epSourceToggleHTML()}</div>
      </div>

      ${epProgressHTML()}
      ${epStats}

      <div class="table-section">
        <div class="table-header">
          <div class="section-title">Endpoints <span>${filteredEp.length > 0 ? `(${filteredEp.length})` : ""}</span></div>
          <div class="table-actions">
            <div class="ep-filter-wrap" id="ep-filter-wrap">
              <button class="action-btn" id="ep-filter-toggle-btn">
                ${svgFilter} Filters ${state.epChips.size > 0 ? `<span style="background:var(--cyan);color:#0a0f1e;border-radius:10px;padding:1px 6px;font-size:10px;font-weight:800">${state.epChips.size}</span>` : ""}
              </button>
              ${epFilterMenuHTML()}
            </div>
            <input class="filter-input" id="ep-filter-input" style="width:190px" type="text" placeholder="Filter endpoints…" value="${state.epFilter}" />
            <button class="action-btn" id="ep-copy-btn">${svgCopy} Copy</button>
            <button class="action-btn" id="ep-export-btn">${svgDownload} Export .txt</button>
          </div>
        </div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>#</th><th>URL</th><th>Status</th><th>Source</th></tr></thead>
            <tbody id="ep-tbody">${epTableRowsHTML(filteredEp)}</tbody>
          </table>
        </div>
      </div>`;
  }

  else if (state.tab === "dork") {
    html = `
      <div class="hero" style="padding-bottom:28px">
        <h1 style="font-size:clamp(32px,6vw,56px)">Google Dork</h1>
        <div class="hero-tagline">
          <span class="hero-tag">Sensitive Files</span><span class="hero-sep">·</span>
          <span class="hero-tag">Admin Panels</span><span class="hero-sep">·</span>
          <span class="hero-tag">Exposed APIs</span><span class="hero-sep">·</span>
          <span class="hero-tag">Cloud Storage</span>
        </div>
        <p>Ready-made Google dorks for bug bounty recon. Enter your target domain, click <strong style="color:var(--cyan)">Search</strong> to run on Google, or copy the query.</p>
      </div>

      <div class="dork-search-bar">
        <input class="dork-target-input" id="dork-domain-input" type="text" placeholder="Target domain (e.g. example.com)" value="${state.dorkDomain}" />
        <input class="dork-search-input" id="dork-search-input" type="text" placeholder="Search dorks…" value="${state.dorkSearch}" />
      </div>

      <div id="dork-grid-container">${dorkGridHTML()}</div>`;
  }

  html += footerHTML();
  app.innerHTML = html;
  bindEvents();
}

/* ── Bind Events ── */
function bindEvents() {
  // Subdomain tab
  const subInput = document.getElementById("sub-domain-input");
  if (subInput) {
    subInput.addEventListener("input", e => { state.subDomain = e.target.value; });
    subInput.addEventListener("keydown", e => { if (e.key === "Enter" && !state.subScanning) startSubScan(); });
  }
  document.getElementById("sub-scan-btn")?.addEventListener("click", startSubScan);
  document.getElementById("sub-filter-input")?.addEventListener("input", e => {
    state.subFilter = e.target.value; state.subPage = 0;
    const tbody = document.getElementById("sub-tbody");
    if (tbody) tbody.innerHTML = subTableRowsHTML(getFilteredSub());
    bindShowMore();
  });
  document.getElementById("sub-copy-btn")?.addEventListener("click", () => {
    if (!state.subResults.length) { showToast("Nothing to copy.", "error"); return; }
    navigator.clipboard.writeText(state.subResults.map(r => r.subdomain).join("\n"))
      .then(() => showToast("Copied to clipboard!", "success"));
  });
  document.getElementById("sub-export-btn")?.addEventListener("click", () => {
    if (!state.subResults.length) { showToast("Nothing to export.", "error"); return; }
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([state.subResults.map(r => r.subdomain).join("\n")], { type: "text/plain" }));
    a.download = `${state.subDomain}_subdomains.txt`; a.click();
    showToast(`Exported ${state.subResults.length} subdomains`, "success");
  });

  // Sub source toggles
  document.querySelectorAll("#sub-source-row .source-toggle").forEach(el => {
    el.addEventListener("click", () => {
      const src = el.dataset.src;
      state.subSources[src] = !state.subSources[src];
      el.classList.toggle("active", state.subSources[src]);
      el.querySelector(".dot").style.background = state.subSources[src] ? "var(--green)" : "";
      el.querySelector(".dot").style.boxShadow = state.subSources[src] ? "0 0 6px var(--green)" : "";
    });
  });

  // Endpoint tab
  const epInput = document.getElementById("ep-domain-input");
  if (epInput) {
    epInput.addEventListener("input", e => { state.epDomain = e.target.value; });
    epInput.addEventListener("keydown", e => { if (e.key === "Enter" && !state.epScanning) startEpScan(); });
  }
  document.getElementById("ep-scan-btn")?.addEventListener("click", startEpScan);
  document.getElementById("ep-filter-input")?.addEventListener("input", e => {
    state.epFilter = e.target.value; state.epPage = 0;
    const tbody = document.getElementById("ep-tbody");
    if (tbody) tbody.innerHTML = epTableRowsHTML(getFilteredEp());
    bindShowMore();
  });
  document.getElementById("ep-copy-btn")?.addEventListener("click", () => {
    const f = getFilteredEp();
    if (!f.length) { showToast("Nothing to copy.", "error"); return; }
    navigator.clipboard.writeText(f.map(r => r.url).join("\n")).then(() => showToast("Copied!", "success"));
  });
  document.getElementById("ep-export-btn")?.addEventListener("click", () => {
    const f = getFilteredEp();
    if (!f.length) { showToast("Nothing to export.", "error"); return; }
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([f.map(r => r.url).join("\n")], { type: "text/plain" }));
    a.download = `${state.epDomain}_endpoints.txt`; a.click();
    showToast(`Exported ${f.length} endpoints`, "success");
  });

  // EP source toggles
  document.querySelectorAll("#ep-source-row .source-toggle").forEach(el => {
    el.addEventListener("click", () => {
      const src = el.dataset.src;
      state.epSources[src] = !state.epSources[src];
      el.classList.toggle("active", state.epSources[src]);
    });
  });

  // EP filter toggle
  document.getElementById("ep-filter-toggle-btn")?.addEventListener("click", e => {
    e.stopPropagation();
    state.epFilterOpen = !state.epFilterOpen;
    const wrap = document.getElementById("ep-filter-wrap");
    if (wrap) {
      const menu = wrap.querySelector(".ep-filter-menu");
      if (menu) menu.remove();
      if (state.epFilterOpen) wrap.insertAdjacentHTML("beforeend", epFilterMenuHTML().replace('<div class="ep-filter-menu" id="ep-filter-menu">', '<div class="ep-filter-menu" id="ep-filter-menu">'));
      bindFilterChips();
    }
  });
  document.addEventListener("click", (e) => {
    if (state.epFilterOpen && !e.target.closest("#ep-filter-wrap")) {
      state.epFilterOpen = false;
      document.getElementById("ep-filter-menu")?.remove();
    }
  });

  bindFilterChips();
  bindShowMore();
  bindDorkEvents();
}

function bindFilterChips() {
  document.querySelectorAll(".ep-chip").forEach(btn => {
    btn.addEventListener("click", () => {
      const key = btn.dataset.chip;
      if (state.epChips.has(key)) state.epChips.delete(key); else state.epChips.add(key);
      btn.classList.toggle("active", state.epChips.has(key));
      const tbody = document.getElementById("ep-tbody");
      if (tbody) tbody.innerHTML = epTableRowsHTML(getFilteredEp());
      bindShowMore();
    });
  });
  document.getElementById("ep-filter-clear")?.addEventListener("click", () => {
    state.epChips.clear();
    document.querySelectorAll(".ep-chip").forEach(b => b.classList.remove("active"));
    const tbody = document.getElementById("ep-tbody");
    if (tbody) tbody.innerHTML = epTableRowsHTML(getFilteredEp());
    bindShowMore();
  });
}

function bindShowMore() {
  document.getElementById("sub-show-more")?.addEventListener("click", () => {
    state.subPage++;
    const tbody = document.getElementById("sub-tbody");
    if (tbody) tbody.innerHTML = subTableRowsHTML(getFilteredSub());
    bindShowMore();
  });
  document.getElementById("ep-show-more")?.addEventListener("click", () => {
    state.epPage++;
    const tbody = document.getElementById("ep-tbody");
    if (tbody) tbody.innerHTML = epTableRowsHTML(getFilteredEp());
    bindShowMore();
  });
}

function bindDorkEvents() {
  document.getElementById("dork-domain-input")?.addEventListener("input", e => {
    state.dorkDomain = e.target.value;
    const gc = document.getElementById("dork-grid-container");
    if (gc) gc.innerHTML = dorkGridHTML();
    bindDorkGrid();
  });
  document.getElementById("dork-search-input")?.addEventListener("input", e => {
    state.dorkSearch = e.target.value;
    const gc = document.getElementById("dork-grid-container");
    if (gc) gc.innerHTML = dorkGridHTML();
    bindDorkGrid();
  });
  bindDorkGrid();
}

function bindDorkGrid() {
  document.querySelectorAll(".dork-query").forEach(el => {
    el.addEventListener("click", () => {
      const catId = el.dataset.cat; const idx = parseInt(el.dataset.idx);
      const cat = DORK_CATEGORIES.find(c => c.id === catId);
      if (!cat) return;
      const q = buildDork(cat.dorks[idx].query);
      navigator.clipboard.writeText(q).then(() => showToast("Copied!", "success"));
    });
  });
  document.querySelectorAll(".dork-run-btn").forEach(el => {
    el.addEventListener("click", () => {
      const catId = el.dataset.cat; const idx = parseInt(el.dataset.idx);
      const cat = DORK_CATEGORIES.find(c => c.id === catId);
      if (!cat) return;
      const q = buildDork(cat.dorks[idx].query);
      window.open(`https://www.google.com/search?q=${encodeURIComponent(q)}`, "_blank", "noopener");
    });
  });
  document.querySelectorAll(".dork-copy-btn").forEach(el => {
    el.addEventListener("click", () => {
      const catId = el.dataset.cat; const idx = parseInt(el.dataset.idx);
      const cat = DORK_CATEGORIES.find(c => c.id === catId);
      if (!cat) return;
      navigator.clipboard.writeText(buildDork(cat.dorks[idx].query)).then(() => showToast("Copied!", "success"));
    });
  });
}

/* ── Sub Scan ── */
async function startSubScan() {
  const domain = state.subDomain.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/\/$/, "");
  if (!domain || !/^[a-z0-9][a-z0-9.\-]*\.[a-z]{2,}$/.test(domain)) { showToast("Please enter a valid domain name.", "error"); return; }
  if (!Object.values(state.subSources).some(Boolean)) { showToast("Enable at least one source.", "error"); return; }

  state.subScanning = true; state.subResults = []; state.subPage = 0; state.subFilter = "";
  state.subShowProgress = true; state.subProgress = 0; state.subSrcStatus = {};
  const active = Object.entries(state.subSources).filter(([, v]) => v).map(([k]) => k);
  active.forEach(k => { state.subSrcStatus[k] = { state: "loading" }; });
  render();

  let done = 0;
  function mergeResults(items) {
    const seen = new Set(state.subResults.map(r => r.subdomain));
    state.subResults.push(...items.filter(r => !seen.has(r.subdomain)));
  }
  function updateProgress(src, st, count) {
    state.subSrcStatus[src] = { state: st, count };
    done++;
    state.subProgress = Math.round(done / active.length * 100);
    // Partial UI update
    const pb = document.querySelector(".progress-bar-fill");
    if (pb) pb.style.width = state.subProgress + "%";
    const pct = document.querySelector(".progress-pct");
    if (pct) pct.textContent = state.subProgress + "%";
    const srcList = document.querySelector(".source-status");
    if (srcList) {
      const extra = st === "done" ? ` (${count})` : st === "error" ? " — failed" : st === "quota" ? " — rate limited" : "";
      const item = srcList.querySelector(`.src-item`);
      if (item) {
        // Re-render source status
        srcList.innerHTML = Object.entries(state.subSrcStatus).map(([k, v]) => {
          const ex = v.state === "done" ? ` (${v.count})` : v.state === "error" ? " — failed" : v.state === "quota" ? " — rate limited" : "";
          return `<div class="src-item ${v.state}"><div class="src-dot"></div><span>${SRC_LABELS[k] || k}${ex}</span></div>`;
        }).join("");
      }
    }
    // Update stats
    const statsCards = document.querySelectorAll(".stat-card .stat-value");
    if (statsCards.length >= 4) {
      const resolved = state.subResults.filter(r => r.ip).length;
      const ips = new Set(state.subResults.filter(r => r.ip).map(r => r.ip)).size;
      const srcs = new Set(state.subResults.map(r => r.source)).size;
      statsCards[0].textContent = state.subResults.length;
      statsCards[1].textContent = resolved;
      statsCards[2].textContent = srcs;
      statsCards[3].textContent = ips;
    }
    // Update table
    const tbody = document.getElementById("sub-tbody");
    if (tbody) tbody.innerHTML = subTableRowsHTML(getFilteredSub());
    bindShowMore();
    // Update toggle counts
    if (st === "done") {
      document.querySelectorAll("#sub-source-row .source-toggle").forEach(el => {
        if (el.dataset.src === src) {
          let badge = el.querySelector(".toggle-count");
          if (!badge) { badge = document.createElement("span"); badge.className = "toggle-count"; el.appendChild(badge); }
          badge.textContent = count;
        }
      });
    }
  }

  const tasks = active.map(async (src) => {
    try {
      let results = [];
      if (src === "hackertarget") results = await fetchHackerTarget(domain);
      else if (src === "urlscan") results = await fetchURLScan(domain);
      else if (src === "crtsh") results = await fetchCrtSh(domain);
      else if (src === "jldc") results = await fetchJLDC(domain);
      else if (src === "certspotter") results = await fetchCertSpotter(domain);
      else if (src === "rapiddns") results = await fetchRapidDNS(domain);
      else if (src === "dnsrepo") results = await fetchDNSRepo(domain);
      else if (src === "wayback_sub") results = await fetchWaybackSub(domain);
      else if (src === "github") results = await fetchGitHub(domain);
      else if (src === "shodan") results = await fetchShodan(domain);
      else if (src === "censys") results = await fetchCensys(domain);
      mergeResults(results);
      updateProgress(src, "done", results.length);
    } catch (e) {
      updateProgress(src, e?.quota ? "quota" : "error", 0);
    }
  });

  await Promise.allSettled(tasks);
  state.subProgress = 100;
  state.subScanning = false;
  setTimeout(() => { state.subShowProgress = false; render(); }, 700);
}

/* ── Ep Scan ── */
async function startEpScan() {
  const domain = state.epDomain.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  if (!domain || !/^[a-z0-9][a-z0-9.\-]*\.[a-z]{2,}$/.test(domain)) { showToast("Please enter a valid domain.", "error"); return; }
  if (!Object.values(state.epSources).some(Boolean)) { showToast("Enable at least one source.", "error"); return; }

  state.epScanning = true; state.epResults = []; state.epPage = 0; state.epFilter = "";
  state.epShowProgress = true; state.epProgress = 0; state.epSrcStatus = {};
  state.epStatsDomain = domain; state.epChips = new Set();
  const active = Object.entries(state.epSources).filter(([, v]) => v).map(([k]) => k);
  active.forEach(k => { state.epSrcStatus[k] = { state: "loading" }; });
  render();

  let done = 0;
  function mergeEpResults(items) {
    const seen = new Set(state.epResults.map(r => r.url));
    state.epResults.push(...items.filter(r => !seen.has(r.url)));
  }
  function updateEpProgress(src, st, count) {
    state.epSrcStatus[src] = { state: st, count };
    done++;
    state.epProgress = Math.round(done / active.length * 100);
    const pb = document.querySelector(".progress-bar-fill");
    if (pb) pb.style.width = state.epProgress + "%";
    const pct = document.querySelector(".progress-pct");
    if (pct) pct.textContent = state.epProgress + "%";
    const srcList = document.querySelector(".source-status");
    if (srcList) {
      srcList.innerHTML = Object.entries(state.epSrcStatus).map(([k, v]) => {
        const ex = v.state === "done" ? ` (${v.count})` : v.state === "error" ? " — failed" : "";
        return `<div class="src-item ${v.state}"><div class="src-dot"></div><span>${EP_LABELS[k] || k}${ex}</span></div>`;
      }).join("");
    }
    const tbody = document.getElementById("ep-tbody");
    if (tbody) tbody.innerHTML = epTableRowsHTML(getFilteredEp());
    bindShowMore();
  }

  const tasks = active.map(async (src) => {
    try {
      let results = [];
      if (src === "wayback") results = await fetchWayback(domain);
      else if (src === "commoncrawl") results = await fetchCommonCrawl(domain);
      else if (src === "otx") results = await fetchOTX(domain);
      else if (src === "urlscan") results = await fetchURLScanEp(domain);
      mergeEpResults(results);
      updateEpProgress(src, "done", results.length);
    } catch { updateEpProgress(src, "error", 0); }
  });

  await Promise.allSettled(tasks);
  state.epProgress = 100;
  state.epScanning = false;
  setTimeout(() => { state.epShowProgress = false; render(); }, 700);
}

/* ── Nav / Tab Switching ── */
function setTab(tab) {
  state.tab = tab;
  state.drawerOpen = false;
  // Update nav pills
  document.querySelectorAll(".nav-pill").forEach(btn => btn.classList.toggle("active", btn.dataset.tab === tab));
  document.querySelectorAll(".drawer-nav-item").forEach(btn => btn.classList.toggle("active", btn.dataset.tab === tab));
  document.getElementById("mobile-drawer").classList.remove("open");
  document.getElementById("hamburger-btn").classList.remove("open");
  render();
}

/* ── Init ── */
document.addEventListener("DOMContentLoaded", () => {
  initParticles();

  // Nav brand click
  document.getElementById("nav-brand").addEventListener("click", () => setTab("subdomain"));

  // Nav pills
  document.querySelectorAll(".nav-pill").forEach(btn => btn.addEventListener("click", () => setTab(btn.dataset.tab)));

  // Mobile drawer
  document.querySelectorAll(".drawer-nav-item").forEach(btn => btn.addEventListener("click", () => setTab(btn.dataset.tab)));
  document.getElementById("hamburger-btn").addEventListener("click", () => {
    state.drawerOpen = !state.drawerOpen;
    document.getElementById("hamburger-btn").classList.toggle("open", state.drawerOpen);
    document.getElementById("mobile-drawer").classList.toggle("open", state.drawerOpen);
  });

  render();
});
