/* =========================================================
   BrahmastraX — Advanced Recon & Dorking Platform
   created by pradyumntiwarenexus
   Standalone Vanilla JS — No build tools required
   ========================================================= */

/* ── CORS Proxies ── */
const PROXY_LIST = [
  u=>`https://corsproxy.io/?url=${encodeURIComponent(u)}`,
  u=>`https://cors.eu.org/${u}`,
  u=>`https://api.allorigins.win/raw?url=${encodeURIComponent(u)}`,
  u=>`https://api.codetabs.com/v1/proxy?quest=${encodeURIComponent(u)}`,
  u=>`https://thingproxy.freeboard.io/fetch/${u}`,
];
const PROXY_LARGE = [
  u=>`https://cors.eu.org/${u}`,
  u=>`https://api.allorigins.win/raw?url=${encodeURIComponent(u)}`,
  u=>`https://api.codetabs.com/v1/proxy?quest=${encodeURIComponent(u)}`,
  u=>`https://thingproxy.freeboard.io/fetch/${u}`,
  u=>`https://corsproxy.io/?url=${encodeURIComponent(u)}`,
];

async function proxyFetch(url, ms=13000, large=false) {
  const list = large ? PROXY_LARGE : PROXY_LIST;
  let last = new Error("All proxies failed");
  for (const make of list) {
    try {
      const r = await fetch(make(url), {signal: AbortSignal.timeout(ms)});
      if (r.ok) return r;
      last = new Error("HTTP "+r.status);
    } catch(e) { last=e; }
  }
  throw last;
}

function isValidSub(raw, domain) {
  if (!raw) return false;
  const s = raw.trim().toLowerCase();
  if (s.includes("@")||s.includes("/")||s.includes(":")||s.startsWith("*")) return false;
  if (!/^[a-z0-9][a-z0-9.\-]*[a-z0-9]$/.test(s) && s!==domain) return false;
  if (s!==domain && !s.endsWith("."+domain)) return false;
  if (s===domain) return false;
  if (s.split(".").some(l=>l.length>63)) return false;
  return true;
}

/* ── SUBDOMAIN FETCHERS ── */
async function fetchHackerTarget(d,ms=13000) {
  const url=`https://api.hackertarget.com/hostsearch/?q=${d}`;
  let text;
  try { const r=await fetch(url,{signal:AbortSignal.timeout(ms)}); text=await r.text(); }
  catch { try { const r=await proxyFetch(url,ms+5000); text=await r.text(); } catch { return []; } }
  if (!text) return [];
  if (text.includes("API count exceeded")||text.includes("API Key Required")||text.includes("Increase Quota")) { const e=new Error("quota"); e.quota=true; throw e; }
  if (text.startsWith("error")||text.startsWith("<")||!text.includes(",")) return [];
  return text.trim().split("\n").filter(l=>l.includes(","))
    .map(l=>{ const [s,ip]=l.split(","); return {subdomain:s.trim().toLowerCase(),ip:(ip||"").trim(),source:"hackertarget"}; })
    .filter(r=>isValidSub(r.subdomain,d));
}
async function fetchURLScan(d,ms=13000) {
  try {
    const r=await proxyFetch(`https://urlscan.io/api/v1/search/?q=page.domain:${d}&size=100`,ms);
    const data=await r.json(); const seen=new Set(); const out=[];
    for (const x of (data.results||[])) {
      const s=(x?.page?.domain||"").toLowerCase();
      if (s&&isValidSub(s,d)&&!seen.has(s)) { seen.add(s); out.push({subdomain:s,ip:x?.page?.ip||"",source:"urlscan"}); }
    }
    return out;
  } catch { return []; }
}
async function fetchCrtSh(d,ms=40000) {
  let res=null;
  const direct=`https://crt.sh/?q=%.${d}&output=json`;
  const proxied=`https://crt.sh/?q=%25.${d}&output=json`;
  try { const r=await fetch(direct,{signal:AbortSignal.timeout(ms)}); if(r.ok) res=r; } catch {}
  if (!res) { try { const r=await fetch(`https://corsproxy.io/?url=${encodeURIComponent(proxied)}`,{signal:AbortSignal.timeout(ms)}); if(r.ok) res=r; } catch {} }
  if (!res) return [];
  let text; try { text=await res.text(); } catch { return []; }
  if (!text||text.trimStart()[0]!=="[") return [];
  let data; try { data=JSON.parse(text); } catch { return []; }
  const seen=new Set(); const out=[];
  for (const e of data) {
    for (const n of (e.name_value||"").split("\n")) {
      const s=n.trim().replace(/^\*\./,"").toLowerCase();
      if (s&&isValidSub(s,d)&&!seen.has(s)) { seen.add(s); out.push({subdomain:s,ip:"",source:"crtsh"}); }
    }
  }
  return out;
}
async function fetchJLDC(d,ms=13000) {
  try {
    const r=await proxyFetch(`https://dns.bufferover.run/dns?q=.${d}`,ms);
    const data=await r.json(); const seen=new Set(); const out=[];
    for (const rec of [...(data.FDNS_A||[]),...(data.RDNS||[])]) {
      const parts=rec.split(","); const s=(parts[1]||parts[0]||"").toLowerCase().trim();
      const ip=parts.length>1?parts[0].trim():"";
      if (s&&isValidSub(s,d)&&!seen.has(s)) { seen.add(s); out.push({subdomain:s,ip,source:"jldc"}); }
    }
    return out;
  } catch { return []; }
}
async function fetchCertSpotter(d,ms=13000) {
  try {
    const r=await proxyFetch(`https://api.certspotter.com/v1/issuances?domain=${d}&include_subdomains=true&expand=dns_names`,ms);
    const data=await r.json(); if (!Array.isArray(data)) return [];
    const seen=new Set(); const out=[];
    for (const c of data) for (const n of (c.dns_names||[])) {
      const s=n.replace(/^\*\./,"").toLowerCase().trim();
      if (s&&isValidSub(s,d)&&!seen.has(s)) { seen.add(s); out.push({subdomain:s,ip:"",source:"certspotter"}); }
    }
    return out;
  } catch { return []; }
}
async function fetchRapidDNS(d,ms=13000) {
  try {
    const r=await proxyFetch(`https://rapiddns.io/subdomain/${d}?full=1`,ms);
    const html=await r.text();
    const seen=new Set(); const out=[];
    for (const m of html.matchAll(/<td>([a-z0-9][a-z0-9.\-]*\.[a-z]{2,})<\/td>/gi)) {
      const s=m[1].toLowerCase();
      if (isValidSub(s,d)&&!seen.has(s)) { seen.add(s); out.push({subdomain:s,ip:"",source:"rapiddns"}); }
    }
    return out;
  } catch { return []; }
}
async function fetchDNSRepo(d,ms=13000) {
  try {
    const r=await proxyFetch(`https://dnsrepo.noc.org/?domain=${d}`,ms);
    const html=await r.text();
    const seen=new Set(); const out=[];
    for (const m of html.matchAll(/([a-z0-9][a-z0-9.\-]*\.[a-z]{2,})/gi)) {
      const s=m[1].toLowerCase();
      if (isValidSub(s,d)&&!seen.has(s)) { seen.add(s); out.push({subdomain:s,ip:"",source:"dnsrepo"}); }
    }
    return out;
  } catch { return []; }
}
async function fetchWaybackSub(d,ms=25000) {
  try {
    const r=await proxyFetch(`https://web.archive.org/cdx/search/cdx?url=*.${d}/*&output=text&fl=original&collapse=urlkey&limit=15000`,ms,true);
    const text=await r.text(); const seen=new Set(); const out=[];
    for (const line of text.trim().split("\n")) {
      try { const u=new URL(line.trim()); const h=u.hostname.toLowerCase(); if(isValidSub(h,d)&&!seen.has(h)){seen.add(h);out.push({subdomain:h,ip:"",source:"wayback_sub"});} } catch {}
    }
    return out;
  } catch { return []; }
}
async function fetchGitHub(d,ms=15000) {
  try {
    const r=await proxyFetch(`https://api.github.com/search/code?q=%22${d}%22&per_page=100`,ms);
    const data=await r.json(); const seen=new Set(); const out=[];
    const regex=new RegExp(`[a-z0-9][a-z0-9.\\-]*\\.${d.replace(/\./g,"\\.")}`, "gi");
    for (const item of (data.items||[])) {
      const text=[item.html_url||"",item.name||"",item.path||"",item.repository?.full_name||""].join(" ");
      for (const m of (text.match(regex)||[])) {
        const s=m.toLowerCase();
        if (isValidSub(s,d)&&!seen.has(s)) { seen.add(s); out.push({subdomain:s,ip:"",source:"github"}); }
      }
    }
    return out;
  } catch { return []; }
}
async function fetchShodan(d,ms=15000) {
  try {
    const r=await proxyFetch(`https://www.shodan.io/search?query=hostname%3A${d}&facets=domain`,ms);
    const html=await r.text(); const seen=new Set(); const out=[];
    const regex=new RegExp(`[a-z0-9][a-z0-9.\\-]*\\.${d.replace(/\./g,"\\.")}`, "gi");
    for (const m of (html.match(regex)||[])) {
      const s=m.toLowerCase();
      if (isValidSub(s,d)&&!seen.has(s)) { seen.add(s); out.push({subdomain:s,ip:"",source:"shodan"}); }
    }
    return out;
  } catch { return []; }
}
async function fetchCensys(d,ms=15000) {
  try {
    const r=await proxyFetch(`https://search.censys.io/certificates?q=parsed.names%3A${d}&per_page=100`,ms);
    const html=await r.text(); const seen=new Set(); const out=[];
    const regex=new RegExp(`[a-z0-9][a-z0-9.\\-]*\\.${d.replace(/\./g,"\\.")}`, "gi");
    for (const m of (html.match(regex)||[])) {
      const s=m.toLowerCase();
      if (isValidSub(s,d)&&!seen.has(s)) { seen.add(s); out.push({subdomain:s,ip:"",source:"censys"}); }
    }
    return out;
  } catch { return []; }
}

/* ── ENDPOINT FETCHERS ── */
async function fetchWayback(d,ms=20000) {
  try {
    const r=await proxyFetch(`https://web.archive.org/cdx/search/cdx?url=*.${d}/*&output=json&fl=original,statuscode&collapse=urlkey&limit=3000`,ms,true);
    const data=await r.json(); if (!Array.isArray(data)) return [];
    const seen=new Set(); const out=[];
    for (const row of data.slice(1)) {
      const url=(row[0]||"").trim(); const status=(row[1]||"").trim();
      if (url&&!seen.has(url)) { seen.add(url); out.push({url,status,source:"wayback"}); }
    }
    return out;
  } catch { return []; }
}
async function fetchCommonCrawl(d,ms=20000) {
  try {
    const idx=await (await proxyFetch("https://index.commoncrawl.org/collinfo.json",8000)).json();
    const latest=idx[0]?.cdx_api||"https://index.commoncrawl.org/CC-MAIN-2024-10-index";
    const r=await proxyFetch(`${latest}?url=*.${d}/*&output=json&fl=url,status&limit=2000`,ms,true);
    const text=await r.text(); const seen=new Set(); const out=[];
    for (const line of text.trim().split("\n")) {
      try { const obj=JSON.parse(line); const url=obj.url?.trim(); if(url&&!seen.has(url)){seen.add(url);out.push({url,status:obj.status||"",source:"commoncrawl"});} } catch {}
    }
    return out;
  } catch { return []; }
}
async function fetchOTX(d,ms=13000) {
  try {
    const r=await proxyFetch(`https://otx.alienvault.com/api/v1/indicators/domain/${d}/url_list?limit=500`,ms);
    const data=await r.json(); const seen=new Set(); const out=[];
    for (const x of (data.url_list||[])) {
      const url=x.url?.trim(); if(url&&!seen.has(url)){seen.add(url);out.push({url,status:"",source:"otx"});}
    }
    return out;
  } catch { return []; }
}
async function fetchURLScanEp(d,ms=13000) {
  try {
    const r=await proxyFetch(`https://urlscan.io/api/v1/search/?q=page.domain:${d}&size=100`,ms);
    const data=await r.json(); const seen=new Set(); const out=[];
    for (const x of (data.results||[])) {
      const url=x?.page?.url?.trim(); if(url&&!seen.has(url)){seen.add(url);out.push({url,status:String(x?.page?.status||""),source:"urlscan"});}
    }
    return out;
  } catch { return []; }
}

/* ── GOOGLE DORK CATEGORIES (12 categories, 60+ dorks) ── */
const DORK_CATEGORIES = [
  {
    id:"sensitive", title:"Sensitive Files & Data", emoji:"📁",
    color:"rgba(248,113,113,0.12)", border:"rgba(248,113,113,0.3)", textColor:"#f87171",
    dorks:[
      {label:"Config / ENV files", query:'site:{domain} ext:env | ext:config | ext:cfg | ext:ini'},
      {label:"SQL dump files", query:'site:{domain} ext:sql | ext:sql.gz | ext:db'},
      {label:"Backup files", query:'site:{domain} ext:bak | ext:backup | ext:old | ext:orig'},
      {label:"Log files", query:'site:{domain} ext:log'},
      {label:"Password files", query:'site:{domain} intitle:"index of" "passwd" | "password"'},
      {label:"Private keys", query:'site:{domain} ext:pem | ext:key | ext:ppk'},
    ]
  },
  {
    id:"login", title:"Login & Admin Panels", emoji:"🔐",
    color:"rgba(139,92,246,0.12)", border:"rgba(139,92,246,0.3)", textColor:"#a78bfa",
    dorks:[
      {label:"Admin panels", query:'site:{domain} inurl:admin | inurl:administrator | inurl:wp-admin'},
      {label:"Login pages", query:'site:{domain} inurl:login | inurl:signin | inurl:auth'},
      {label:"Dashboard pages", query:'site:{domain} inurl:dashboard | inurl:panel | inurl:control'},
      {label:"phpMyAdmin", query:'site:{domain} inurl:phpmyadmin'},
      {label:"CMS login", query:'site:{domain} inurl:wp-login | inurl:joomla | inurl:drupal'},
      {label:"Portal login", query:'site:{domain} inurl:portal | inurl:sso | inurl:idp'},
    ]
  },
  {
    id:"api", title:"APIs & Endpoints", emoji:"🔌",
    color:"rgba(99,179,255,0.12)", border:"rgba(99,179,255,0.3)", textColor:"#63b3ff",
    dorks:[
      {label:"API endpoints", query:'site:{domain} inurl:/api/ | inurl:/v1/ | inurl:/v2/ | inurl:/rest/'},
      {label:"GraphQL", query:'site:{domain} inurl:graphql | inurl:graphiql'},
      {label:"Swagger UI", query:'site:{domain} inurl:swagger | inurl:api-docs | inurl:openapi'},
      {label:'API keys in JS', query:'site:{domain} ext:js "apiKey" | "api_key" | "secret"'},
      {label:"Exposed endpoints", query:'site:{domain} intitle:"index of" "/api"'},
      {label:"Postman collections", query:'site:{domain} ext:json "postman_collection"'},
    ]
  },
  {
    id:"exposed", title:"Exposed Directories", emoji:"📂",
    color:"rgba(251,191,36,0.12)", border:"rgba(251,191,36,0.3)", textColor:"#fbbf24",
    dorks:[
      {label:"Directory listing", query:'site:{domain} intitle:"index of /"'},
      {label:"Git exposed", query:'site:{domain} inurl:/.git'},
      {label:".htaccess exposed", query:'site:{domain} inurl:.htaccess | inurl:.htpasswd'},
      {label:"Exposed uploads", query:'site:{domain} intitle:"index of" "uploads" | "files"'},
      {label:"DS_Store files", query:'site:{domain} inurl:.DS_Store'},
      {label:"SVN exposed", query:'site:{domain} inurl:/.svn/entries'},
    ]
  },
  {
    id:"subdomains", title:"Subdomains & Infrastructure", emoji:"🌐",
    color:"rgba(52,211,153,0.12)", border:"rgba(52,211,153,0.3)", textColor:"#34d399",
    dorks:[
      {label:"Dev/Staging subdomains", query:'site:dev.{domain} | site:staging.{domain} | site:test.{domain}'},
      {label:"Internal subdomains", query:'site:internal.{domain} | site:intranet.{domain} | site:vpn.{domain}'},
      {label:"All subdomains", query:'site:*.{domain}'},
      {label:"Beta subdomains", query:'site:beta.{domain} | site:alpha.{domain} | site:preview.{domain}'},
      {label:"CI/CD subdomains", query:'site:jenkins.{domain} | site:gitlab.{domain} | site:ci.{domain}'},
    ]
  },
  {
    id:"cloud", title:"Cloud & Storage", emoji:"☁️",
    color:"rgba(56,189,248,0.12)", border:"rgba(56,189,248,0.3)", textColor:"#38bdf8",
    dorks:[
      {label:"S3 buckets", query:'site:s3.amazonaws.com "{domain}"'},
      {label:"Azure Blob", query:'site:blob.core.windows.net "{domain}"'},
      {label:"GCP Bucket", query:'site:storage.googleapis.com "{domain}"'},
      {label:"Firebase DB", query:'site:firebaseio.com "{domain}"'},
      {label:"Cloud credentials", query:'site:{domain} "aws_access_key" | "aws_secret" | "AZURE_"'},
      {label:"DigitalOcean Spaces", query:'site:digitaloceanspaces.com "{domain}"'},
    ]
  },
  {
    id:"errors", title:"Error Pages & Debug Info", emoji:"⚠️",
    color:"rgba(251,146,60,0.12)", border:"rgba(251,146,60,0.3)", textColor:"#fb923c",
    dorks:[
      {label:"Stack traces", query:'site:{domain} "stack trace" | "traceback" | "exception"'},
      {label:"PHP errors", query:'site:{domain} "PHP Parse error" | "PHP Warning" | "PHP Fatal"'},
      {label:"SQL errors", query:'site:{domain} "sql syntax" | "mysql_fetch" | "ORA-01"'},
      {label:"Debug mode", query:'site:{domain} "debug=true" | "debug=1" | "APP_DEBUG"'},
      {label:"Server info", query:'site:{domain} intitle:"phpinfo" "PHP Version"'},
      {label:"Django errors", query:'site:{domain} "DisallowedHost" | "Django Version"'},
    ]
  },
  {
    id:"documents", title:"Documents & Reports", emoji:"📄",
    color:"rgba(236,72,153,0.12)", border:"rgba(236,72,153,0.3)", textColor:"#ec4899",
    dorks:[
      {label:"PDF documents", query:'site:{domain} ext:pdf "confidential" | "internal"'},
      {label:"Excel files", query:'site:{domain} ext:xlsx | ext:xls | ext:csv'},
      {label:"Word documents", query:'site:{domain} ext:doc | ext:docx'},
      {label:"Presentation files", query:'site:{domain} ext:ppt | ext:pptx'},
      {label:'Sensitive docs', query:'site:{domain} ext:pdf | ext:doc "password" | "credentials"'},
      {label:"Text files with data", query:'site:{domain} ext:txt "username" | "password" | "token"'},
    ]
  },
  {
    id:"sourcecode", title:"Source Code Exposure", emoji:"💻",
    color:"rgba(99,179,255,0.12)", border:"rgba(99,179,255,0.3)", textColor:"#63b3ff",
    dorks:[
      {label:"Git config exposed", query:'site:{domain} inurl:"/.git/config"'},
      {label:"Package.json exposed", query:'site:{domain} inurl:"package.json" -node_modules'},
      {label:"Dockerfile exposed", query:'site:{domain} inurl:Dockerfile | inurl:docker-compose.yml'},
      {label:"Requirements.txt", query:'site:{domain} inurl:requirements.txt | inurl:Pipfile'},
      {label:"Source maps", query:'site:{domain} ext:map | ext:js.map'},
      {label:"Hardcoded secrets in JS", query:'site:{domain} ext:js "password" | "secret" | "token" | "key"'},
    ]
  },
  {
    id:"juicy", title:"Juicy Extensions", emoji:"🍯",
    color:"rgba(251,146,60,0.12)", border:"rgba(251,146,60,0.3)", textColor:"#fb923c",
    dorks:[
      {label:"PHP with params", query:'site:{domain} ext:php inurl:"?"'},
      {label:"ASP pages", query:'site:{domain} ext:aspx | ext:asp | ext:asmx'},
      {label:"JSP pages", query:'site:{domain} ext:jsp | ext:jspx | ext:do | ext:action'},
      {label:"Old backup files", query:'site:{domain} ext:bak | ext:old | ext:orig | ext:bkp'},
      {label:"XML config files", query:'site:{domain} ext:xml | ext:conf | ext:properties'},
      {label:"YAML config files", query:'site:{domain} ext:yaml | ext:yml "password" | "secret"'},
    ]
  },
  {
    id:"network", title:"Network & IoT Devices", emoji:"📡",
    color:"rgba(167,139,250,0.12)", border:"rgba(167,139,250,0.3)", textColor:"#a78bfa",
    dorks:[
      {label:"Open VPN portals", query:'site:{domain} inurl:"/vpn/" | inurl:"/remote/" | inurl:"/sslvpn/"'},
      {label:"Network monitor pages", query:'site:{domain} intitle:"network status" | intitle:"network monitor"'},
      {label:"Webcam streams", query:'site:{domain} inurl:"/view.shtml" | inurl:"/view/index.shtml"'},
      {label:"Router admin pages", query:'site:{domain} intitle:"router" | intitle:"gateway" inurl:admin'},
      {label:"Printer admin pages", query:'site:{domain} intitle:"printer" | intitle:"HP" inurl:admin'},
      {label:"Kibana / Elasticsearch", query:'site:{domain} inurl:":9200" | inurl:":5601" | inurl:kibana'},
    ]
  },
  {
    id:"cms", title:"CMS & WordPress", emoji:"🔧",
    color:"rgba(52,211,153,0.12)", border:"rgba(52,211,153,0.3)", textColor:"#34d399",
    dorks:[
      {label:"WordPress content", query:'site:{domain} inurl:wp-content | inurl:wp-includes'},
      {label:"WordPress config backup", query:'site:{domain} inurl:wp-config.php | inurl:wp-config.php.bak'},
      {label:"WP REST API users", query:'site:{domain} inurl:/wp-json/wp/v2/users'},
      {label:"Joomla config", query:'site:{domain} inurl:configuration.php | inurl:joomla.conf'},
      {label:"Drupal config", query:'site:{domain} inurl:settings.php | inurl:drupal.conf'},
      {label:"Magento admin", query:'site:{domain} inurl:admin | inurl:backend inurl:magento | inurl:mage'},
    ]
  },
];

const SRC_LABELS = {
  hackertarget:"HackerTarget", urlscan:"URLScan.io", crtsh:"crt.sh", jldc:"JLDC",
  certspotter:"CertSpotter", rapiddns:"RapidDNS", dnsrepo:"DNSRepo",
  wayback_sub:"Wayback", github:"GitHub", shodan:"Shodan", censys:"Censys",
  wayback:"Wayback", commoncrawl:"CommonCrawl", otx:"AlienVault OTX", urlscan_ep:"URLScan.io",
};
const EP_LABELS = {wayback:"Wayback Machine", commoncrawl:"Common Crawl", otx:"AlienVault OTX", urlscan:"URLScan.io"};

const QUOTES = [
  {text:"Recon is 80% of the hack — know your target better than they know themselves.", by:"— The Hacker's Mindset"},
  {text:"The quieter you become, the more you are able to hear.", by:"— Kali Linux motto"},
  {text:"Every system is hackable if you take enough time to understand it.", by:"— Unknown"},
  {text:"Recon is 80% of the hack — know your target better than they know themselves.", by:"— The Hacker's Mindset"},
  {text:"Finding a subdomain is easy. Finding the one that matters is the art.", by:"— Recon Philosophy"},
  {text:"Automation finds quantity. Curiosity finds quality.", by:"— Bug Hunter's Creed"},
  {text:"Most critical vulnerabilities aren't in fancy code — they're in forgotten endpoints.", by:"— OWASP Insight"},
  {text:"One man's forgotten staging server is another man's P1.", by:"— Bug Bounty Folklore"},
  {text:"Reconnaissance is the phase where patience pays dividends in vulnerabilities.", by:"— Bug Bounty Handbook"},
];
const QUOTE = QUOTES[Math.floor(Math.random()*QUOTES.length)];

/* ── APP STATE ── */
const S = {
  tab:"subdomain", drawerOpen:false,
  subDomain:"", subResults:[], subScanning:false, subProgress:0, subShowProgress:false,
  subSrcStatus:{}, subFilter:"", subPage:0,
  subSources:{hackertarget:true,urlscan:true,crtsh:true,jldc:true,certspotter:true,rapiddns:true,dnsrepo:true,wayback_sub:true,github:true,shodan:true,censys:true},
  epDomain:"", epResults:[], epScanning:false, epProgress:0, epShowProgress:false,
  epSrcStatus:{}, epFilter:"", epPage:0, epFilterOpen:false, epChips:new Set(), epStatsDomain:"",
  epSources:{wayback:true,commoncrawl:true,otx:true,urlscan:true},
  dorkDomain:"", dorkSearch:"",
};
const PAGE=100; const EP_PAGE=100;

/* ── CANVAS: Matrix Rain + Particle Network ── */
function initCanvas() {
  const c=document.getElementById("bg-canvas");
  if (!c) return;
  const ctx=c.getContext("2d");
  let W,H,cols,drops,particles;

  function resize() {
    W=c.width=innerWidth; H=c.height=innerHeight;
    cols=Math.floor(W/18);
    drops=Array(cols).fill(null).map(()=>Math.random()*-50);
    if (!particles) particles=[];
    while(particles.length<70) particles.push(mkParticle());
    particles=particles.slice(0,70);
    particles.forEach(p=>{p.x=Math.random()*W;p.y=Math.random()*H;});
  }

  function mkParticle() {
    return {
      x:Math.random()*(W||1920), y:Math.random()*(H||1080),
      vx:(Math.random()-.5)*.35, vy:(Math.random()-.5)*.35,
      r:Math.random()*1.8+.4, alpha:Math.random()*.5+.15,
      col:Math.random()>.6?"139,92,246":"99,179,255",
    };
  }

  resize();
  window.addEventListener("resize",resize);

  const CHARS="01アイウエ0F<>{}∑∆≠ABCDEF01";
  let frame=0;

  function loop() {
    frame++;
    // Fade trail
    ctx.fillStyle="rgba(2,4,8,0.18)";
    ctx.fillRect(0,0,W,H);

    // Matrix rain (subtle)
    ctx.font="13px 'JetBrains Mono',monospace";
    for (let i=0;i<cols;i++) {
      const y=drops[i]*18;
      // Lead char (bright green)
      ctx.fillStyle="rgba(34,211,160,0.75)";
      ctx.fillText(CHARS[Math.floor(Math.random()*CHARS.length)],i*18,y);
      // Second char (dim)
      if (drops[i]>2) {
        ctx.fillStyle="rgba(34,211,160,0.12)";
        ctx.fillText(CHARS[Math.floor(Math.random()*CHARS.length)],i*18,y-18);
      }
      if (y>H&&Math.random()>.975) drops[i]=-Math.floor(Math.random()*20);
      drops[i]+=.45;
    }

    // Particles
    for (const p of particles) {
      p.x+=p.vx; p.y+=p.vy;
      if(p.x<0||p.x>W) p.vx*=-1;
      if(p.y<0||p.y>H) p.vy*=-1;
      const g=ctx.createRadialGradient(p.x,p.y,0,p.x,p.y,p.r*4);
      g.addColorStop(0,`rgba(${p.col},${p.alpha})`);
      g.addColorStop(1,`rgba(${p.col},0)`);
      ctx.beginPath(); ctx.arc(p.x,p.y,p.r*4,0,Math.PI*2);
      ctx.fillStyle=g; ctx.fill();
    }

    // Connections
    for (let i=0;i<particles.length;i++) for(let j=i+1;j<particles.length;j++) {
      const dx=particles[i].x-particles[j].x, dy=particles[i].y-particles[j].y;
      const dist=Math.sqrt(dx*dx+dy*dy);
      if (dist<140) {
        ctx.beginPath(); ctx.moveTo(particles[i].x,particles[i].y); ctx.lineTo(particles[j].x,particles[j].y);
        ctx.strokeStyle=`rgba(99,179,255,${.07*(1-dist/140)})`; ctx.lineWidth=.6; ctx.stroke();
      }
    }
    requestAnimationFrame(loop);
  }
  loop();
}

/* ── TOAST ── */
let toastT;
function showToast(msg,type="success") {
  clearTimeout(toastT);
  const el=document.getElementById("toast");
  const iconEl=document.getElementById("toast-icon");
  const msgEl=document.getElementById("toast-msg");
  if (iconEl) iconEl.textContent=type==="success"?"✓":"✕";
  if (msgEl) msgEl.textContent=msg;
  el.className=`toast show ${type}`;
  toastT=setTimeout(()=>{el.className="toast";},3200);
}

/* ── SVG ICONS ── */
const IC={
  search:`<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>`,
  copy:`<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>`,
  dl:`<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>`,
  filter:`<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/></svg>`,
  extlink:`<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="opacity:.4"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>`,
  github:`<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.3 3.44 9.8 8.21 11.39.6.11.82-.26.82-.58v-2.03c-3.34.72-4.04-1.61-4.04-1.61-.55-1.38-1.34-1.75-1.34-1.75-1.09-.74.08-.73.08-.73 1.2.09 1.84 1.24 1.84 1.24 1.07 1.83 2.81 1.3 3.5 1 .11-.78.42-1.3.76-1.6-2.67-.3-5.47-1.33-5.47-5.93 0-1.31.47-2.38 1.24-3.22-.12-.3-.54-1.52.12-3.18 0 0 1.01-.32 3.3 1.23a11.5 11.5 0 0 1 3-.4c1.02.01 2.04.14 3 .4 2.29-1.55 3.3-1.23 3.3-1.23.66 1.66.24 2.88.12 3.18.77.84 1.24 1.91 1.24 3.22 0 4.61-2.81 5.63-5.48 5.92.43.37.81 1.1.81 2.22v3.29c0 .32.22.7.83.58C20.56 21.8 24 17.3 24 12c0-6.63-5.37-12-12-12z"/></svg>`,
  medium:`<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M13.54 12a6.8 6.8 0 0 1-6.77 6.82A6.8 6.8 0 0 1 0 12a6.8 6.8 0 0 1 6.77-6.82A6.8 6.8 0 0 1 13.54 12zm7.42 0c0 3.54-1.51 6.42-3.38 6.42-1.87 0-3.39-2.88-3.39-6.42s1.52-6.42 3.39-6.42 3.38 2.88 3.38 6.42M24 12c0 3.17-.53 5.75-1.19 5.75-.66 0-1.19-2.58-1.19-5.75s.53-5.75 1.19-5.75C23.47 6.25 24 8.83 24 12z"/></svg>`,
  linkedin:`<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433a2.062 2.062 0 0 1-2.063-2.065 2.064 2.064 0 1 1 2.063 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"/></svg>`,
  x:`<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-4.714-6.231-5.401 6.231H2.748l7.73-8.835L1.254 2.25H8.08l4.259 5.629L18.244 2.25zm-1.161 17.52h1.833L7.084 4.126H5.117L17.083 19.77z"/></svg>`,
  portfolio:`<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="m8 21 4-4 4 4"/><path d="M12 17v4"/></svg>`,
};

/* ── FILTERS ── */
function filteredSub(){
  return S.subResults.filter(r=>!S.subFilter||r.subdomain.includes(S.subFilter.toLowerCase())||r.ip.includes(S.subFilter));
}
function filteredEp(){
  return S.epResults.filter(r=>{
    const q=S.epFilter.toLowerCase();
    if(q&&!r.url.toLowerCase().includes(q)) return false;
    if(S.epChips.has("js")&&!r.url.match(/\.js(\?|$)/)) return false;
    if(S.epChips.has("config")&&!r.url.match(/\.(env|config|cfg|ini|xml|yaml|yml|bak|backup|sql)(\?|$)/i)) return false;
    if(S.epChips.has("redirect")&&!r.url.match(/redirect|return|next|url=/i)) return false;
    if(S.epChips.has("upload")&&!r.url.match(/upload|file|attach/i)) return false;
    if(S.epChips.has("auth")&&!r.url.match(/auth|login|oauth|token|sso/i)) return false;
    if(S.epChips.has("admin")&&!r.url.match(/admin|panel|manage|dashboard/i)) return false;
    if(S.epChips.has("api")&&!r.url.match(/\/api\/|\/v[0-9]+\/|rest|graphql/i)) return false;
    if(S.epChips.has("params")&&!r.url.includes("?")) return false;
    return true;
  });
}

function statusBadgeH(s) {
  const n=parseInt(s);
  if (!n) return `<span style="color:var(--muted);font-size:12px">—</span>`;
  const cls=n>=200&&n<300?"status-2xx":n>=300&&n<400?"status-3xx":n>=400&&n<500?"status-4xx":"status-5xx";
  return `<span class="status-badge ${cls}">${s}</span>`;
}

function buildDork(tmpl) {
  const d=(S.dorkDomain.trim().replace(/^https?:\/\//,"").replace(/\/.*/,""))||"example.com";
  return tmpl.replace(/\{domain\}/g,d);
}

/* ── TABLE ROW HTML ── */
function subRows(list) {
  if (!list.length) return `<tr><td colspan="5"><div class="empty-state"><div class="empty-icon">◎</div><p>Enter a domain above and click <strong>Scan</strong><br/>to begin subdomain discovery.</p></div></td></tr>`;
  const visible=list.slice(0,(S.subPage+1)*PAGE);
  const rem=list.length-(S.subPage+1)*PAGE;
  let out=visible.map((r,i)=>{
    const parts=r.subdomain.split(".");
    const sub=parts.length>2
      ?`<span class="highlight">${parts.slice(0,-2).join(".")}</span>.${parts.slice(-2).join(".")}`
      :`<span class="highlight">${r.subdomain}</span>`;
    const ip=r.ip?`<span class="ip-pill">${r.ip}</span>`:`<span style="color:var(--muted)">—</span>`;
    const st=r.ip?`<span class="status-pill resolved"><span class="status-dot"></span>Resolved</span>`:`<span class="status-pill none"><span class="status-dot"></span>—</span>`;
    return `<tr>
      <td class="td-index">${i+1}</td>
      <td class="td-sub"><a class="sub-link" href="https://${r.subdomain}" target="_blank" rel="noopener">${sub} ${IC.extlink}</a></td>
      <td class="td-ip">${ip}</td>
      <td><span class="source-badge ${r.source}">${SRC_LABELS[r.source]||r.source}</span></td>
      <td>${st}</td>
    </tr>`;
  }).join("");
  if (rem>0) out+=`<tr><td colspan="5" style="padding:14px 0"><button class="show-more-btn" id="sub-more">Show ${Math.min(rem,PAGE)} more (${rem} remaining)</button></td></tr>`;
  return out;
}
function epRows(list) {
  if (!list.length) return `<tr><td colspan="4"><div class="empty-state"><div class="empty-icon">◎</div><p>Enter a domain above and click <strong>Scan</strong><br/>to start endpoint discovery.</p></div></td></tr>`;
  const visible=list.slice(0,(S.epPage+1)*EP_PAGE);
  const rem=list.length-(S.epPage+1)*EP_PAGE;
  let out=visible.map((r,i)=>`<tr>
    <td class="td-index">${i+1}</td>
    <td class="ep-url-cell"><a href="${r.url}" target="_blank" rel="noopener">${r.url}</a></td>
    <td>${statusBadgeH(r.status)}</td>
    <td><span class="source-badge ${r.source}">${SRC_LABELS[r.source]||r.source}</span></td>
  </tr>`).join("");
  if (rem>0) out+=`<tr><td colspan="4" style="padding:14px 0"><button class="show-more-btn" id="ep-more">Show ${Math.min(rem,EP_PAGE)} more (${rem} remaining)</button></td></tr>`;
  return out;
}

/* ── PROGRESS HTML ── */
function progH(status,pct) {
  return `<div class="progress-wrap">
    <div class="progress-header">
      <div class="progress-title"><span class="spinner"></span>Scanning sources…</div>
      <span class="progress-pct">${pct}%</span>
    </div>
    <div class="progress-bar-bg"><div class="progress-bar-fill" style="width:${pct}%"></div></div>
    <div class="source-status">${Object.entries(status).map(([k,v])=>{
      const ex=v.state==="done"?` (${v.count})`:v.state==="error"?" — failed":v.state==="quota"?" — rate limited":"";
      return `<div class="src-item ${v.state}"><div class="src-dot"></div><span>${SRC_LABELS[k]||EP_LABELS[k]||k}${ex}</span></div>`;
    }).join("")}</div>
  </div>`;
}

/* ── DORK GRID HTML ── */
function dorkGrid() {
  const q=S.dorkSearch.toLowerCase();
  const cats=DORK_CATEGORIES.map(c=>({...c,dorks:c.dorks.filter(d=>!q||d.label.toLowerCase().includes(q)||d.query.toLowerCase().includes(q))})).filter(c=>c.dorks.length>0);
  if (!cats.length) return `<div class="empty-state"><div class="empty-icon">🔍</div><p>No dorks match your search.</p></div>`;
  return `<div class="dork-grid">${cats.map(cat=>`
    <div class="dork-category">
      <div class="dork-category-title">
        <span class="dork-cat-emoji" style="background:${cat.color};border:1px solid ${cat.border}">${cat.emoji}</span>
        ${cat.title}
      </div>
      <div class="dork-category-desc">${cat.dorks.length} dorks available</div>
      <div class="dork-items">
        ${cat.dorks.map((d,i)=>`
          <div class="dork-item">
            <div class="dork-item-left">
              <div class="dork-item-label" style="color:${cat.textColor}">${d.label}</div>
              <div class="dork-query" data-cat="${cat.id}" data-i="${i}" title="Click to copy">${buildDork(d.query)}</div>
            </div>
            <div class="dork-btns">
              <button class="dork-run-btn" data-cat="${cat.id}" data-i="${i}">${IC.search} Search</button>
              <button class="dork-copy-btn" data-cat="${cat.id}" data-i="${i}">${IC.copy}</button>
            </div>
          </div>`).join("")}
      </div>
    </div>`).join("")}</div>`;
}

function subSrcToggles() {
  return Object.keys(S.subSources).map(k=>{
    const on=S.subSources[k]; const st=S.subSrcStatus[k];
    const cnt=(st&&st.state==="done"&&st.count!==undefined)?`<span class="toggle-count">${st.count}</span>`:"";
    return `<label class="source-toggle ${on?"active":""}" data-src="${k}"><input type="checkbox" ${on?"checked":""}/><span class="dot"></span>${SRC_LABELS[k]||k}${cnt}</label>`;
  }).join("");
}
function epSrcToggles() {
  return Object.keys(S.epSources).map(k=>{
    const on=S.epSources[k]; const st=S.epSrcStatus[k];
    const cnt=(st&&st.state==="done"&&st.count!==undefined)?`<span class="toggle-count">${st.count}</span>`:"";
    return `<label class="source-toggle ${on?"active":""}" data-src="${k}"><input type="checkbox" ${on?"checked":""}/><span class="dot"></span>${EP_LABELS[k]||k}${cnt}</label>`;
  }).join("");
}
function epFilterMenuH() {
  if (!S.epFilterOpen) return "";
  const groups=[
    {label:"File Types",items:[["js","JS"],["config","Config / Backup"]]},
    {label:"Security",items:[["redirect","Redirect"],["upload","Upload"],["auth","Auth"],["admin","Admin"]]},
    {label:"Discovery",items:[["api","API"],["params","Has Params"]]},
  ];
  return `<div class="ep-filter-menu" id="epfm">
    ${groups.map(g=>`<div class="ep-filter-group">
      <div class="ep-filter-group-label">${g.label}</div>
      <div class="ep-filter-chips">${g.items.map(([k,l])=>`<button class="ep-chip ${S.epChips.has(k)?"active":""}" data-chip="${k}">${l}</button>`).join("")}</div>
    </div>`).join("")}
    <div class="ep-filter-footer"><button class="ep-filter-clear" id="epfc">Clear all</button></div>
  </div>`;
}
function footerH() {
  return `<div class="social-footer"><div class="social-footer-inner">
    <span class="social-brand-name">⚔ Brahmastra</span>
    <div class="social-links">
      <a class="social-link" href="https://github.com/PradyumnTiwareNexus" target="_blank" rel="noopener">${IC.github} GitHub</a>
      <a class="social-link" href="https://pradyumntiwarenexus.medium.com/" target="_blank" rel="noopener">${IC.medium} Medium</a>
      <a class="social-link" href="https://www.linkedin.com/in/pradyumn-tiwarinexus-b270561b1/" target="_blank" rel="noopener">${IC.linkedin} LinkedIn</a>
      <a class="social-link" href="https://x.com/pradyumnTiwari0" target="_blank" rel="noopener">${IC.x} X / Twitter</a>
      <a class="social-link" href="https://github.com/PradyumnTiwareNexus" target="_blank" rel="noopener">${IC.portfolio} Portfolio</a>
    </div>
    <div class="social-copy">© 2026 BrahmastraX · created by pradyumntiwarenexus · Advanced Recon & Dorking Platform</div>
  </div></div>`;
}

/* ── MAIN RENDER ── */
function render() {
  const app=document.getElementById("app");
  const fs=filteredSub(); const fe=filteredEp();
  const subR=S.subResults.filter(r=>r.ip).length;
  const subIP=new Set(S.subResults.filter(r=>r.ip).map(r=>r.ip)).size;
  const subSrc=new Set(S.subResults.map(r=>r.source)).size;
  let html="";

  if (S.tab==="subdomain") {
    html=`
      <div class="hero">
        <h1>BrahmastraX</h1>
        <div class="hero-tagline"><span class="hero-tag">Advanced Recon &amp; Dorking Platform</span></div>
        <div class="hero-tagline" style="margin-top:0">
          <span class="hero-tag">Subdomain Discovery</span><span class="hero-sep">•</span>
          <span class="hero-tag">Endpoint Enumeration</span><span class="hero-sep">•</span>
          <span class="hero-tag">Google Dork Intelligence</span>
        </div>
        <p>BrahmastraX is a powerful bug bounty recon toolkit combining 11 passive intelligence sources with 70+ Google dorks — no install, no setup, runs in your browser.</p>
        <div class="hero-quote">
          <span class="hero-quote-mark">"</span>${QUOTE.text}<span class="hero-quote-mark">"</span>
          <span class="hero-quote-by">${QUOTE.by}</span>
        </div>
      </div>
      <div class="search-card">
        <div class="input-row">
          <div class="input-wrap">
            <span class="input-icon">⌕</span>
            <input class="domain-input" id="sub-inp" type="text" placeholder="e.g. example.com" value="${S.subDomain}" autocomplete="off" spellcheck="false"/>
          </div>
          <button class="scan-btn" id="sub-btn" ${S.subScanning?"disabled":""}>
            <span class="btn-inner">${S.subScanning?`<span class="spinner"></span> Scanning…`:`${IC.search} Scan`}</span>
          </button>
        </div>
        <div class="source-row" id="sub-src-row">${subSrcToggles()}</div>
      </div>
      <div class="stats-row">
        <div class="stat-card"><div class="stat-label">Subdomains</div><div class="stat-value">${S.subResults.length}</div></div>
        <div class="stat-card"><div class="stat-label">Resolved</div><div class="stat-value">${subR}</div></div>
        <div class="stat-card"><div class="stat-label">Sources Hit</div><div class="stat-value">${subSrc}</div></div>
        <div class="stat-card"><div class="stat-label">Unique IPs</div><div class="stat-value">${subIP}</div></div>
      </div>
      ${S.subShowProgress?progH(S.subSrcStatus,S.subProgress):""}
      <div class="table-section">
        <div class="table-header">
          <div class="section-title">Results <span>${fs.length>0?`(${fs.length})`:""}</span></div>
          <div class="table-actions">
            <input class="filter-input" id="sub-flt" type="text" placeholder="Filter results…" value="${S.subFilter}"/>
            <button class="action-btn" id="sub-cp">${IC.copy} Copy</button>
            <button class="action-btn" id="sub-ex">${IC.dl} Export .txt</button>
          </div>
        </div>
        <div class="table-wrap"><table>
          <thead><tr><th>#</th><th>Subdomain</th><th>IP Address</th><th>Source</th><th>Status</th></tr></thead>
          <tbody id="sub-tb">${subRows(fs)}</tbody>
        </table></div>
      </div>`;
  }
  else if (S.tab==="endpoint") {
    const stats=S.epResults.length?`<div class="stats-row">
      <div class="stat-card"><div class="stat-label">Endpoints Found</div><div class="stat-value">${S.epResults.length}</div></div>
      <div class="stat-card"><div class="stat-label">Sources Hit</div><div class="stat-value">${new Set(S.epResults.map(r=>r.source)).size}</div></div>
      <div class="stat-card"><div class="stat-label">Domain</div><div class="stat-value" style="font-size:1rem;word-break:break-all">${S.epStatsDomain||"—"}</div></div>
    </div>`:"";
    html=`
      <div class="hero" style="padding-bottom:32px">
        <h1 style="font-size:clamp(2rem,6vw,4rem)">Endpoint Recon</h1>
        <div class="hero-tagline">
          <span class="hero-tag">Wayback Machine</span><span class="hero-sep">·</span>
          <span class="hero-tag">Common Crawl</span><span class="hero-sep">·</span>
          <span class="hero-tag">AlienVault OTX</span><span class="hero-sep">·</span>
          <span class="hero-tag">URLScan.io</span>
        </div>
        <p>Discover historical endpoints, URLs and paths from passive web archives — no active scanning, no noise.</p>
      </div>
      <div class="search-card">
        <div class="input-row">
          <div class="input-wrap">
            <span class="input-icon">⌕</span>
            <input class="domain-input" id="ep-inp" type="text" placeholder="e.g. example.com" value="${S.epDomain}" autocomplete="off"/>
          </div>
          <button class="scan-btn" id="ep-btn" ${S.epScanning?"disabled":""}>
            <span class="btn-inner">${S.epScanning?`<span class="spinner"></span> Scanning…`:`${IC.search} Scan`}</span>
          </button>
        </div>
        <div class="source-row" id="ep-src-row">${epSrcToggles()}</div>
      </div>
      ${S.epShowProgress?progH(S.epSrcStatus,S.epProgress):""}
      ${stats}
      <div class="table-section">
        <div class="table-header">
          <div class="section-title">Endpoints <span>${fe.length>0?`(${fe.length})`:""}</span></div>
          <div class="table-actions">
            <div class="ep-filter-wrap" id="epfw">
              <button class="action-btn" id="ep-ftb">${IC.filter} Filters ${S.epChips.size?`<span style="background:var(--cyan);color:#000;border-radius:10px;padding:1px 6px;font-size:10px;font-weight:800">${S.epChips.size}</span>`:""}</button>
              ${epFilterMenuH()}
            </div>
            <input class="filter-input" id="ep-flt" style="width:200px" type="text" placeholder="Filter endpoints…" value="${S.epFilter}"/>
            <button class="action-btn" id="ep-cp">${IC.copy} Copy</button>
            <button class="action-btn" id="ep-ex">${IC.dl} Export .txt</button>
          </div>
        </div>
        <div class="table-wrap"><table>
          <thead><tr><th>#</th><th>URL</th><th>Status</th><th>Source</th></tr></thead>
          <tbody id="ep-tb">${epRows(fe)}</tbody>
        </table></div>
      </div>`;
  }
  else {
    html=`
      <div class="hero" style="padding-bottom:32px">
        <h1 style="font-size:clamp(2rem,6vw,4rem)">Google Dork</h1>
        <div class="hero-tagline">
          <span class="hero-tag">12 Categories</span><span class="hero-sep">·</span>
          <span class="hero-tag">70+ Dorks</span><span class="hero-sep">·</span>
          <span class="hero-tag">One-Click Search</span>
        </div>
        <p>Ready-made Google dorks for bug bounty recon. Enter your target, click <strong style="color:var(--cyan)">Search</strong> to run on Google or copy the query.</p>
      </div>
      <div class="dork-search-bar">
        <input class="dork-target-input" id="dk-domain" type="text" placeholder="Target domain (e.g. example.com)" value="${S.dorkDomain}" autocomplete="off"/>
        <input class="dork-search-input" id="dk-search" type="text" placeholder="Search dorks…" value="${S.dorkSearch}"/>
      </div>
      <div id="dork-container">${dorkGrid()}</div>`;
  }

  app.innerHTML=html+footerH();
  bindEvents();
}

/* ── BIND EVENTS ── */
function bindEvents() {
  // Sub tab
  const si=document.getElementById("sub-inp");
  if (si) { si.addEventListener("input",e=>{S.subDomain=e.target.value;}); si.addEventListener("keydown",e=>{if(e.key==="Enter"&&!S.subScanning)startSub();}); }
  document.getElementById("sub-btn")?.addEventListener("click",startSub);
  document.getElementById("sub-flt")?.addEventListener("input",e=>{ S.subFilter=e.target.value; S.subPage=0; partialSubTable(); });
  document.getElementById("sub-cp")?.addEventListener("click",()=>{ if(!S.subResults.length){showToast("Nothing to copy.","error");return;} navigator.clipboard.writeText(S.subResults.map(r=>r.subdomain).join("\n")).then(()=>showToast("Copied to clipboard!","success")); });
  document.getElementById("sub-ex")?.addEventListener("click",()=>{ if(!S.subResults.length){showToast("Nothing to export.","error");return;} exportTxt(S.subResults.map(r=>r.subdomain).join("\n"),`${S.subDomain}_subdomains.txt`); showToast(`Exported ${S.subResults.length} subdomains`,"success"); });
  document.querySelectorAll("#sub-src-row .source-toggle").forEach(el=>{ el.addEventListener("click",()=>{ const k=el.dataset.src; S.subSources[k]=!S.subSources[k]; el.classList.toggle("active",S.subSources[k]); el.querySelector(".dot").style.cssText=S.subSources[k]?"background:var(--green);box-shadow:0 0 8px var(--green)":""; }); });

  // Ep tab
  const ei=document.getElementById("ep-inp");
  if (ei) { ei.addEventListener("input",e=>{S.epDomain=e.target.value;}); ei.addEventListener("keydown",e=>{if(e.key==="Enter"&&!S.epScanning)startEp();}); }
  document.getElementById("ep-btn")?.addEventListener("click",startEp);
  document.getElementById("ep-flt")?.addEventListener("input",e=>{ S.epFilter=e.target.value; S.epPage=0; partialEpTable(); });
  document.getElementById("ep-cp")?.addEventListener("click",()=>{ const f=filteredEp(); if(!f.length){showToast("Nothing to copy.","error");return;} navigator.clipboard.writeText(f.map(r=>r.url).join("\n")).then(()=>showToast("Copied!","success")); });
  document.getElementById("ep-ex")?.addEventListener("click",()=>{ const f=filteredEp(); if(!f.length){showToast("Nothing to export.","error");return;} exportTxt(f.map(r=>r.url).join("\n"),`${S.epDomain}_endpoints.txt`); showToast(`Exported ${f.length} endpoints`,"success"); });
  document.querySelectorAll("#ep-src-row .source-toggle").forEach(el=>{ el.addEventListener("click",()=>{ const k=el.dataset.src; S.epSources[k]=!S.epSources[k]; el.classList.toggle("active",S.epSources[k]); }); });

  // EP filter
  document.getElementById("ep-ftb")?.addEventListener("click",e=>{ e.stopPropagation(); S.epFilterOpen=!S.epFilterOpen; const fw=document.getElementById("epfw"); if(fw){const m=fw.querySelector("#epfm"); if(m)m.remove(); if(S.epFilterOpen)fw.insertAdjacentHTML("beforeend",epFilterMenuH()); bindChips(); } });
  document.addEventListener("click",e=>{ if(S.epFilterOpen&&!e.target.closest("#epfw")){S.epFilterOpen=false;document.getElementById("epfm")?.remove();} });
  bindChips();

  // Dork tab
  document.getElementById("dk-domain")?.addEventListener("input",e=>{ S.dorkDomain=e.target.value; const c=document.getElementById("dork-container"); if(c){c.innerHTML=dorkGrid();bindDork();} });
  document.getElementById("dk-search")?.addEventListener("input",e=>{ S.dorkSearch=e.target.value; const c=document.getElementById("dork-container"); if(c){c.innerHTML=dorkGrid();bindDork();} });
  bindDork();
  bindShowMore();
}

function bindChips() {
  document.querySelectorAll(".ep-chip").forEach(b=>{ b.addEventListener("click",()=>{ const k=b.dataset.chip; S.epChips.has(k)?S.epChips.delete(k):S.epChips.add(k); b.classList.toggle("active",S.epChips.has(k)); partialEpTable(); }); });
  document.getElementById("epfc")?.addEventListener("click",()=>{ S.epChips.clear(); document.querySelectorAll(".ep-chip").forEach(b=>b.classList.remove("active")); partialEpTable(); });
}
function bindShowMore() {
  document.getElementById("sub-more")?.addEventListener("click",()=>{ S.subPage++; partialSubTable(); });
  document.getElementById("ep-more")?.addEventListener("click",()=>{ S.epPage++; partialEpTable(); });
}
function bindDork() {
  document.querySelectorAll(".dork-query").forEach(el=>{ el.addEventListener("click",()=>{ const d=getDorkByIds(el.dataset.cat,el.dataset.i); if(d) navigator.clipboard.writeText(buildDork(d.query)).then(()=>showToast("Copied!","success")); }); });
  document.querySelectorAll(".dork-run-btn").forEach(el=>{ el.addEventListener("click",()=>{ const d=getDorkByIds(el.dataset.cat,el.dataset.i); if(d) window.open(`https://www.google.com/search?q=${encodeURIComponent(buildDork(d.query))}`,"_blank","noopener"); }); });
  document.querySelectorAll(".dork-copy-btn").forEach(el=>{ el.addEventListener("click",()=>{ const d=getDorkByIds(el.dataset.cat,el.dataset.i); if(d) navigator.clipboard.writeText(buildDork(d.query)).then(()=>showToast("Copied!","success")); }); });
}
function getDorkByIds(catId,i) {
  const cat=DORK_CATEGORIES.find(c=>c.id===catId); return cat?cat.dorks[parseInt(i)]:null;
}

/* ── PARTIAL DOM UPDATES ── */
function partialSubTable() { const tb=document.getElementById("sub-tb"); if(tb){tb.innerHTML=subRows(filteredSub());bindShowMore();} }
function partialEpTable() { const tb=document.getElementById("ep-tb"); if(tb){tb.innerHTML=epRows(filteredEp());bindShowMore();} }

function updateSubProgress() {
  const pb=document.querySelector(".progress-bar-fill"); if(pb) pb.style.width=S.subProgress+"%";
  const pct=document.querySelector(".progress-pct"); if(pct) pct.textContent=S.subProgress+"%";
  const ss=document.querySelector(".source-status"); if(ss) ss.innerHTML=Object.entries(S.subSrcStatus).map(([k,v])=>{const ex=v.state==="done"?` (${v.count})`:v.state==="error"?" — failed":v.state==="quota"?" — rate limited":""; return `<div class="src-item ${v.state}"><div class="src-dot"></div><span>${SRC_LABELS[k]||k}${ex}</span></div>`;}).join("");
  const stats=document.querySelectorAll(".stat-card .stat-value");
  if(stats.length>=4){const r=S.subResults.filter(x=>x.ip).length;const ip=new Set(S.subResults.filter(x=>x.ip).map(x=>x.ip)).size;const src=new Set(S.subResults.map(x=>x.source)).size;stats[0].textContent=S.subResults.length;stats[1].textContent=r;stats[2].textContent=src;stats[3].textContent=ip;}
  partialSubTable();
  // Update toggle counts
  document.querySelectorAll("#sub-src-row .source-toggle").forEach(el=>{
    const k=el.dataset.src; const st=S.subSrcStatus[k];
    if(st&&st.state==="done"){let b=el.querySelector(".toggle-count");if(!b){b=document.createElement("span");b.className="toggle-count";el.appendChild(b);}b.textContent=st.count;}
  });
}
function updateEpProgress() {
  const pb=document.querySelector(".progress-bar-fill"); if(pb) pb.style.width=S.epProgress+"%";
  const pct=document.querySelector(".progress-pct"); if(pct) pct.textContent=S.epProgress+"%";
  const ss=document.querySelector(".source-status"); if(ss) ss.innerHTML=Object.entries(S.epSrcStatus).map(([k,v])=>{const ex=v.state==="done"?` (${v.count})`:v.state==="error"?" — failed":"";return `<div class="src-item ${v.state}"><div class="src-dot"></div><span>${EP_LABELS[k]||k}${ex}</span></div>`;}).join("");
  partialEpTable();
}

function exportTxt(content,name) { const a=document.createElement("a"); a.href=URL.createObjectURL(new Blob([content],{type:"text/plain"})); a.download=name; a.click(); }

/* ── SUBDOMAIN SCAN ── */
async function startSub() {
  const domain=S.subDomain.trim().toLowerCase().replace(/^https?:\/\//,"").replace(/\/.*/,"").replace(/\/$/,"");
  if (!domain||!/^[a-z0-9][a-z0-9.\-]*\.[a-z]{2,}$/.test(domain)) { showToast("Enter a valid domain (e.g. example.com)","error"); return; }
  if (!Object.values(S.subSources).some(Boolean)) { showToast("Enable at least one source","error"); return; }
  S.subScanning=true; S.subResults=[]; S.subPage=0; S.subFilter=""; S.subShowProgress=true; S.subProgress=0; S.subSrcStatus={};
  const active=Object.entries(S.subSources).filter(([,v])=>v).map(([k])=>k);
  active.forEach(k=>{S.subSrcStatus[k]={state:"loading"};});
  render(); let done=0;
  function merge(items){const seen=new Set(S.subResults.map(r=>r.subdomain));S.subResults.push(...items.filter(r=>!seen.has(r.subdomain)));}
  function mark(k,state,count=0){S.subSrcStatus[k]={state,count};done++;S.subProgress=Math.round(done/active.length*100);updateSubProgress();}

  await Promise.allSettled(active.map(async k=>{
    try {
      let res=[];
      if(k==="hackertarget") res=await fetchHackerTarget(domain);
      else if(k==="urlscan") res=await fetchURLScan(domain);
      else if(k==="crtsh") res=await fetchCrtSh(domain);
      else if(k==="jldc") res=await fetchJLDC(domain);
      else if(k==="certspotter") res=await fetchCertSpotter(domain);
      else if(k==="rapiddns") res=await fetchRapidDNS(domain);
      else if(k==="dnsrepo") res=await fetchDNSRepo(domain);
      else if(k==="wayback_sub") res=await fetchWaybackSub(domain);
      else if(k==="github") res=await fetchGitHub(domain);
      else if(k==="shodan") res=await fetchShodan(domain);
      else if(k==="censys") res=await fetchCensys(domain);
      merge(res); mark(k,"done",res.length);
    } catch(e) { mark(k,e?.quota?"quota":"error",0); }
  }));
  S.subProgress=100; S.subScanning=false;
  setTimeout(()=>{S.subShowProgress=false;render();},700);
}

/* ── ENDPOINT SCAN ── */
async function startEp() {
  const domain=S.epDomain.trim().toLowerCase().replace(/^https?:\/\//,"").replace(/\/.*/,"");
  if (!domain||!/^[a-z0-9][a-z0-9.\-]*\.[a-z]{2,}$/.test(domain)) { showToast("Enter a valid domain","error"); return; }
  if (!Object.values(S.epSources).some(Boolean)) { showToast("Enable at least one source","error"); return; }
  S.epScanning=true; S.epResults=[]; S.epPage=0; S.epFilter=""; S.epShowProgress=true; S.epProgress=0; S.epSrcStatus={}; S.epStatsDomain=domain; S.epChips=new Set();
  const active=Object.entries(S.epSources).filter(([,v])=>v).map(([k])=>k);
  active.forEach(k=>{S.epSrcStatus[k]={state:"loading"};});
  render(); let done=0;
  function merge(items){const seen=new Set(S.epResults.map(r=>r.url));S.epResults.push(...items.filter(r=>!seen.has(r.url)));}
  function mark(k,state,count=0){S.epSrcStatus[k]={state,count};done++;S.epProgress=Math.round(done/active.length*100);updateEpProgress();}

  await Promise.allSettled(active.map(async k=>{
    try {
      let res=[];
      if(k==="wayback") res=await fetchWayback(domain);
      else if(k==="commoncrawl") res=await fetchCommonCrawl(domain);
      else if(k==="otx") res=await fetchOTX(domain);
      else if(k==="urlscan") res=await fetchURLScanEp(domain);
      merge(res); mark(k,"done",res.length);
    } catch { mark(k,"error",0); }
  }));
  S.epProgress=100; S.epScanning=false;
  setTimeout(()=>{S.epShowProgress=false;render();},700);
}

/* ── NAV ── */
function setTab(tab){
  S.tab=tab; S.drawerOpen=false;
  document.querySelectorAll(".nav-pill").forEach(b=>b.classList.toggle("active",b.dataset.tab===tab));
  document.querySelectorAll(".drawer-nav-item").forEach(b=>b.classList.toggle("active",b.dataset.tab===tab));
  document.getElementById("mobile-drawer").classList.remove("open");
  document.getElementById("hamburger-btn").classList.remove("open");
  render();
}

/* ── INIT ── */
document.addEventListener("DOMContentLoaded",()=>{
  initCanvas();
  document.getElementById("nav-brand").addEventListener("click",()=>setTab("subdomain"));
  document.querySelectorAll(".nav-pill").forEach(b=>b.addEventListener("click",()=>setTab(b.dataset.tab)));
  document.querySelectorAll(".drawer-nav-item").forEach(b=>b.addEventListener("click",()=>setTab(b.dataset.tab)));
  document.getElementById("hamburger-btn").addEventListener("click",()=>{
    S.drawerOpen=!S.drawerOpen;
    document.getElementById("hamburger-btn").classList.toggle("open",S.drawerOpen);
    document.getElementById("mobile-drawer").classList.toggle("open",S.drawerOpen);
  });
  render();
});
