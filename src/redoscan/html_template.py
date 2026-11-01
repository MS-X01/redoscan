"""Self-contained HTML report template for redoscan.

The page embeds the scan result as JSON and renders it client-side, which is
what makes live search, multi-dimensional filtering, grouping (by category /
file / language / severity) and CSV/JSON export possible without a server and
without any external assets: one .html file you can open, email, or attach to
a ticket. Placeholders (``@@NAME@@``) are substituted by ``report.render_html``.
"""

TEMPLATE = r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>redoscan report@@TITLE_SUFFIX@@</title>
<meta name="description" content="redoscan security scan report">
<link rel="icon" href="data:image/svg+xml,@@FAVICON@@">
<style>
:root{
  --bg:#09090a; --panel:#131315; --panel2:#19191c; --border:#27272b; --text:#ececef; --muted:#8e8e96;
  --accent:#ff2d2d; --accent2:#7a0000; --code:#0d0d0f; --shadow:0 8px 30px rgba(0,0,0,.35);
  --critical:#ef4444; --high:#f97316; --medium:#eab308; --low:#38bdf8; --info:#6b7280;
  --ok:#22c55e; color-scheme:dark;
}
:root[data-theme="light"]{
  --bg:#f5f5f7; --panel:#ffffff; --panel2:#f0f0f3; --border:#e2e2e7; --text:#1a1a1d; --muted:#6a6a73;
  --code:#f6f6f8; --shadow:0 8px 30px rgba(20,20,40,.08); color-scheme:light;
}
@media (prefers-color-scheme: light){
  :root:not([data-theme="dark"]){
    --bg:#f5f5f7; --panel:#ffffff; --panel2:#f0f0f3; --border:#e2e2e7; --text:#1a1a1d; --muted:#6a6a73;
    --code:#f6f6f8; --shadow:0 8px 30px rgba(20,20,40,.08); color-scheme:light;
  }
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
  font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
a{color:var(--accent);text-decoration:none} a:hover{text-decoration:underline}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace}
button{font:inherit;color:inherit;cursor:pointer}
.wrap{max-width:1180px;margin:0 auto;padding:0 20px}

/* ---------- banner ---------- */
.banner{position:relative;overflow:hidden;border-bottom:1px solid var(--border);
  background:
    radial-gradient(900px 260px at 12% -10%, rgba(255,45,45,.30), transparent 60%),
    radial-gradient(700px 240px at 100% 120%, rgba(122,0,0,.40), transparent 60%),
    linear-gradient(180deg,#101012,#0a0a0b);}
.banner::before{content:"";position:absolute;inset:0;opacity:.35;
  background-image:linear-gradient(rgba(255,255,255,.05) 1px,transparent 1px),
                   linear-gradient(90deg,rgba(255,255,255,.05) 1px,transparent 1px);
  background-size:34px 34px;mask-image:linear-gradient(180deg,#000 30%,transparent)}
.banner::after{content:"";position:absolute;left:0;right:0;height:2px;top:0;
  background:linear-gradient(90deg,transparent,var(--accent),transparent);
  animation:scan 5s ease-in-out infinite;opacity:.8}
@keyframes scan{0%{top:0}50%{top:calc(100% - 2px)}100%{top:0}}
@media (prefers-reduced-motion: reduce){.banner::after{animation:none}}
.banner-in{position:relative;display:flex;align-items:center;justify-content:space-between;gap:24px;
  padding:34px 0 30px;flex-wrap:wrap;color:#f2f2f4}
.brand{display:flex;align-items:center;gap:18px}
.logo{filter:drop-shadow(0 0 18px rgba(255,45,45,.45))}
.wordmark{font-size:44px;font-weight:800;letter-spacing:-.02em;line-height:1;margin:0;
  background:linear-gradient(90deg,#fff 0%,#ffb3b3 55%,var(--accent) 100%);
  -webkit-background-clip:text;background-clip:text;color:transparent}
.tagline{color:#a9a9b2;margin-top:8px;font-size:14px}
.chips{display:flex;gap:6px;margin-top:12px;flex-wrap:wrap}
.chip-s{font-size:11px;padding:2px 9px;border-radius:999px;border:1px solid rgba(255,255,255,.14);color:#c9c9d0;
  background:rgba(255,255,255,.04)}
.chip-s.ver{border-color:rgba(255,45,45,.5);color:#ff9d9d}
.links{display:flex;gap:10px;flex-wrap:wrap}
.btn{display:inline-flex;align-items:center;gap:8px;padding:9px 15px;border-radius:10px;font-weight:600;font-size:13px;
  border:1px solid rgba(255,255,255,.16);background:rgba(255,255,255,.06);color:#f2f2f4;transition:.15s}
.btn:hover{background:rgba(255,255,255,.12);text-decoration:none;transform:translateY(-1px)}
.btn.primary{background:linear-gradient(180deg,#ff3b3b,#c40000);border-color:#ff5a5a;box-shadow:0 6px 18px rgba(255,0,0,.25)}
.btn svg{width:16px;height:16px;fill:currentColor}

/* ---------- meta + stats ---------- */
.meta{display:flex;gap:18px;flex-wrap:wrap;color:var(--muted);font-size:12.5px;padding:14px 0}
.meta b{color:var(--text);font-weight:600}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:16px}
.stat{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:14px 16px;text-align:left;
  position:relative;overflow:hidden;transition:.15s}
.stat::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--c,var(--border))}
.stat .n{font-size:28px;font-weight:800;line-height:1.1}
.stat .l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.06em}
button.stat:hover{border-color:var(--c,var(--accent));transform:translateY(-1px)}
button.stat.on{border-color:var(--c);box-shadow:0 0 0 1px var(--c) inset}
.panels{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px;margin-bottom:18px}
.panel{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:14px 16px}
.panel h3{margin:0 0 10px;font-size:12px;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);font-weight:600}
.bar{display:grid;grid-template-columns:minmax(110px,46%) 1fr auto;gap:8px;align-items:center;width:100%;
  background:none;border:0;padding:3px 4px;border-radius:6px;text-align:left}
.bar:hover,.bar.on{background:var(--panel2)}
.bar .nm{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:12.5px}
.bar .tr{height:8px;background:var(--panel2);border-radius:99px;overflow:hidden}
.bar .fl{height:100%;border-radius:99px;background:linear-gradient(90deg,var(--accent2),var(--accent))}
.bar .ct{font-size:12px;color:var(--muted);min-width:22px;text-align:right}
.donutwrap{display:flex;align-items:center;gap:16px}
.legend{display:grid;gap:4px;font-size:12.5px}
.legend i{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:7px}

/* ---------- toolbar ---------- */
.toolbar{position:sticky;top:0;z-index:20;background:color-mix(in srgb,var(--bg) 88%,transparent);
  backdrop-filter:blur(10px);border-bottom:1px solid var(--border);padding:10px 0;margin:0 -20px 14px}
.toolbar-in{padding:0 20px;display:flex;flex-direction:column;gap:9px}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.search{flex:1 1 280px;position:relative}
.search input{width:100%;padding:9px 38px 9px 36px;border-radius:10px;border:1px solid var(--border);background:var(--panel);
  color:var(--text);font:inherit;outline:none}
.search input:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(255,45,45,.15)}
.search svg{position:absolute;left:11px;top:50%;transform:translateY(-50%);width:16px;height:16px;fill:var(--muted)}
.search kbd{position:absolute;right:10px;top:50%;transform:translateY(-50%);font-size:11px;color:var(--muted);
  border:1px solid var(--border);border-radius:5px;padding:0 6px;background:var(--panel2)}
select{padding:8px 10px;border-radius:9px;border:1px solid var(--border);background:var(--panel);color:var(--text);font:inherit;max-width:190px}
.seg{display:inline-flex;border:1px solid var(--border);border-radius:9px;overflow:hidden;background:var(--panel)}
.seg button{border:0;background:none;padding:7px 11px;font-size:12.5px;color:var(--muted)}
.seg button.on{background:var(--accent);color:#fff}
.tb{border:1px solid var(--border);background:var(--panel);border-radius:9px;padding:7px 11px;font-size:12.5px}
.tb:hover{border-color:var(--accent)}
.sevchips{display:flex;gap:6px;flex-wrap:wrap}
.sc{border:1px solid var(--border);background:var(--panel);border-radius:999px;padding:4px 11px;font-size:12px;font-weight:600;
  display:inline-flex;gap:6px;align-items:center}
.sc i{width:8px;height:8px;border-radius:50%;background:var(--c)}
.sc.on{border-color:var(--c);background:color-mix(in srgb,var(--c) 16%,var(--panel))}
.count{color:var(--muted);font-size:12.5px;margin-left:auto}
.lbl{color:var(--muted);font-size:12px}

/* ---------- groups + findings ---------- */
.group{background:var(--panel);border:1px solid var(--border);border-radius:12px;margin-bottom:12px;overflow:hidden}
.group>summary{list-style:none;cursor:pointer;display:flex;align-items:center;gap:10px;padding:12px 16px;
  background:var(--panel2);user-select:none}
.group>summary::-webkit-details-marker{display:none}
.group>summary .car{transition:.15s;color:var(--muted);font-size:11px}
.group[open]>summary .car{transform:rotate(90deg)}
.gname{font-weight:700}
.gname.mono{font-weight:600;font-size:13px;word-break:break-all}
.gcount{color:var(--muted);font-size:12px}
.gsev{margin-left:auto;display:flex;gap:5px}
.finding{border-top:1px solid var(--border)}
.finding>summary{list-style:none;cursor:pointer;display:grid;grid-template-columns:auto 1fr;gap:6px 12px;padding:11px 16px;align-items:start}
.finding>summary::-webkit-details-marker{display:none}
.finding>summary:hover{background:var(--panel2)}
.finding[open]>summary{background:var(--panel2)}
.badge{display:inline-block;font-size:11px;font-weight:800;letter-spacing:.04em;padding:2px 8px;border-radius:6px;color:#fff;
  text-transform:uppercase;min-width:66px;text-align:center}
.badge.sm{min-width:0;padding:1px 7px;font-size:10.5px}
.fmain{min-width:0}
.ftop{display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-bottom:3px}
.tag{font-size:11px;padding:1px 8px;border-radius:5px;border:1px solid var(--border);color:var(--muted);background:var(--panel)}
.tag.proven{color:var(--ok);border-color:color-mix(in srgb,var(--ok) 45%,var(--border))}
.tag.heur{color:var(--medium);border-color:color-mix(in srgb,var(--medium) 45%,var(--border))}
.tag a{color:inherit}
.loc{font-size:12px;color:var(--muted);word-break:break-all}
.msg{font-size:13.5px}
.fbody{padding:4px 16px 16px 16px;display:grid;gap:10px}
.fbody h4{margin:0 0 4px;font-size:11px;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);font-weight:600}
pre.code{margin:0;background:var(--code);border:1px solid var(--border);border-radius:9px;padding:10px 12px;overflow:auto;
  font-size:12.5px;white-space:pre-wrap;word-break:break-all;position:relative}
.copy{position:absolute;right:6px;top:6px;font-size:11px;border:1px solid var(--border);background:var(--panel2);
  border-radius:6px;padding:1px 8px;color:var(--muted)}
.copy:hover{color:var(--text);border-color:var(--accent)}
.detail{color:var(--muted);font-size:13px;white-space:pre-wrap}
.dyn{font-size:13px}
mark{background:rgba(255,45,45,.3);color:inherit;border-radius:3px;padding:0 1px}
.empty{text-align:center;color:var(--muted);padding:60px 10px;border:1px dashed var(--border);border-radius:12px}
.empty .big{font-size:34px}
.more{display:block;margin:10px auto 0}
.clean{margin-top:18px}
.clean .row-c{padding:6px 16px;border-top:1px solid var(--border);font-size:12.5px;display:flex;gap:10px}
.okdot{color:var(--ok)}
footer{margin:46px 0 40px;padding-top:20px;border-top:1px solid var(--border);color:var(--muted);font-size:12.5px;
  display:flex;justify-content:space-between;gap:14px;flex-wrap:wrap}
footer a{color:var(--text);font-weight:600}
.toast{position:fixed;bottom:22px;left:50%;transform:translateX(-50%) translateY(20px);background:var(--accent);color:#fff;
  padding:8px 16px;border-radius:9px;opacity:0;transition:.2s;pointer-events:none;z-index:50;font-size:13px}
.toast.show{opacity:1;transform:translateX(-50%)}
noscript{display:block;padding:30px;text-align:center}
@media print{
  .toolbar,.btn,.copy,.more,.banner::after{display:none!important}
  .banner{background:#111!important}
  details{display:block} details>*{display:block}
  body{background:#fff;color:#000}
}
@media (max-width:640px){.wordmark{font-size:32px}.count{margin-left:0;width:100%}}
</style>
</head>
<body>

<header class="banner">
  <div class="wrap banner-in">
    <div class="brand">
      <svg class="logo" width="68" height="68" viewBox="0 0 26 26" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
        <rect width="26" height="26" rx="6" fill="#1D1D1D"/>
        <path d="M13 4 L21 7.5 V13 C21 18 17.5 21.3 13 22.5 C8.5 21.3 5 18 5 13 V7.5 Z" stroke="#FF0000" stroke-width="1.4" fill="rgba(255,0,0,.08)"/>
        <path d="M10 13 L12 15 L16.5 10" stroke="#FF0000" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
      <div>
        <h1 class="wordmark">redoscan</h1>
        <div class="tagline">Find ReDoS-vulnerable regexes &mdash; and prove it. Plus 11 more vulnerability checks.</div>
        <div class="chips">
          <span class="chip-s ver">v@@VERSION@@</span>
          <span class="chip-s">ReDoS</span><span class="chip-s">SQLi</span><span class="chip-s">CMDi</span>
          <span class="chip-s">SSRF</span><span class="chip-s">IDOR</span><span class="chip-s">+ 7 more</span>
        </div>
      </div>
    </div>
    <nav class="links" aria-label="Project links">
      <a class="btn primary" href="https://github.com/MS-X01/redoscan" target="_blank" rel="noopener">
        <svg viewBox="0 0 16 16"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>
        Star on GitHub</a>
      <a class="btn" href="https://github.com/MS-X01" target="_blank" rel="noopener">
        <svg viewBox="0 0 16 16"><path d="M8 8a3 3 0 100-6 3 3 0 000 6zm-5 6a5 5 0 0110 0H3z"/></svg>
        MS-X01</a>
    </nav>
  </div>
</header>

<main class="wrap">
  <div class="meta" id="meta"></div>
  <noscript>This report needs JavaScript for search and filters. The raw data is embedded in the page source.</noscript>
  <section class="stats" id="stats" aria-label="Summary"></section>
  <section class="panels" id="panels" aria-label="Overview"></section>

  <div class="toolbar" id="toolbar">
    <div class="toolbar-in">
      <div class="row">
        <div class="search">
          <svg viewBox="0 0 16 16"><path d="M11.7 10.3a6 6 0 10-1.4 1.4l3.5 3.5 1.4-1.4-3.5-3.5zM6.5 11a4.5 4.5 0 110-9 4.5 4.5 0 010 9z"/></svg>
          <input id="q" type="search" placeholder="Search message, code, file, CWE, category&hellip;" autocomplete="off" spellcheck="false">
          <kbd>/</kbd>
        </div>
        <select id="fCat" aria-label="Category"></select>
        <select id="fLang" aria-label="Language"></select>
        <select id="fConf" aria-label="Confidence">
          <option value="">Any confidence</option>
          <option value="proven">Proven (ReDoS)</option>
          <option value="heuristic">Heuristic</option>
        </select>
        <select id="fFile" aria-label="File"></select>
      </div>
      <div class="row">
        <div class="sevchips" id="sevchips"></div>
        <span class="lbl">Group by</span>
        <div class="seg" id="groupSeg">
          <button data-g="category" class="on">Category</button>
          <button data-g="file">File</button>
          <button data-g="lang">Language</button>
          <button data-g="severity">Severity</button>
          <button data-g="none">None</button>
        </div>
        <select id="sort" aria-label="Sort">
          <option value="severity">Sort: severity</option>
          <option value="file">Sort: file &amp; line</option>
          <option value="category">Sort: category</option>
        </select>
        <button class="tb" id="expand">Expand all</button>
        <button class="tb" id="collapse">Collapse all</button>
        <button class="tb" id="reset">Reset</button>
        <button class="tb" id="expCsv">CSV</button>
        <button class="tb" id="expJson">JSON</button>
        <button class="tb" id="theme" title="Toggle light / dark">Theme</button>
        <span class="count" id="count"></span>
      </div>
    </div>
  </div>

  <div id="list"></div>
  <div id="cleanBox"></div>

  <footer>
    <div>Generated by <a href="https://github.com/MS-X01/redoscan" target="_blank" rel="noopener">redoscan</a> v@@VERSION@@
      &middot; <span id="gen"></span></div>
    <div>Built by <a href="https://github.com/MS-X01" target="_blank" rel="noopener">Mohammad Sadra Naderi (MS-X01)</a>
      &middot; <a href="https://www.linkedin.com/in/zvitox" target="_blank" rel="noopener">LinkedIn</a>
      &middot; <a href="https://zvitox.medium.com" target="_blank" rel="noopener">Medium</a></div>
  </footer>
</main>
<div class="toast" id="toast"></div>

<script id="rs-data" type="application/json">@@DATA@@</script>
<script>
(function(){
"use strict";
var D = JSON.parse(document.getElementById('rs-data').textContent);
var SEV = ["critical","high","medium","low","info"];
var SEVC = {critical:"#ef4444",high:"#f97316",medium:"#eab308",low:"#38bdf8",info:"#6b7280"};
var RANK = {critical:0,high:1,medium:2,low:3,info:4};
var F = D.findings, CLEAN = D.clean || [];
var st = {q:"",sev:{},cat:"",lang:"",conf:"",file:"",group:"category",sort:"severity",limit:400,closed:{},opened:{}};

function $(id){return document.getElementById(id)}
function esc(s){return String(s==null?"":s).replace(/[&<>"']/g,function(c){return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]})}
function reEsc(s){return s.replace(/[.*+?^${}()|[\]\\]/g,"\\$&")}
function hl(s){
  s = String(s==null?"":s);
  var terms = st.q.trim().split(/\s+/).filter(Boolean);
  if(!terms.length) return esc(s);
  var re = new RegExp("("+terms.map(reEsc).join("|")+")","gi");
  return s.split(re).map(function(p,i){return i%2 ? "<mark>"+esc(p)+"</mark>" : esc(p)}).join("");
}
function cweLink(c){
  if(!c) return "";
  return c.replace(/CWE-([\d\/]+)/g,function(_,nums){
    return nums.split("/").map(function(n,i){
      return '<a href="https://cwe.mitre.org/data/definitions/'+n+'.html" target="_blank" rel="noopener">'+(i?"":"CWE-")+n+'</a>';
    }).join("/");
  });
}
function badge(sev,sm){return '<span class="badge'+(sm?' sm':'')+'" style="background:'+SEVC[sev]+'">'+esc(sev)+'</span>'}
function toast(m){var t=$("toast");t.textContent=m;t.classList.add("show");setTimeout(function(){t.classList.remove("show")},1400)}
function count(arr,key){var o={};arr.forEach(function(x){var k=x[key];o[k]=(o[k]||0)+1});return o}
function uniq(arr,key){var o={};arr.forEach(function(x){o[x[key]]=1});return Object.keys(o)}
function nameOf(kind,v){
  if(kind==="category") return D.catLabels[v]||v;
  if(kind==="lang") return D.langLabels[v]||v;
  return v;
}

/* ---------- static header bits ---------- */
$("meta").innerHTML =
  '<span>Target: <b class="mono">'+esc(D.target||"—")+'</b></span>'+
  '<span>'+esc(D.scanned)+'</span>'+
  '<span>Generated: <b>'+esc(D.generated)+'</b></span>';
$("gen").textContent = D.generated;

/* ---------- filtering ---------- */
function activeSev(){return SEV.filter(function(s){return st.sev[s]})}
function matches(f){
  var as = activeSev();
  if(as.length && as.indexOf(f.severity)<0) return false;
  if(st.cat && f.category!==st.cat) return false;
  if(st.lang && f.lang!==st.lang) return false;
  if(st.file && f.file!==st.file) return false;
  if(st.conf && f.conf!==st.conf) return false;
  if(st.q){
    var h = f._h, terms = st.q.toLowerCase().split(/\s+/).filter(Boolean);
    for(var i=0;i<terms.length;i++) if(h.indexOf(terms[i])<0) return false;
  }
  return true;
}
F.forEach(function(f,i){
  f.id = i;
  f._h = [f.message,f.code,f.evidence,f.file,f.cwe,f.kind,f.detail,nameOf("category",f.category),nameOf("lang",f.lang),f.severity,f.conf].join("\n").toLowerCase();
});
function cmp(a,b){
  if(st.sort==="file") return a.file<b.file?-1:a.file>b.file?1:a.line-b.line;
  if(st.sort==="category") return a.category<b.category?-1:a.category>b.category?1:RANK[a.severity]-RANK[b.severity];
  return RANK[a.severity]-RANK[b.severity] || (a.file<b.file?-1:a.file>b.file?1:a.line-b.line);
}
function filtered(){return F.filter(matches).sort(cmp)}

/* ---------- overview (always the full scan; click to filter) ---------- */
function renderStats(){
  var bySev = count(F,"severity");
  var h = '<div class="stat" style="--c:var(--accent)"><div class="n">'+F.length+'</div><div class="l">Findings</div></div>';
  SEV.slice(0,4).forEach(function(s){
    h += '<button class="stat'+(st.sev[s]?' on':'')+'" data-sev="'+s+'" style="--c:'+SEVC[s]+'"><div class="n" style="color:'+SEVC[s]+'">'+(bySev[s]||0)+'</div><div class="l">'+s+'</div></button>';
  });
  h += '<div class="stat" style="--c:var(--ok)"><div class="n">'+uniq(F,"file").length+'</div><div class="l">Files affected</div></div>';
  var proven = F.filter(function(f){return f.conf==="proven"}).length;
  h += '<div class="stat" style="--c:var(--medium)"><div class="n">'+proven+'<span style="font-size:15px;color:var(--muted);font-weight:600"> / '+(F.length-proven)+'</span></div><div class="l">Proven / heuristic</div></div>';
  $("stats").innerHTML = h;
}
function barPanel(title,kind,key,items,max){
  var top = items.slice(0,max||8), mx = top.length?top[0][1]:1;
  var h = '<div class="panel"><h3>'+title+'</h3>';
  top.forEach(function(it){
    var on = st[key]===it[0];
    h += '<button class="bar'+(on?' on':'')+'" data-k="'+key+'" data-v="'+esc(it[0])+'" title="'+esc(nameOf(kind,it[0]))+'"><span class="nm">'+esc(kind==="file"?it[0].split(/[\\\/]/).slice(-1)[0]:nameOf(kind,it[0]))+'</span><span class="tr"><span class="fl" style="display:block;width:'+Math.max(4,Math.round(it[1]/mx*100))+'%"></span></span><span class="ct">'+it[1]+'</span></button>';
  });
  if(!top.length) h += '<div class="lbl">nothing to show</div>';
  return h+'</div>';
}
function sorted(o){return Object.keys(o).map(function(k){return [k,o[k]]}).sort(function(a,b){return b[1]-a[1]})}
function renderPanels(){
  var bySev = count(F,"severity"), tot = F.length||1, acc=0, R=38, C=2*Math.PI*R, segs="", leg="";
  SEV.forEach(function(s){
    var n=bySev[s]||0; if(!n) return;
    var len=n/tot*C;
    segs += '<circle r="'+R+'" cx="50" cy="50" fill="none" stroke="'+SEVC[s]+'" stroke-width="16" stroke-dasharray="'+len+' '+(C-len)+'" stroke-dashoffset="'+(-acc)+'" transform="rotate(-90 50 50)"/>';
    acc+=len; leg += '<div><i style="background:'+SEVC[s]+'"></i>'+s+' <b>'+n+'</b></div>';
  });
  if(!F.length) segs='<circle r="'+R+'" cx="50" cy="50" fill="none" stroke="var(--ok)" stroke-width="16"/>';
  var donut = '<div class="panel"><h3>Severity</h3><div class="donutwrap"><svg width="120" height="120" viewBox="0 0 100 100" role="img" aria-label="Severity breakdown">'+segs+
    '<text x="50" y="55" text-anchor="middle" font-size="18" font-weight="800" fill="currentColor">'+F.length+'</text></svg><div class="legend">'+(leg||'<div>No findings</div>')+'</div></div></div>';
  $("panels").innerHTML = donut +
    barPanel("By category","category","cat",sorted(count(F,"category"))) +
    barPanel("By language","lang","lang",sorted(count(F,"lang"))) +
    barPanel("Top files","file","file",sorted(count(F,"file")),6);
}

/* ---------- selects ---------- */
function fillSelects(){
  function fill(id,first,kind,key){
    var items = sorted(count(F,key)), h='<option value="">'+first+'</option>';
    items.forEach(function(it){h+='<option value="'+esc(it[0])+'">'+esc(kind==="file"?it[0]:nameOf(kind,it[0]))+' ('+it[1]+')</option>'});
    $(id).innerHTML=h;
  }
  fill("fCat","All categories","category","category");
  fill("fLang","All languages","lang","lang");
  fill("fFile","All files","file","file");
  var h=""; SEV.slice(0,4).forEach(function(s){h+='<button class="sc" data-sev="'+s+'" style="--c:'+SEVC[s]+'"><i></i>'+s+'</button>'});
  $("sevchips").innerHTML=h;
}
function syncControls(){
  $("fCat").value=st.cat; $("fLang").value=st.lang; $("fFile").value=st.file; $("fConf").value=st.conf;
  Array.prototype.forEach.call(document.querySelectorAll("#sevchips .sc"),function(b){b.classList.toggle("on",!!st.sev[b.dataset.sev])});
  Array.prototype.forEach.call(document.querySelectorAll("#groupSeg button"),function(b){b.classList.toggle("on",b.dataset.g===st.group)});
  $("sort").value=st.sort; $("q").value=st.q;
}

/* ---------- list ---------- */
function findingHtml(f){
  var open = st.opened[f.id] ? " open" : "";
  var tags = '<span class="tag">'+hl(nameOf("category",f.category))+'</span>';
  if(f.cwe) tags += '<span class="tag">'+cweLink(f.cwe)+'</span>';
  tags += '<span class="tag '+(f.conf==="proven"?"proven":"heur")+'">'+(f.conf==="proven"?"proven":"heuristic")+'</span>';
  tags += '<span class="tag">'+esc(nameOf("lang",f.lang))+'</span>';
  var body = '<div><h4>'+(f.codeLabel==="pattern"?"Regex":"Matched code")+'</h4><pre class="code mono"><button class="copy" data-copy="'+esc(f.code)+'">copy</button>'+hl(f.code)+'</pre></div>';
  if(f.sample) body += '<div><h4>Attack sample</h4><pre class="code mono"><button class="copy" data-copy="'+esc(f.sampleRaw||f.sample)+'">copy</button>'+esc(f.sample)+'</pre></div>';
  if(f.dyn) body += '<div class="dyn"><h4>Dynamic confirmation</h4><b>'+esc(f.dyn.verdict)+'</b> &middot; worst '+Number(f.dyn.worst_seconds||0).toFixed(3)+'s at '+esc(f.dyn.worst_length)+'x'+(f.dyn.poc_repeats?' &middot; PoC: '+esc(f.dyn.poc_repeats)+'&times; the sample unit':'')+'</div>';
  if(f.detail) body += '<div><h4>Details &amp; fix</h4><div class="detail">'+hl(f.detail)+'</div></div>';
  if(f.warnings && f.warnings.length) body += '<div class="detail">note: '+esc(f.warnings.join(" · "))+'</div>';
  return '<details class="finding" data-id="'+f.id+'"'+open+'><summary>'+badge(f.severity)+
    '<div class="fmain"><div class="ftop">'+tags+'</div><div class="msg">'+hl(f.message)+'</div><div class="loc mono">'+hl(f.file)+(f.line?':'+f.line:'')+'</div></div></summary><div class="fbody">'+body+'</div></details>';
}
function groupKey(f){return st.group==="category"?f.category:st.group==="file"?f.file:st.group==="lang"?f.lang:f.severity}
function groupName(k){
  if(st.group==="category") return nameOf("category",k);
  if(st.group==="lang") return nameOf("lang",k);
  if(st.group==="severity") return k.charAt(0).toUpperCase()+k.slice(1);
  return k;
}
function render(){
  var items = filtered();
  $("count").textContent = "Showing "+items.length+" of "+F.length+" finding"+(F.length===1?"":"s");
  syncControls();
  Array.prototype.forEach.call(document.querySelectorAll(".stat[data-sev]"),function(b){b.classList.toggle("on",!!st.sev[b.dataset.sev])});
  Array.prototype.forEach.call(document.querySelectorAll(".bar"),function(b){b.classList.toggle("on",st[b.dataset.k]===b.dataset.v)});
  var out = "";
  if(!F.length){
    out = '<div class="empty"><div class="big">&#10003;</div><b>No issues found.</b><br>Nothing matched at the selected checks and severity.</div>';
  } else if(!items.length){
    out = '<div class="empty"><div class="big">&#8709;</div><b>No findings match these filters.</b><br>Try a different search, or press Reset.</div>';
  } else {
    var budget = st.limit, shown = 0;
    if(st.group==="none"){
      var h=""; items.forEach(function(f){ if(shown<budget){h+=findingHtml(f);shown++} });
      out = '<div class="group"><div>'+h+'</div></div>';
    } else {
      var groups = {}, order = [];
      items.forEach(function(f){var k=groupKey(f); if(!groups[k]){groups[k]=[];order.push(k)} groups[k].push(f)});
      if(st.group==="severity") order.sort(function(a,b){return RANK[a]-RANK[b]});
      else if(st.group!=="file") order.sort(function(a,b){return groups[b].length-groups[a].length});
      else order.sort(function(a,b){var wa=Math.min.apply(null,groups[a].map(function(f){return RANK[f.severity]})),wb=Math.min.apply(null,groups[b].map(function(f){return RANK[f.severity]}));return wa-wb||groups[b].length-groups[a].length||(a<b?-1:1)});
      order.forEach(function(k){
        var g = groups[k], sc = count(g,"severity"), gs="";
        SEV.forEach(function(s){ if(sc[s]) gs += '<span class="badge sm" style="background:'+SEVC[s]+'">'+sc[s]+' '+s+'</span>' });
        var h="";
        g.forEach(function(f){ if(shown<budget){h+=findingHtml(f);shown++} });
        out += '<details class="group" data-gk="'+esc(k)+'"'+(st.closed[st.group+":"+k]?'':' open')+'><summary><span class="car">&#9654;</span>'+
          '<span class="gname'+(st.group==="file"?' mono':'')+'">'+hl(groupName(k))+'</span><span class="gcount">'+g.length+' finding'+(g.length===1?'':'s')+'</span><span class="gsev">'+gs+'</span></summary>'+h+'</details>';
      });
    }
    if(shown<items.length) out += '<button class="tb more" id="more">Show '+Math.min(400,items.length-shown)+' more ('+(items.length-shown)+' hidden)</button>';
  }
  $("list").innerHTML = out;
  renderClean();
}
function renderClean(){
  if(!CLEAN.length){$("cleanBox").innerHTML="";return}
  var rows = CLEAN.slice(0,200).map(function(c){return '<div class="row-c"><span class="okdot">&#10003;</span><span class="mono">'+esc(c.file)+(c.line?':'+c.line:'')+'</span><span class="mono" style="color:var(--muted)">'+esc(c.code)+'</span></div>'}).join("");
  $("cleanBox").innerHTML = '<details class="group clean"><summary><span class="car">&#9654;</span><span class="gname">Clean patterns</span><span class="gcount">'+CLEAN.length+' checked, no issue</span></summary>'+rows+(CLEAN.length>200?'<div class="row-c">&hellip; and '+(CLEAN.length-200)+' more</div>':'')+'</details>';
}

/* ---------- events ---------- */
document.addEventListener("click",function(e){
  var t=e.target.closest("[data-sev],[data-k],[data-copy],#more,#expand,#collapse,#reset,#expCsv,#expJson,#theme,#groupSeg button");
  if(!t) return;
  if(t.dataset.copy!==undefined){
    e.preventDefault(); e.stopPropagation();
    var txt=t.dataset.copy;
    (navigator.clipboard?navigator.clipboard.writeText(txt):Promise.reject()).then(function(){toast("Copied")},function(){
      var ta=document.createElement("textarea");ta.value=txt;document.body.appendChild(ta);ta.select();try{document.execCommand("copy");toast("Copied")}catch(_){}ta.remove()});
    return;
  }
  if(t.dataset.sev){ st.sev[t.dataset.sev]=!st.sev[t.dataset.sev]; render(); return }
  if(t.dataset.k){ st[t.dataset.k]= st[t.dataset.k]===t.dataset.v ? "" : t.dataset.v; render(); return }
  if(t.id==="more"){ st.limit+=400; render(); return }
  if(t.id==="expand"){ Array.prototype.forEach.call(document.querySelectorAll("#list details"),function(d){d.open=true;if(d.dataset.id)st.opened[d.dataset.id]=1}); return }
  if(t.id==="collapse"){ st.opened={}; Array.prototype.forEach.call(document.querySelectorAll("#list .finding"),function(d){d.open=false}); return }
  if(t.id==="reset"){ st.q="";st.sev={};st.cat="";st.lang="";st.file="";st.conf="";st.sort="severity";st.limit=400; render(); return }
  if(t.id==="expCsv"){ exportCsv(); return }
  if(t.id==="expJson"){ exportJson(); return }
  if(t.id==="theme"){ var r=document.documentElement,cur=r.dataset.theme||(matchMedia("(prefers-color-scheme: light)").matches?"light":"dark");r.dataset.theme=cur==="dark"?"light":"dark"; try{localStorage.setItem("redoscan-theme",r.dataset.theme)}catch(_){} return }
  if(t.closest("#groupSeg")){ st.group=t.dataset.g; render(); return }
});
$("list").addEventListener("toggle",function(e){
  var d=e.target; if(!d.dataset) return;
  if(d.dataset.id){ if(d.open) st.opened[d.dataset.id]=1; else delete st.opened[d.dataset.id] }
  else if(d.dataset.gk!==undefined){ var k=st.group+":"+d.dataset.gk; if(d.open) delete st.closed[k]; else st.closed[k]=1 }
},true);
var qt; $("q").addEventListener("input",function(){clearTimeout(qt);var v=this.value;qt=setTimeout(function(){st.q=v;st.limit=400;render()},120)});
[["fCat","cat"],["fLang","lang"],["fFile","file"],["fConf","conf"]].forEach(function(p){$(p[0]).addEventListener("change",function(){st[p[1]]=this.value;render()})});
$("sort").addEventListener("change",function(){st.sort=this.value;render()});
document.addEventListener("keydown",function(e){
  if(e.key==="/" && document.activeElement!==$("q") && !/INPUT|SELECT|TEXTAREA/.test(document.activeElement.tagName)){e.preventDefault();$("q").focus()}
  if(e.key==="Escape" && document.activeElement===$("q")){$("q").value="";st.q="";render();$("q").blur()}
});

/* ---------- export ---------- */
function download(name,mime,text){
  var a=document.createElement("a"); a.href=URL.createObjectURL(new Blob([text],{type:mime})); a.download=name;
  document.body.appendChild(a); a.click(); setTimeout(function(){URL.revokeObjectURL(a.href);a.remove()},500);
}
function exportJson(){
  var items=filtered().map(function(f){var o={};Object.keys(f).forEach(function(k){if(k[0]!=="_"&&k!=="id")o[k]=f[k]});return o});
  download("redoscan-findings.json","application/json",JSON.stringify(items,null,2)); toast("Exported "+items.length+" findings");
}
function exportCsv(){
  var cols=["severity","category","kind","cwe","conf","lang","file","line","message","code"];
  function q(v){v=String(v==null?"":v);return /[",\n]/.test(v)?'"'+v.replace(/"/g,'""')+'"':v}
  var rows=[cols.join(",")].concat(filtered().map(function(f){return cols.map(function(c){return q(f[c])}).join(",")}));
  download("redoscan-findings.csv","text/csv",rows.join("\n")); toast("Exported "+(rows.length-1)+" findings");
}

/* ---------- boot ---------- */
try{var th=localStorage.getItem("redoscan-theme"); if(th) document.documentElement.dataset.theme=th}catch(_){}
fillSelects(); renderStats(); renderPanels(); render();
})();
</script>
</body>
</html>
'''
