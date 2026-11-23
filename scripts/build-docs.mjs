import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");
const DOCS = path.join(ROOT, "docs");
const BASE_URL = "https://zcoldwater.github.io/vibe-security-checklist";
const TODAY = "2026-11-23";
const INDEXNOW_KEY = crypto.createHash("sha256").update("omniforge-vibe-security-checklist-v1").digest("hex").slice(0, 32);

const esc = (s) =>
  String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");

const TABS = [
  { id: "vercel", label: "Vercel (vercel.json)", file: "configs/vercel.json" },
  { id: "nextjs", label: "Next.js (next-headers.mjs)", file: "configs/next-headers.mjs" },
  { id: "netlify", label: "Netlify / CF Pages (_headers)", file: "configs/netlify-headers" },
  { id: "cloudflare", label: "Cloudflare Workers", file: "configs/cloudflare-headers.js" },
  { id: "nginx", label: "Nginx", file: "configs/nginx-security.conf" },
  { id: "supabase", label: "Supabase RLS SQL", file: "configs/supabase-rls-template.sql" },
  { id: "firebase", label: "Firebase Rules", file: "configs/firebase-rules-template.rules" },
  { id: "cursor", label: "Cursor Rules (.mdc)", file: "rules/cursor-security.mdc" },
].map((t) => ({
  ...t,
  code: fs.readFileSync(path.join(ROOT, t.file), "utf8").trim(),
}));

const CHECKLIST = [
  "No server secrets (OpenAI, Stripe live, AWS, Supabase service_role) in NEXT_PUBLIC_* or VITE_* variables",
  "Local bundle secret scanner (scripts/check-bundle-secrets.mjs ./dist) passes with 0 findings",
  "All 10 Mozilla Observatory security headers configured (CSP, HSTS preload, X-Frame-Options, COOP, Permissions-Policy)",
  "Production source maps disabled (productionBrowserSourceMaps: false / build.sourcemap: false)",
  "Every public Supabase table has ALTER TABLE ... ENABLE ROW LEVEL SECURITY and strict auth.uid() policies",
  "Firebase / Firestore rules deny default read/write (allow read, write: if false) outside verified auth.uid()",
  "Sensitive dotfiles (/.env, /.git/config, /.DS_Store, /swagger.json) return 404 on production origin",
  "Stripe / Gumroad / webhook endpoints verify cryptographic HMAC signatures against raw request bytes",
  "AI generation and LLM proxy endpoints enforce server-side authentication, per-IP rate limits, and max_tokens",
  "Email domain passes InboxShield SPF <=10 lookups, DKIM alignment, and DMARC policy",
  "Robots.txt and /llms.txt verified on CiteReady so GPTBot, OAI-SearchBot, ClaudeBot, and PerplexityBot can index",
  "Brand name and 78+ TLDs screened for USPTO trademark collisions on BrandShield (100% Free)",
];

const schema = {
  "@context": "https://schema.org",
  "@graph": [
    {
      "@type": "SoftwareApplication",
      name: "Vibe Security Checklist & Pre-Launch Scanner",
      applicationCategory: "SecurityApplication",
      operatingSystem: "Web",
      url: `${BASE_URL}/`,
      description: "MIT open-source pre-launch security checklist, 8 copy-paste production header & RLS configs, local bundle secret scanner, and live VibeShield v7.0 passive web app audit.",
      offers: { "@type": "Offer", price: "0.00", priceCurrency: "USD" },
      publisher: { "@type": "Organization", name: "OmniForge · Agent Arena Studio" },
    },
    {
      "@type": "FAQPage",
      mainEntity: [
        {
          "@type": "Question",
          name: "What security issues do AI-built web apps ship most often in 2026?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "In our empirical 2026 study of 55 freshly launched AI-built web apps (6,120+ VibeShield v7.0 checks), 74.5% shipped missing 8 to 9 of 10 Mozilla Observatory security headers, 20.0% ran live Supabase backends requiring strict RLS checks, and 3.6% leaked sensitive client keys.",
          },
        },
        {
          "@type": "Question",
          name: "Are the configs and local secret scanner free to use commercially?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "Yes. Every config template (Vercel, Next.js, Netlify, Cloudflare Workers, Nginx, Supabase RLS, Firebase, Cursor .mdc) and the zero-dependency bundle secret scanner in zColdWater/vibe-security-checklist are MIT licensed. Live online scanning on VibeShield v7.0 is free with zero signup, and optional Web Pro fix passes are $2 one-time during our Launch Special (was $9).",
          },
        },
      ],
    },
  ],
};

const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Vibe Security Checklist (MIT) — Interactive Pre-Launch Configs &amp; Live 116-Check Scanner</title>
  <meta name="description" content="Open-source MIT pre-launch security checklist for Cursor, Lovable, Bolt, Next.js, Vercel, Netlify, Cloudflare, and Supabase apps. Copy-paste 8 hardened configs and run a live 116-check VibeShield v7.0 scan free." />
  <meta name="robots" content="index,follow" />
  <link rel="canonical" href="${BASE_URL}/" />
  <meta property="og:type" content="website" />
  <meta property="og:title" content="Vibe Security Checklist (MIT) — Pre-Launch Configs &amp; Live Scanner" />
  <meta property="og:description" content="8 copy-paste MIT security configs (Vercel, Next.js, Netlify, Cloudflare, Nginx, Supabase RLS, Firebase, Cursor .mdc) + live 116-check VibeShield v7.0 scanner." />
  <meta property="og:url" content="${BASE_URL}/" />
  <meta property="og:image" content="https://brand-checker.appwrite.network/assets/cover-vibeshield-2usd.png" />
  <meta property="og:image:width" content="1280" />
  <meta property="og:image:height" content="720" />
  <meta name="twitter:card" content="summary_large_image" />
  <meta name="twitter:image" content="https://brand-checker.appwrite.network/assets/cover-vibeshield-2usd.png" />
  <style>
    :root{--bg:#f8fafc;--card:#ffffff;--ink:#0f172a;--ink2:#334155;--mut:#64748b;--bd:#e2e8f0;--brand:#0f766e;--brand2:#115e59;--dark:#0f172a;--ok-bg:#dcfce7;--ok-fg:#166534;--warn-bg:#fef3c7;--warn-fg:#92400e;--bad-bg:#fee2e2;--bad-fg:#991b1b}
    *{box-sizing:border-box}
    body{margin:0;font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,sans-serif;background:var(--bg);color:var(--ink)}
    a{color:var(--brand);text-decoration:none}a:hover{text-decoration:underline}
    .wrap{max-width:1080px;margin:0 auto;padding:0 20px}
    .top{background:#fff;border-bottom:1px solid var(--bd);position:sticky;top:0;z-index:20}
    .nav{display:flex;align-items:center;justify-content:space-between;gap:14px;min-height:60px;flex-wrap:wrap;padding:8px 0}
    .brand{display:inline-flex;align-items:center;gap:10px;font-weight:800;color:var(--ink)}
    .mark{width:28px;height:28px;border-radius:8px;background:linear-gradient(135deg,#0f766e,#0284c7);color:#fff;display:inline-flex;align-items:center;justify-content:center;font-size:12px;font-weight:900}
    .nav-links{display:flex;align-items:center;gap:14px;flex-wrap:wrap;font-size:13.5px;font-weight:600}
    .btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;padding:9px 15px;border-radius:9px;font-weight:700;font-size:13.5px;border:1px solid var(--bd);background:#fff;color:var(--ink);cursor:pointer;text-decoration:none!important}
    .btn:hover{border-color:#94a3b8}
    .btn-pri{background:var(--brand);color:#fff;border-color:var(--brand)}.btn-pri:hover{background:var(--brand2)}
    .btn-dark{background:var(--dark);color:#fff;border-color:var(--dark)}.btn-dark:hover{background:#1e293b}
    .btn-sm{padding:6px 11px;font-size:12.5px}
    .hero{background:linear-gradient(180deg,#ffffff 0%,#f1f5f9 100%);border-bottom:1px solid var(--bd);padding:42px 0 34px}
    .eyebrow{display:inline-block;padding:4px 11px;border-radius:999px;background:#ccfbf1;color:#115e59;font-size:12px;font-weight:700;margin-bottom:12px}
    h1{font-size:clamp(1.7rem,3.3vw,2.45rem);line-height:1.15;margin:0 0 12px;letter-spacing:-.02em}
    h2{font-size:1.35rem;margin:34px 0 12px;letter-spacing:-.01em}
    .lead{color:var(--ink2);font-size:1.02rem;max-width:820px;margin:0 0 20px}
    .acts{display:flex;gap:10px;flex-wrap:wrap}
    main{padding:28px 0 64px}
    .card{background:var(--card);border:1px solid var(--bd);border-radius:14px;padding:20px;margin-bottom:18px;box-shadow:0 1px 2px rgba(15,23,42,.04)}
    .scan-row{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px}
    .scan-in{flex:1;min-width:220px;padding:10px 13px;border:1px solid #cbd5e1;border-radius:9px;font:14px ui-monospace,SFMono-Regular,Menlo,monospace}
    .chips{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px;align-items:center;font-size:12.5px;color:var(--mut)}
    .chip{padding:4px 10px;border-radius:999px;border:1px solid var(--bd);background:#f8fafc;color:var(--ink2);font:12px ui-monospace,SFMono-Regular,Menlo,monospace;cursor:pointer}
    .chip:hover{border-color:var(--brand);color:var(--brand)}
    .res-box{display:none;margin-top:14px;padding:14px;border-radius:10px;background:#f8fafc;border:1px solid var(--bd)}
    .pill{display:inline-block;padding:2px 9px;border-radius:999px;font-size:12px;font-weight:700}
    .p-ok{background:var(--ok-bg);color:var(--ok-fg)}
    .p-warn{background:var(--warn-bg);color:var(--warn-fg)}
    .p-bad{background:var(--bad-bg);color:var(--bad-fg)}
    .p-neutral{background:#e2e8f0;color:#334155}
    .tabs{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px}
    .tab{padding:7px 12px;border-radius:8px;border:1px solid var(--bd);background:#f8fafc;color:var(--ink2);font-size:12.5px;font-weight:600;cursor:pointer}
    .tab.active{background:var(--dark);color:#fff;border-color:var(--dark)}
    .code-head{display:flex;justify-content:space-between;align-items:center;gap:10px;margin-bottom:8px;font-size:13px;color:var(--mut)}
    pre{margin:0;background:#0f172a;color:#e2e8f0;border-radius:10px;padding:16px;overflow-x:auto;font:12.5px/1.55 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
    .chk-list{list-style:none;padding:0;margin:10px 0 0}
    .chk-list li{display:flex;align-items:flex-start;gap:10px;padding:9px 0;border-bottom:1px solid #f1f5f9;font-size:14px;color:var(--ink2)}
    .chk-list li:last-child{border-bottom:0}
    .chk-list input{margin-top:4px;width:16px;height:16px;accent-color:var(--brand);cursor:pointer}
    .cta{background:linear-gradient(135deg,#ecfdf5 0%,#eff6ff 100%);border:1px solid #99f6e4;border-radius:14px;padding:22px;display:flex;justify-content:space-between;align-items:center;gap:18px;flex-wrap:wrap;margin-top:24px}
    .ft{border-top:1px solid var(--bd);background:#fff;padding:24px 0;font-size:13px;color:var(--mut)}
    .ft-row{display:flex;justify-content:space-between;gap:14px;flex-wrap:wrap}
    .ft-links{display:flex;gap:14px;flex-wrap:wrap}
  </style>
  <script type="application/ld+json">${JSON.stringify(schema)}</script>
</head>
<body>
  <header class="top"><div class="wrap nav">
    <a class="brand" href="./"><span class="mark">VS</span><span>Vibe Security Checklist</span></a>
    <nav class="nav-links" aria-label="Primary">
      <a href="#scanner">Live Scanner</a>
      <a href="#configs">8 MIT Configs</a>
      <a href="#checklist">12-Point Checklist</a>
      <a href="https://zcoldwater.github.io/launch-audit-reports/vibe-security-2026/" target="_blank" rel="noopener">2026 Benchmark Study</a>
      <a href="https://github.com/zColdWater/vibe-security-checklist" target="_blank" rel="noopener">GitHub (MIT)</a>
      <a class="btn btn-pri btn-sm" href="https://omnipulse-x402.appwrite.network/go/gumroad/vibeshield" target="_blank" rel="noopener">Launch Special: $2 (was $9)</a>
    </nav>
  </div></header>

  <section class="hero">
    <div class="wrap">
      <span class="eyebrow">MIT Open Source v1.1.0 &middot; 6,120+ Live AI App Audits &middot; Zero Signup</span>
      <h1>Pre-Launch Security Scanner &amp; MIT Configs for AI-Built Web Apps</h1>
      <p class="lead">74.5% of freshly launched Cursor, Lovable, Bolt, and v0 apps miss 8–9 of 10 security headers and 20% run live Supabase backends. Run a live 116-check VibeShield v7.0 scan right here, then grab 8 MIT production configs below.</p>
      <div id="scanner" class="card" style="margin:18px 0 14px;border-color:#99f6e4;box-shadow:0 4px 16px rgba(15,118,110,.08)">
        <form id="vscForm" class="scan-row" style="margin-top:0">
          <input id="vscInput" class="scan-in" type="text" placeholder="https://your-app.vercel.app or yourdomain.com" required maxlength="150" />
          <button id="vscBtn" class="btn btn-pri" type="submit">Scan Live URL Free (116 Checks) &rarr;</button>
        </form>
        <div class="chips">
          <span>1-click live demo:</span>
          <button type="button" class="chip v-chip" data-u="https://supabase.com">supabase.com</button>
          <button type="button" class="chip v-chip" data-u="https://vercel.com">vercel.com</button>
          <button type="button" class="chip v-chip" data-u="https://linear.app">linear.app</button>
          <span style="margin-left:auto"><a href="https://omnipulse-x402.appwrite.network/go/gumroad/vibeshield" target="_blank" rel="noopener" style="font-weight:700">Launch Special: $2 once (was <s>$9</s>)</a> &middot; <a href="https://omnipulse-x402.appwrite.network/go/gumroad/launch-stack" target="_blank" rel="noopener" style="font-weight:700">All 3 Tools $5</a></span>
        </div>
        <div style="margin-top:12px;padding:10px 12px;border-radius:9px;background:#0f172a;color:#e2e8f0;display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;font:12.5px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace">
          <span><span style="color:#5eead4;font-weight:700">Zero-install CLI:</span> <code id="vscCliCmd">curl -fsSL https://vibe-checker.appwrite.network/cli.sh | sh -s -- yoursite.com</code></span>
          <button type="button" class="btn btn-sm" id="copyCliBtn" style="background:#1e293b;color:#f8fafc;border-color:#334155">Copy CLI</button>
        </div>
        <details style="margin-top:10px;font-size:13px;color:var(--ink2)">
          <summary style="cursor:pointer;font-weight:700;color:var(--brand)">Preview what the $2 Launch Special Fix Pack unlocks (was $9 — 14-day refund)</summary>
          <div style="margin-top:8px;padding:10px 12px;border-radius:8px;background:#f8fafc;border:1px solid var(--bd);display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px">
            <div><strong>1. Exact Chunk &amp; Line Evidence</strong><br /><span style="color:var(--mut)">Unmasks exact JS bundle paths, matched key offsets, and offending header directives.</span></div>
            <div><strong>2. Tailored 5-Platform Fix Patches</strong><br /><span style="color:var(--mut)">Ready-to-paste Next.js, Vercel, Cloudflare, Nginx &amp; Supabase RLS diffs tuned to your scan.</span></div>
            <div><strong>3. 50-URL Batch CSV + A4 PDF</strong><br /><span style="color:var(--mut)">Export client-ready A4 security dossiers and audit staging + production in one pass.</span></div>
          </div>
        </details>
        <div id="vscOut" class="res-box"></div>
      </div>
      <div class="acts">
        <a class="btn btn-dark btn-sm" href="https://omnipulse-x402.appwrite.network/go/gumroad/vibeshield" target="_blank" rel="noopener">Unlock Exact Code Fixes — $2 Once (was $9)</a>
        <a class="btn btn-sm" href="#configs">Jump to 8 MIT Configs</a>
        <a class="btn btn-sm" href="#checklist">12-Point Checklist</a>
        <a class="btn btn-sm" href="https://github.com/zColdWater/vibe-security-checklist" target="_blank" rel="noopener">GitHub Repo (MIT)</a>
      </div>
    </div>
  </section>

  <main class="wrap">
    <section id="configs" class="card">
      <h2 style="margin:0 0 6px">2. Copy-Paste Production Security Configs (MIT License)</h2>
      <p style="margin:0 0 14px;color:var(--mut);font-size:13.5px">Drop these directly into your repository to harden security headers, Supabase RLS, Firestore rules, and Cursor AI code generation:</p>
      <div class="tabs" id="cfgTabs">
        ${TABS.map((t, i) => `<button type="button" class="tab${i === 0 ? " active" : ""}" data-tab="${esc(t.id)}">${esc(t.label)}</button>`).join("")}
      </div>
      <div class="code-head">
        <span id="cfgPath"><code>${esc(TABS[0].file)}</code></span>
        <button type="button" class="btn btn-sm" id="copyCfgBtn">Copy Config</button>
      </div>
      <pre id="cfgCode">${esc(TABS[0].code)}</pre>
    </section>

    <section id="checklist" class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap">
        <h2 style="margin:0">3. Interactive 12-Point Pre-Launch Security Checklist</h2>
        <span id="chkProg" class="pill p-neutral">0 / 12 Checked</span>
      </div>
      <ul class="chk-list" id="chkList">
        ${CHECKLIST.map((item, idx) => `<li><input type="checkbox" id="c${idx}" class="chk-box" /><label for="c${idx}" style="cursor:pointer">${esc(item)}</label></li>`).join("")}
      </ul>
    </section>

    <div class="cta">
      <div style="max-width:600px">
        <strong style="font-size:18px;display:block;margin-bottom:6px">Launch Special: Unlock Full Line-Level Fixes for $2 (was <s>$9</s>) or All 3 Tools for $5 (was <s>$29</s>)</strong>
        <span style="color:var(--ink2);font-size:14px">One-time perpetual browser unlock with 14-day refund guarantee (zero recurring monthly fee). Complete Suite unlocks <strong>VibeShield + InboxShield + CiteReady</strong>; <strong>BrandShield</strong> stays 100% Free Forever.</span>
      </div>
      <div style="display:flex;flex-direction:column;gap:8px;min-width:250px">
        <a class="btn btn-dark" href="https://omnipulse-x402.appwrite.network/go/gumroad/vibeshield" target="_blank" rel="noopener">Unlock VibeShield — $2 (was $9)</a>
        <a class="btn btn-pri" href="https://omnipulse-x402.appwrite.network/go/gumroad/launch-stack" target="_blank" rel="noopener">Complete 3-App Suite — $5 (was $29)</a>
      </div>
    </div>
  </main>

  <footer class="ft"><div class="wrap"><div class="ft-row">
    <div><strong>OmniForge &middot; Agent Arena Studio</strong> &middot; MIT Open Source Security Checklist &amp; Diagnostics.</div>
    <div class="ft-links">
      <a href="https://zcoldwater.github.io/launch-audit-reports/tools/" target="_blank" rel="noopener">12 Free Live Tools</a>
      <a href="https://zcoldwater.github.io/launch-audit-reports/vibe-security-2026/" target="_blank" rel="noopener">2026 Study</a>
      <a href="https://omnipulse-x402.appwrite.network/support" target="_blank" rel="noopener">Support</a>
      <a href="https://omnipulse-x402.appwrite.network/refund-policy" target="_blank" rel="noopener">14-Day Refund</a>
      <a href="mailto:agentarenastudio@proton.me">agentarenastudio@proton.me</a>
    </div>
  </div></div></footer>

  <script>
  (function () {
    var CFG = ${JSON.stringify(Object.fromEntries(TABS.map((t) => [t.id, { file: t.file, code: t.code }]))).replace(/<\//g, "<\\/")};
    var cfgPath = document.getElementById("cfgPath");
    var cfgCode = document.getElementById("cfgCode");
    var copyBtn = document.getElementById("copyCfgBtn");
    var currentId = "vercel";

    document.querySelectorAll("#cfgTabs .tab").forEach(function (btn) {
      btn.addEventListener("click", function () {
        currentId = btn.getAttribute("data-tab");
        document.querySelectorAll("#cfgTabs .tab").forEach(function (b) { b.classList.remove("active"); });
        btn.classList.add("active");
        cfgPath.innerHTML = "<code>" + CFG[currentId].file + "</code>";
        cfgCode.textContent = CFG[currentId].code;
      });
    });

    copyBtn.addEventListener("click", function () {
      if (navigator.clipboard) {
        navigator.clipboard.writeText(CFG[currentId].code).then(function () {
          copyBtn.textContent = "Copied!";
          setTimeout(function () { copyBtn.textContent = "Copy Config"; }, 1800);
        });
      }
    });

    var copyCliBtn = document.getElementById("copyCliBtn");
    var vscCliCmd = document.getElementById("vscCliCmd");
    if (copyCliBtn && vscCliCmd) {
      copyCliBtn.addEventListener("click", function () {
        if (navigator.clipboard) {
          navigator.clipboard.writeText(vscCliCmd.textContent).then(function () {
            copyCliBtn.textContent = "Copied!";
            setTimeout(function () { copyCliBtn.textContent = "Copy CLI"; }, 1800);
          });
        }
      });
    }

    var boxes = document.querySelectorAll(".chk-box");
    var prog = document.getElementById("chkProg");
    function updateProg() {
      var n = 0;
      boxes.forEach(function (b) { if (b.checked) n++; });
      prog.textContent = n + " / " + boxes.length + " Checked";
      prog.className = "pill " + (n === boxes.length ? "p-ok" : (n > 0 ? "p-warn" : "p-neutral"));
    }
    boxes.forEach(function (b) { b.addEventListener("change", updateProg); });

    var form = document.getElementById("vscForm");
    var inp = document.getElementById("vscInput");
    var btn = document.getElementById("vscBtn");
    var out = document.getElementById("vscOut");
    function esc(s) { return String(s == null ? "" : s).split("&").join("&amp;").split("<").join("&lt;").split(">").join("&gt;").split('"').join("&quot;"); }

    async function runScan(raw) {
      var v = String(raw || "").trim();
      if (!v) return;
      var u = /^https?:\\/\\//i.test(v) ? v : "https://" + v;
      inp.value = u;
      btn.disabled = true;
      out.style.display = "block";
      out.innerHTML = '<span style="color:var(--mut)">Scanning <strong>' + esc(u) + '</strong> with VibeShield v7.0 (116 passive checks)...</span>';
      try {
        var r = await fetch("https://vibe-checker.appwrite.network/api/free-scan?url=" + encodeURIComponent(u), { headers: { Accept: "application/json" } });
        var d = await r.json().catch(function () { return {}; });
        if (!r.ok || d.ok === false) {
          out.innerHTML = '<span class="pill p-bad">Notice</span> ' + esc(d.error || "Could not scan URL.") + ' <a href="https://vibe-checker.appwrite.network/?url=' + encodeURIComponent(u) + '" target="_blank" rel="noopener" style="margin-left:8px;font-weight:600">Open VibeShield v7.0 &rarr;</a>';
          return;
        }
        var sc = (d.assessment && typeof d.assessment.score === "number") ? d.assessment.score : 0;
        var gr = (d.assessment && d.assessment.grade) || "-";
        var checks = d.checksExecuted || 110;
        var findings = Array.isArray(d.findings) ? d.findings : [];
        var locked = d.lockedFindingsCount || 0;
        var cls = sc >= 80 ? "p-ok" : (sc >= 60 ? "p-warn" : "p-bad");
        if (typeof window.opTrack === "function") window.opTrack("scan");
        var ctxHost = d.hostname || u;
        var ctxUrl = "https://omnipulse-x402.appwrite.network/checkout/vibeshield?domain=" + encodeURIComponent(ctxHost) + "&score=" + encodeURIComponent(sc) + "&issues=" + encodeURIComponent(findings.length);
        var list = findings.length ? '<ul style="margin:10px 0 0;padding-left:18px;font-size:13px;color:var(--ink2)">' + findings.slice(0, 3).map(function (f) {
          var sev = String(f.severity || "INFO").toUpperCase();
          var c2 = (sev === "CRITICAL" || sev === "HIGH") ? "p-bad" : (sev === "MEDIUM" ? "p-warn" : "p-neutral");
          return '<li style="margin:4px 0"><span class="pill ' + c2 + '" style="margin-right:6px;font-size:11px">' + esc(sev) + '</span>' + esc(f.title || f.summary || "Finding detected") + '</li>';
        }).join("") + '</ul>' : '';
        out.innerHTML =
          '<div style="display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap">' +
            '<div><strong>' + esc(ctxHost) + '</strong> &middot; Checks: <strong>' + esc(checks) + '</strong> &middot; Findings: <strong>' + esc(findings.length) + '</strong>' + (locked ? ' (<strong>' + esc(locked) + '</strong> locked fixes)' : '') + '</div>' +
            '<span class="pill ' + cls + '">Score: ' + esc(sc) + '/100 (' + esc(gr) + ')</span>' +
          '</div>' + list +
          '<div style="margin-top:12px;padding-top:10px;border-top:1px solid var(--bd);display:flex;gap:10px;flex-wrap:wrap">' +
            '<a class="btn btn-dark btn-sm" href="' + esc(ctxUrl) + '" target="_blank" rel="noopener">Unlock Exact Fixes for ' + esc(ctxHost) + ' — $2 Launch Special (was $9) &rarr;</a>' +
            '<a class="btn btn-pri btn-sm" href="https://vibe-checker.appwrite.network/?url=' + encodeURIComponent(u) + '" target="_blank" rel="noopener">Inspect Full Trace &rarr;</a>' +
          '</div>';
      } catch (e) {
        out.innerHTML = '<span class="pill p-warn">Notice</span> <a href="https://vibe-checker.appwrite.network/?url=' + encodeURIComponent(u) + '" target="_blank" rel="noopener" style="font-weight:600">Open VibeShield v7.0 directly &rarr;</a>';
      } finally {
        btn.disabled = false;
      }
    }
    form.addEventListener("submit", function (e) { e.preventDefault(); runScan(inp.value); });
    document.querySelectorAll(".v-chip").forEach(function (c) { c.addEventListener("click", function () { runScan(c.getAttribute("data-u")); }); });
    try {
      var qp = new URLSearchParams(window.location.search);
      var autoUrl = qp.get("url") || qp.get("domain");
      if (autoUrl) runScan(autoUrl);
    } catch (e) {}
  })();
  </script>
  <script>
  (function(){
    var E="https://omnipulse-x402.appwrite.network/v1/telemetry",D=document,W=window,R=D.documentElement,G=navigator,S=W.screen,M=Math,N=Date.now;
    var I="vsc_"+N().toString(36)+"_"+M.random().toString(36).slice(2,10),z="",d=0,v=D.hidden?0:N(),m=0,la=0,c={scan:0,outbound:0,paywall:0};
    try{z=Intl.DateTimeFormat().resolvedOptions().timeZone||""}catch(e){}
    function fl(){if(v)d+=M.max(0,N()-v);v=D.hidden?0:N();}
    function us(){m=M.max(m,M.min(100,M.round(M.max(0,W.scrollY)/M.max(1,R.scrollHeight-W.innerHeight)*100)));}
    function tx(ev){fl();us();var b=JSON.stringify({site:"vibeshield",sid:I,event:ev,path:"/vibe-security-checklist",webdriver:!!G.webdriver,screen:S?S.width+"x"+S.height:"0x0",dwellSec:M.round(d/1e3),scrollPct:m,scansRun:c.scan,outboundClicks:c.outbound,paywallClicks:c.paywall,referrer:(D.referrer||"").slice(0,128),tz:z,lang:R.lang||"en"});try{if(!G.sendBeacon||!G.sendBeacon(E,new Blob([b],{type:"text/plain"})))fetch(E,{method:"POST",body:b,keepalive:true}).catch(function(){});}catch(e){}}
    function lv(){fl();v=0;if(N()-la>1000){la=N();tx("leave");}}
    W.opTrack=function(ev){if(ev in c)c[ev]++;tx(ev);};
    W.addEventListener("scroll",us,{passive:true});D.addEventListener("visibilitychange",function(){if(D.hidden)lv();else v=N();});W.addEventListener("pagehide",lv);
    D.addEventListener("click",function(e){var a=e.target&&e.target.closest?e.target.closest("a[href]"):null;if(!a)return;var h=a.getAttribute("href")||"";if(h.indexOf("/go/gumroad")!==-1||h.indexOf("/checkout/")!==-1)W.opTrack("paywall");else if(h.indexOf("appwrite.network")!==-1)W.opTrack("outbound");});
    tx("pageview");
  })();
  </script>
</body>
</html>`;

fs.mkdirSync(DOCS, { recursive: true });
fs.writeFileSync(path.join(DOCS, "index.html"), html);
fs.writeFileSync(path.join(DOCS, "robots.txt"), `User-agent: *\nAllow: /\n\nUser-agent: GPTBot\nAllow: /\n\nUser-agent: OAI-SearchBot\nAllow: /\n\nUser-agent: ClaudeBot\nAllow: /\n\nUser-agent: PerplexityBot\nAllow: /\n\nSitemap: ${BASE_URL}/sitemap.xml\n`);
fs.writeFileSync(path.join(DOCS, "sitemap.xml"), `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n  <url><loc>${BASE_URL}/</loc><lastmod>${TODAY}</lastmod><changefreq>weekly</changefreq><priority>1.0</priority></url>\n  <url><loc>${BASE_URL}/llms.txt</loc><lastmod>${TODAY}</lastmod><changefreq>weekly</changefreq><priority>0.8</priority></url>\n</urlset>\n`);
fs.writeFileSync(path.join(DOCS, "llms.txt"), `# Vibe Security Checklist (MIT) — Pre-Launch Hardening & Live Scanner\n\n> Open-source MIT pre-launch security checklist, 8 copy-paste production configs (Vercel, Next.js, Netlify, Cloudflare Workers, Nginx, Supabase RLS, Firebase Rules, Cursor .mdc), zero-dependency local bundle secret scanner, and live VibeShield v7.0 passive web app audit.\n\n- Interactive Checklist & Live Scanner: ${BASE_URL}/\n- GitHub Repository (MIT): https://github.com/zColdWater/vibe-security-checklist\n- 2026 Empirical Benchmark Study (55 Live AI Apps): https://zcoldwater.github.io/launch-audit-reports/vibe-security-2026/\n- VibeShield v7.0 ($2 Launch Special, was $9): https://vibe-checker.appwrite.network\n- OmniForge Complete Suite ($5 Launch Special, was $29): https://omnipulse-x402.appwrite.network/go/gumroad/launch-stack\n`);
fs.writeFileSync(path.join(DOCS, `${INDEXNOW_KEY}.txt`), INDEXNOW_KEY);
console.log(`Built docs/index.html (${html.length} B), IndexNow key: ${INDEXNOW_KEY}`);
