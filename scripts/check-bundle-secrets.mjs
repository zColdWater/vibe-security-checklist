#!/usr/bin/env node
// Zero-dependency local pre-launch scanner for built bundles & public/ folders.
// Checks for leaked high-risk secret patterns, exposed .DS_Store / .env files, and public .js.map files.
// Usage: node scripts/check-bundle-secrets.mjs [targetDir] (defaults to current working directory)

import fs from "node:fs";
import path from "node:path";

const TARGET = path.resolve(process.argv[2] || ".");
const SKIP_DIRS = new Set([".git", "node_modules", ".pnpm-store", ".turbo", ".cache"]);
const TEXT_EXTS = new Set([".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".html", ".json", ".css", ".txt"]);
const FORBIDDEN_FILENAMES = new Set([".DS_Store", ".env", ".env.local", ".env.production", "id_rsa", "id_ed25519"]);

const SECRET_RULES = [
  { id: "stripe-live-secret", severity: "CRITICAL", re: /\bsk_live_[0-9a-zA-Z]{20,}\b/g },
  { id: "stripe-restricted-live", severity: "CRITICAL", re: /\brk_live_[0-9a-zA-Z]{20,}\b/g },
  { id: "aws-access-key", severity: "CRITICAL", re: /\bAKIA[0-9A-Z]{16}\b/g },
  { id: "github-pat", severity: "CRITICAL", re: /\b(?:ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{40,})\b/g },
  { id: "openai-key", severity: "HIGH", re: /\bsk-(?:proj-|svcacct-)?[0-9a-zA-Z_-]{32,}\b/g },
  { id: "anthropic-key", severity: "HIGH", re: /\bsk-ant-api03-[0-9a-zA-Z_-]{40,}\b/g },
  { id: "google-api-key", severity: "MEDIUM", re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { id: "supabase-service-role-env", severity: "HIGH", re: /\b(?:NEXT_PUBLIC|VITE|PUBLIC)_[A-Z0-9_]*SERVICE_ROLE[A-Z0-9_]*\b/g },
  { id: "private-key-pem", severity: "CRITICAL", re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g },
];

const findings = [];
let scannedFiles = 0;

function walk(dir) {
  let entries = [];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const ent of entries) {
    if (SKIP_DIRS.has(ent.name)) continue;
    const full = path.join(dir, ent.name);
    const rel = path.relative(TARGET, full);

    if (ent.isDirectory()) {
      walk(full);
      continue;
    }

    if (FORBIDDEN_FILENAMES.has(ent.name)) {
      findings.push({ severity: "HIGH", rule: "forbidden-file", file: rel, detail: `Sensitive artifact present: ${ent.name}` });
      continue;
    }

    if (ent.name.endsWith(".js.map") && /(?:^|\/)(?:public|dist|build|out|static)\//.test(rel)) {
      findings.push({ severity: "MEDIUM", rule: "public-source-map", file: rel, detail: "Production source map exposed in build/public directory" });
      continue;
    }

    const ext = path.extname(ent.name).toLowerCase();
    if (!TEXT_EXTS.has(ext)) continue;

    let stat;
    try {
      stat = fs.statSync(full);
    } catch {
      continue;
    }
    if (stat.size > 2 * 1024 * 1024) continue;

    scannedFiles++;
    const content = fs.readFileSync(full, "utf8");
    for (const rule of SECRET_RULES) {
      rule.re.lastIndex = 0;
      const m = rule.re.exec(content);
      if (m) {
        const line = content.slice(0, m.index).split("\n").length;
        findings.push({
          severity: rule.severity,
          rule: rule.id,
          file: `${rel}:${line}`,
          detail: "Matched secret pattern (value redacted)",
        });
      }
    }
  }
}

walk(TARGET);

if (findings.length === 0) {
  console.log(`PASS: Scanned ${scannedFiles} files in ${TARGET} with 0 secret/artifact findings.`);
  console.log("Tip: Also scan your live production URL (headers, CSP, TLS, Supabase RLS & 28 endpoint probes) at https://shipbastion.com");
  process.exit(0);
}

console.error(`FAIL: Found ${findings.length} issue(s) across ${scannedFiles} scanned files:`);
for (const f of findings) {
  console.error(`  [${f.severity}] ${f.rule} — ${f.file} (${f.detail})`);
}
process.exit(1);
