# Vibe-Coded Web App Pre-Launch Security Checklist (2026)

Production-ready security checklist, drop-in configuration templates, `.cursor/rules/security.mdc` guardrails, and a zero-dependency local bundle scanner for **Cursor, Lovable, Bolt, v0, Replit, Next.js, Vercel, Netlify, Cloudflare, and Supabase** web apps.

> **Why this exists:** In our [2026 Empirical Security Study](https://zcoldwater.github.io/launch-audit-reports/vibe-security-2026/) across **55 freshly launched public AI-built web apps** (`6,120+` passive checks via [VibeShield v7.0](https://vibe-checker.appwrite.network)):
> - **74.5% (41/55)** shipped missing **8–9 of 10** Mozilla Observatory security headers (`CSP`, `HSTS`, `XFO`, `XCTO`, `Referrer-Policy`, `Permissions-Policy`, `COOP`, `CORP`, `security.txt`).
> - **20.0% (11/55)** shipped live **Supabase** backends where missing Row Level Security (`RLS`) policies expose tables to anyone with the public anon key.
> - **3.6% (2/55)** leaked a **client-delivered secret or API key** (including a live Stripe secret key, strictly anonymized).
> - **3.6% (2/55)** left `/.DS_Store` publicly reachable on production hosts.

---

## Included Ready-to-Copy Templates (MIT)

| File | What It Fixes |
| --- | --- |
| [`configs/vercel.json`](./configs/vercel.json) | Drop-in production security headers (`HSTS`, `CSP`, `XFO`, `XCTO`, `COOP`, `CORP`, `Permissions-Policy`) for Vercel apps |
| [`configs/next-headers.mjs`](./configs/next-headers.mjs) | Drop-in `next.config.mjs` wrapper (`withVibeSecurityHeaders`) + disables `productionBrowserSourceMaps` and `X-Powered-By` |
| [`configs/netlify-headers`](./configs/netlify-headers) | Copy to `public/_headers` for Netlify & Cloudflare Pages deployments |
| [`configs/supabase-rls-template.sql`](./configs/supabase-rls-template.sql) | SQL audit queries that catch every `public` table missing `RLS` + baseline `auth.uid()` user-isolation policies |
| [`rules/cursor-security.mdc`](./rules/cursor-security.mdc) | Copy into `.cursor/rules/security.mdc` so AI coding agents refuse to leak server secrets or skip Supabase RLS |
| [`scripts/check-bundle-secrets.mjs`](./scripts/check-bundle-secrets.mjs) | Zero-dependency Node.js CLI to scan local build output (`dist/`, `.next/`, `public/`) for secrets, `.DS_Store`, and public `.js.map` files |

---

## Quick Start (60 Seconds)

### 1. Run the local pre-commit / build check
```bash
node scripts/check-bundle-secrets.mjs ./dist
# or for Next.js / Vite static output:
node scripts/check-bundle-secrets.mjs ./public
```

### 2. Audit your live production URL (Zero Install, Free 6-Phase Scan)
Run a passive read-only 6-phase audit (`116` checks across TLS, client JS chunks, 52 secret patterns, Supabase/Firebase probes, 28 sensitive endpoints, and 10 Observatory headers) at:
- **[VibeShield v7.0 Live Scanner](https://vibe-checker.appwrite.network)** (free scan, zero signup; optional **`$2` Launch Special** one-time unlock — was ~~`$9`~~ — reveals exact line locations and tailored 5-platform remediation scripts; or **`$5`** for the [Complete 3-App Suite](https://omnipulse-x402.appwrite.network/go/gumroad/launch-stack), was ~~`$29`~~).

---

## The 6-Part Pre-Launch Security Checklist

### 1. Client Bundle Secret Hygiene
- [ ] Zero private keys (`sk_live_`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `SUPABASE_SERVICE_ROLE_KEY`, webhook secrets) prefixed with `NEXT_PUBLIC_`, `VITE_`, or `PUBLIC_`.
- [ ] All third-party AI, payment, and admin database SDK calls run exclusively inside server routes, Server Actions, or Edge Functions.
- [ ] Production browser source maps are disabled (`productionBrowserSourceMaps: false` in Next.js, `build.sourcemap: false` in Vite) so unminified server logic and internal paths are not shipped publicly.
- [ ] `.cursor/rules/security.mdc` (from [`rules/cursor-security.mdc`](./rules/cursor-security.mdc)) is committed in the repo so future AI prompts follow the same guardrails.

### 2. HTTP Security Headers & Content Security Policy (CSP)
- [ ] `Strict-Transport-Security` (`max-age=63072000; includeSubDomains; preload`) is sent on HTTPS responses.
- [ ] `X-Content-Type-Options: nosniff` and `X-Frame-Options: DENY` (or CSP `frame-ancestors 'none'`) are enabled.
- [ ] `Content-Security-Policy` explicitly sets `object-src 'none'`, `base-uri 'self'`, and avoids wildcard `script-src *` / unnecessary `unsafe-eval`.
- [ ] `Referrer-Policy`, `Permissions-Policy`, and `Cross-Origin-Opener-Policy` are configured (copy [`configs/vercel.json`](./configs/vercel.json), [`configs/next-headers.mjs`](./configs/next-headers.mjs), or [`configs/netlify-headers`](./configs/netlify-headers)).

### 3. Supabase & Firebase Database Access Control
- [ ] Every table in PostgreSQL `public` schema has `rowsecurity = true` (verify with Section 1 of [`configs/supabase-rls-template.sql`](./configs/supabase-rls-template.sql)).
- [ ] Every `SELECT` / `INSERT` / `UPDATE` / `DELETE` policy checks `auth.uid()` and scopes roles (`TO authenticated`) rather than broad `USING (true)`.
- [ ] Storage buckets containing user uploads are private unless explicitly intended for public CDN serving.
- [ ] Billing, entitlement, and role columns are mutated only by verified server webhooks — never from client `supabase.from('users').update(...)` calls.

### 4. Exposed Files, Endpoints & Debug Artifacts
- [ ] No `.env`, `.env.local`, `.git/HEAD`, `.DS_Store`, `.bak`, or SQLite files are reachable over HTTPS.
- [ ] Development/debug endpoints (`/api/debug`, Swagger/OpenAPI with live credentials, GraphQL introspection if not needed publicly) are disabled in production.
- [ ] `/.well-known/security.txt` is published with a real security contact email.

### 5. Auth, Webhooks & Cost-Abuse Rate Limits
- [ ] Every mutating API route verifies the authenticated session server-side rather than trusting a `userId` sent in the JSON body.
- [ ] Payment webhooks (Stripe, Lemon Squeezy, Gumroad, Paddle) validate cryptographic signatures against the raw request body.
- [ ] Every LLM, image-generation, email-sending, or external-API route has per-IP / per-user rate limiting and maximum token/payload bounds to prevent runaway API bills.

### 6. Custom Domain, Email & AI Search Pre-Launch Readiness
- [ ] Before moving off `.vercel.app` or `.lovable.app`, verify domain availability across TLDs and check USPTO Class 009/042 trademarks ([BrandShield v6.2 — 100% Free Checker](https://brand-checker.appwrite.network)).
- [ ] Before sending signup/auth emails, verify SPF (`<=10` DNS lookups), DKIM selectors, DMARC policy (`p=quarantine` or `p=reject`), and DNSBL status ([InboxShield v7.0](https://inbox-checker.appwrite.network)).
- [ ] Publish clean `robots.txt` AI crawler rules, Schema.org JSON-LD, and `/llms.txt` ([CiteReady v6.0](https://citeready-checker.appwrite.network)).

---

## Research & Maintenance

- **Empirical Study:** [State of AI & Vibe-Coded Web App Security (2026) — 55 Live Apps Audited](https://zcoldwater.github.io/launch-audit-reports/vibe-security-2026/)
- **228 SaaS Launch Benchmarks:** [zcoldwater.github.io/launch-audit-reports](https://zcoldwater.github.io/launch-audit-reports/)
- **Maintained by:** OmniForge · Agent Arena Studio (`agentarenastudio@proton.me` · [@agentarenastudi](https://x.com/agentarenastudi))
- **License:** [MIT](./LICENSE) — PRs adding framework configs (Cloudflare Workers, Astro, Remix, SvelteKit, Nginx, Firebase rules) are welcome!
