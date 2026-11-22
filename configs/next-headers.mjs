// Drop-in Next.js production security headers & source-map hardening.
// Usage in next.config.mjs:
//   import { withVibeSecurityHeaders } from "./next-headers.mjs";
//   export default withVibeSecurityHeaders({ reactStrictMode: true });

export const SECURITY_HEADERS = [
  {
    key: "Strict-Transport-Security",
    value: "max-age=63072000; includeSubDomains; preload",
  },
  {
    key: "X-Content-Type-Options",
    value: "nosniff",
  },
  {
    key: "X-Frame-Options",
    value: "DENY",
  },
  {
    key: "Referrer-Policy",
    value: "strict-origin-when-cross-origin",
  },
  {
    key: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=(), payment=()",
  },
  {
    key: "Cross-Origin-Opener-Policy",
    value: "same-origin",
  },
  {
    key: "Cross-Origin-Resource-Policy",
    value: "same-site",
  },
  {
    key: "Content-Security-Policy",
    value: [
      "default-src 'self'",
      "base-uri 'self'",
      "object-src 'none'",
      "frame-ancestors 'none'",
      "img-src 'self' data: https:",
      "style-src 'self' 'unsafe-inline'",
      "script-src 'self'",
      "connect-src 'self' https:",
      "upgrade-insecure-requests",
    ].join("; "),
  },
];

export function withVibeSecurityHeaders(nextConfig = {}) {
  const existingHeaders = nextConfig.headers;
  return {
    ...nextConfig,
    poweredByHeader: false,
    productionBrowserSourceMaps: false,
    async headers() {
      const prior = typeof existingHeaders === "function" ? await existingHeaders() : [];
      return [
        ...prior,
        {
          source: "/:path*",
          headers: SECURITY_HEADERS,
        },
      ];
    },
  };
}
