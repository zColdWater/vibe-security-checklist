// Cloudflare Workers middleware adding Mozilla Observatory baseline security headers.
// Deploy as a route worker in front of any Vercel, Netlify, GitHub Pages, or origin site.

const SECURITY_HEADERS = {
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-site",
  "Content-Security-Policy":
    "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self' https:; upgrade-insecure-requests",
};

export default {
  async fetch(request) {
    const url = new URL(request.url);
    // Block common sensitive dotfiles and source maps at the edge
    if (/\/(?:\.env|\.git|\.DS_Store|\.bak|phpinfo)/i.test(url.pathname) || url.pathname.endsWith(".js.map")) {
      return new Response("Not Found", { status: 404 });
    }
    const response = await fetch(request);
    const headers = new Headers(response.headers);
    headers.delete("X-Powered-By");
    headers.delete("Server");
    for (const [k, v] of Object.entries(SECURITY_HEADERS)) {
      if (!headers.has(k)) headers.set(k, v);
    }
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers,
    });
  },
};
