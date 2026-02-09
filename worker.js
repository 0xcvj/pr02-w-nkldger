const RATE_LIMIT = 20;
const RATE_WINDOW_SEC = 3600;

function json(body, status, origin) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    },
  });
}

async function rateLimit(ip, env) {
  if (!ip) return true;
  const key = `rl:${ip}`;
  const current = parseInt((await env.RATE.get(key)) || "0", 10);
  if (current >= RATE_LIMIT) return false;
  await env.RATE.put(key, String(current + 1), { expirationTtl: RATE_WINDOW_SEC });
  return true;
}

export default {
  async fetch(request, env) {
    const allowed = new Set(
      (env.ALLOWED_ORIGINS || "")
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean)
    );
    const origin = request.headers.get("Origin") || "";
    if (!allowed.has(origin)) {
      return json({ ok: false, error: "Forbidden" }, 403, "https://inkledger.app");
    }
    const allowOrigin = origin;

    if (request.method === "OPTIONS") {
      return json({ ok: true }, 200, allowOrigin);
    }

    if (request.method !== "POST") {
      return json({ ok: false, error: "Method not allowed" }, 405, allowOrigin);
    }

    const ip = request.headers.get("CF-Connecting-IP") || "";
    const ua = request.headers.get("User-Agent") || "";

    if (!(await rateLimit(ip, env))) {
      return json({ ok: false, error: "Too many requests" }, 429, allowOrigin);
    }

    const body = await request.json().catch(() => null);
    if (!body) return json({ ok: false, error: "Invalid JSON" }, 400, allowOrigin);

    const path = new URL(request.url).pathname;
    if (path !== "/waitlist") {
      return json({ ok: false, error: "Not found" }, 404, allowOrigin);
    }

    const honeypot = String(body.hp || "").trim();
    if (honeypot) {
      return json({ ok: true }, 200, allowOrigin);
    }

    const email = String(body.email || "").trim().toLowerCase();
    const source = String(body.source || "unknown").trim();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return json({ ok: false, error: "Invalid email" }, 400, allowOrigin);
    }

    try {
      await env.DB.prepare(
        "INSERT OR IGNORE INTO waitlist (email, source, ip, ua, created_at) VALUES (?, ?, ?, ?, ?)"
      )
        .bind(email, source, ip, ua, new Date().toISOString())
        .run();
    } catch {
      return json({ ok: false, error: "DB error" }, 500, allowOrigin);
    }

    return json({ ok: true }, 200, allowOrigin);
  },
};
