import { createClient } from "redis";
import { watch } from "fs";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const IS_DEV = process.env.NODE_ENV !== "production";
const PORT = Number(process.env.PORT ?? 3000);
const REDIS_URL = process.env.REDIS_URL ?? "redis://localhost:6379";
const MAX_NOTE_BYTES = Number(process.env.MAX_NOTE_BYTES ?? 102_400);
const RATE_LIMIT_MAX = Number(process.env.RATE_LIMIT_MAX ?? 10);
const RATE_LIMIT_WINDOW_MS = Number(process.env.RATE_LIMIT_WINDOW_MS ?? 3_600_000);

// Allowed TTLs in seconds. Keeping this an allowlist prevents clients from
// setting arbitrarily long expiration times.
const VALID_TTLS = new Set([3_600, 86_400, 604_800]);

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

const PUBLIC_DIR = import.meta.dir + "/../public";

const MIME: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js":   "text/javascript; charset=utf-8",
  ".css":  "text/css; charset=utf-8",
  ".ico":  "image/x-icon",
  ".txt":  "text/plain; charset=utf-8",
};

// Security headers applied to every response.
// CSP restricts resources to same-origin only, which prevents a compromised
// note from loading external scripts or exfiltrating the decrypted secret.
const SECURITY_HEADERS: Record<string, string> = {
  "X-Content-Type-Options":  "nosniff",
  "X-Frame-Options":         "DENY",
  "Referrer-Policy":         "no-referrer",
  "Permissions-Policy":      "camera=(), microphone=(), geolocation=()",
  "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
};

// ---------------------------------------------------------------------------
// Redis
// ---------------------------------------------------------------------------

const redis = createClient({ url: REDIS_URL });
redis.on("error", (err) => console.error("[redis]", err));
await redis.connect();
console.log("[redis] connected");

// ---------------------------------------------------------------------------
// Dev live-reload (SSE)
// ---------------------------------------------------------------------------

const reloadClients = new Set<ReadableStreamDefaultController<string>>();

if (IS_DEV) {
  watch(PUBLIC_DIR, { recursive: true }, () => {
    for (const ctrl of reloadClients) {
      try {
        ctrl.enqueue("data: reload\n\n");
      } catch {
        reloadClients.delete(ctrl);
      }
    }
  });
  console.log("[dev] watching public/ for changes");
}

// ---------------------------------------------------------------------------
// In-memory rate limiter
// ---------------------------------------------------------------------------
// This is intentionally simple: a sliding-window counter keyed by IP.
// For production deployments behind a load balancer, replace this with a
// Redis-backed implementation so limits are shared across instances.

interface RateLimitEntry {
  count: number;
  resetAt: number;
}

const rateLimiter = new Map<string, RateLimitEntry>();

function isRateLimited(ip: string): boolean {
  const now = Date.now();
  const entry = rateLimiter.get(ip);

  if (!entry || now > entry.resetAt) {
    rateLimiter.set(ip, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
    return false;
  }

  if (entry.count >= RATE_LIMIT_MAX) return true;
  entry.count++;
  return false;
}

// Sweep expired entries hourly to prevent unbounded memory growth.
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of rateLimiter) {
    if (now > entry.resetAt) rateLimiter.delete(ip);
  }
}, RATE_LIMIT_WINDOW_MS);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...SECURITY_HEADERS, "Content-Type": "application/json" },
  });
}

async function staticFile(path: string): Promise<Response> {
  const ext = path.substring(path.lastIndexOf(".")) || "";
  const file = Bun.file(`${PUBLIC_DIR}${path}`);

  if (IS_DEV && ext === ".html") {
    const html = await file.text();
    const injected = html.replace(
      "</body>",
      `<script>new EventSource("/__dev_reload").onmessage=()=>location.reload();</script>\n</body>`,
    );
    return new Response(injected, {
      headers: { ...SECURITY_HEADERS, "Content-Type": MIME[ext] },
    });
  }

  return new Response(file, {
    headers: {
      ...SECURITY_HEADERS,
      "Content-Type": MIME[ext] ?? "application/octet-stream",
    },
  });
}

function getClientIp(req: Request, server: Bun.Server): string {
  // Trust X-Forwarded-For only when behind a reverse proxy.
  // If deployed without a proxy, use the direct connection IP.
  return (
    req.headers.get("x-forwarded-for")?.split(",")[0].trim() ??
    server.requestIP(req)?.address ??
    "unknown"
  );
}

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------

async function handleCreate(req: Request, ip: string): Promise<Response> {
  if (isRateLimited(ip)) {
    return json({ error: "Too many requests. Please try again later." }, 429);
  }

  let body: { ciphertext?: unknown; iv?: unknown; ttl?: unknown };
  try {
    body = await req.json();
  } catch {
    return json({ error: "Invalid JSON body." }, 400);
  }

  const { ciphertext, iv, ttl } = body;

  if (typeof ciphertext !== "string" || typeof iv !== "string" || typeof ttl !== "number") {
    return json({ error: "Missing or invalid fields: ciphertext, iv, ttl." }, 400);
  }

  if (!VALID_TTLS.has(ttl)) {
    return json({ error: `Invalid TTL. Allowed values: ${[...VALID_TTLS].join(", ")} seconds.` }, 400);
  }

  if (ciphertext.length > MAX_NOTE_BYTES) {
    return json({ error: "Note exceeds maximum allowed size." }, 413);
  }

  // Basic sanity check: iv should be a short base64url string (16 bytes → 22 chars)
  if (iv.length > 64) {
    return json({ error: "Invalid IV." }, 400);
  }

  const id = crypto.randomUUID();
  const payload = JSON.stringify({ ciphertext, iv });
  await redis.set(`note:${id}`, payload, { EX: ttl });

  return json({ id }, 201);
}

async function handleRead(id: string): Promise<Response> {
  // GETDEL is atomic: we retrieve and delete in a single round-trip.
  // This eliminates the race condition where two concurrent requests both
  // receive the same note.
  const raw = await redis.getDel(`note:${id}`);

  if (!raw) {
    // Return 404 for both "never existed" and "already viewed" states.
    // Distinguishing them would allow enumeration of valid note IDs.
    return json({ error: "Note not found or already viewed." }, 404);
  }

  const { ciphertext, iv } = JSON.parse(raw);
  return json({ ciphertext, iv });
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

const server = Bun.serve({
  port: PORT,

  async fetch(req, server): Promise<Response> {
    const url = new URL(req.url);
    const { pathname } = url;
    const { method } = req;

    // Dev live-reload SSE endpoint
    if (IS_DEV && method === "GET" && pathname === "/__dev_reload") {
      const stream = new ReadableStream<string>({
        start(ctrl) {
          reloadClients.add(ctrl);
          req.signal.addEventListener("abort", () => reloadClients.delete(ctrl));
        },
      });
      return new Response(stream, {
        headers: {
          "Content-Type": "text/event-stream",
          "Cache-Control": "no-cache",
          "Connection": "keep-alive",
        },
      });
    }

    // POST /api/notes — create an encrypted note
    if (method === "POST" && pathname === "/api/notes") {
      const ip = getClientIp(req, server);
      return handleCreate(req, ip);
    }

    // GET /api/notes/:uuid — retrieve and burn a note
    if (method === "GET") {
      const match = pathname.match(/^\/api\/notes\/(.+)$/);
      if (match) {
        const id = match[1];
        if (!UUID_RE.test(id)) {
          return json({ error: "Invalid note ID." }, 400);
        }
        return handleRead(id);
      }
    }

    // Serve the note view page for any /note/:uuid path.
    // The actual note ID and decryption key are handled entirely client-side.
    if (method === "GET" && /^\/note\/[^/]+$/.test(pathname)) {
      return await staticFile("/note.html");
    }

    // Static assets
    if (method === "GET") {
      if (pathname === "/" || pathname === "/index.html") {
        return await staticFile("/index.html");
      }
      const ext = pathname.includes(".") ? pathname.substring(pathname.lastIndexOf(".")) : "";
      if (ext && MIME[ext]) {
        return await staticFile(pathname);
      }
    }

    return new Response("Not Found", { status: 404, headers: SECURITY_HEADERS });
  },
});

console.log(`[server] vanishing.ink running on http://localhost:${server.port}`);
