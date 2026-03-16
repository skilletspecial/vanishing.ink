# vanishing.ink

Self-destructing, end-to-end encrypted secret sharing. Share passwords, API
keys, and sensitive strings via a one-time link. The server never sees
plaintext. Notes are destroyed after a single view or on expiration.

---

## How it works

### 1. Creating a note

1. You type or paste a secret into the browser.
2. The browser generates a fresh 256-bit AES-GCM key and a random 96-bit IV
   using the [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API).
3. The plaintext is encrypted entirely in-browser. Only the ciphertext and IV
   are sent to the server.
4. The server stores `{ ciphertext, iv }` in Redis under a UUID key with the
   requested TTL.
5. The browser constructs a share link:
   ```
   https://yourhost.com/note/<uuid>#<base64url-key>
   ```

### 2. Opening a note

1. The browser parses the UUID from the URL path and the key from the
   [fragment (`#`)](https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/Identifying_resources_on_the_Web#fragment).
2. It calls `GET /api/notes/<uuid>`. The server performs an atomic `GETDEL` on
   Redis — fetch and delete in a single command — and returns the ciphertext.
3. The browser decrypts the ciphertext using the key from the fragment.
4. The plaintext is displayed. The link is now dead.

### Why the fragment?

HTTP clients (browsers, proxies, CDNs, server logs) never include the URL
fragment in outgoing requests. Placing the decryption key in the fragment means
the key physically cannot reach the server under normal browser behaviour. This
is the same technique used by
[PrivateBin](https://github.com/PrivateBin/PrivateBin) and others.

### Zero-knowledge guarantee

The server stores only ciphertext. A full database dump, a malicious operator,
or a subpoena reveals only unintelligible bytes. Without the key (which only
ever lived in the URL), the data is unrecoverable.

---

## Threat model

### Protected against
- Server-side breach (database dump, compromised host)
- Network interception (TLS covers the ciphertext in transit)
- Operator / hosting provider snooping
- Passive log analysis (key is in the fragment, never logged)
- Replay after expiry (TTL enforced server-side)
- Concurrent reads of the same note (`GETDEL` is atomic)

### Not protected against
- Malware or keyloggers on the sender's or recipient's machine
- Someone watching the screen when the note is displayed
- A compromised browser or browser extension
- The URL being forwarded to an unintended recipient
  — treat the link itself as the secret

---

## Design decisions

### AES-256-GCM

GCM is an authenticated encryption mode: it provides both confidentiality
(the ciphertext reveals nothing about the plaintext) and integrity (any
modification to the ciphertext will cause decryption to fail with an
explicit error). This means a tampered ciphertext in the database is
detected client-side at view time rather than silently decrypting to garbage.

### UUID v4 for note IDs

UUIDs are 128 bits of randomness, making brute-force enumeration of note IDs
computationally infeasible. Short slugs (e.g. 6 characters) would require only
~56 million guesses to cover the space, which is trivially automatable.

### Redis with TTL

Redis has native key expiration (`EX` option on `SET`). This means expiry is
enforced by the database itself — no cron job, no cleanup worker, no drift.
Redis is also optimised for the access pattern here: every note is written
once, read at most once, and then gone.

Redis is configured with AOF (append-only file) persistence so that notes
survive a Redis restart. Notes still self-destruct on schedule via TTL; AOF
only prevents accidental data loss during a restart.

### Atomic delete-on-read (`GETDEL`)

The `GETDEL` command retrieves a value and deletes it in a single atomic
operation. This closes the race condition where two simultaneous requests
could both receive the same note if a `GET` + `DEL` were used as separate
commands.

### Bun

Bun is used as the runtime because it handles TypeScript natively (no
transpilation step), ships a fast built-in HTTP server, and produces a
self-contained process that is easy to containerise. The application has no
framework dependency; the server is ~100 lines of plain `Bun.serve`.

### Vanilla JS, no build step

The frontend has no framework, no bundler, and no build step. The static files
are served as-is. This keeps the attack surface small, makes the code auditable
by anyone, and removes the entire class of supply-chain vulnerabilities that
come with a large `node_modules` tree on the frontend.

### Security headers

Every response includes:

| Header | Value | Purpose |
|--------|-------|---------|
| `Content-Security-Policy` | `default-src 'self'; frame-ancestors 'none'` | Prevents loading external scripts; blocks framing |
| `X-Content-Type-Options` | `nosniff` | Prevents MIME-type sniffing attacks |
| `X-Frame-Options` | `DENY` | Belt-and-suspenders framing protection |
| `Referrer-Policy` | `no-referrer` | Prevents the fragment leaking via the `Referer` header if the page links out |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=()` | Disables unnecessary browser features |

### Fragment removal from browser history

After decrypting the note, `history.replaceState` rewrites the address bar to
remove the `#key` fragment. This prevents the key from persisting in browser
history, where it could be extracted by a later attacker with physical access
to the machine.

---

## Getting started

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/) and
  [Docker Compose](https://docs.docker.com/compose/)

### Run with Docker Compose

```bash
git clone https://github.com/yourname/vanishing.ink
cd vanishing.ink
cp .env.example .env
docker compose up --build
```

The app will be available at `http://localhost:3000`.

### Run locally (without Docker)

Requires [Bun](https://bun.sh) ≥ 1.0 and a running Redis instance.

```bash
bun install
cp .env.example .env
# Edit .env to point REDIS_URL at your Redis instance
bun run dev
```

---

## Configuration

All configuration is via environment variables. See `.env.example` for
defaults.

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3000` | HTTP port |
| `REDIS_URL` | `redis://localhost:6379` | Redis connection string |
| `MAX_NOTE_BYTES` | `102400` | Max ciphertext size in bytes (~75 KB plaintext) |
| `RATE_LIMIT_MAX` | `10` | Max note creations per IP per window |
| `RATE_LIMIT_WINDOW_MS` | `3600000` | Rate-limit window in milliseconds (1 hour) |

### Reverse proxy

vanishing.ink is designed to sit behind a reverse proxy (nginx, Caddy, etc.)
that handles TLS termination. The application does not serve HTTPS directly.

The rate limiter trusts the `X-Forwarded-For` header when present. If you are
running without a reverse proxy, this header can be spoofed by clients. For a
production deployment, configure your proxy to set `X-Forwarded-For` and
consider adding proxy-level rate limiting as an additional layer.

Example Caddy configuration:

```
yourdomain.com {
    reverse_proxy localhost:3000
}
```

---

## Project structure

```
vanishing.ink/
├── docker-compose.yml   # App + Redis services
├── Dockerfile
├── package.json
├── .env.example
├── server/
│   └── index.ts         # Bun HTTP server, API routes, rate limiter
└── public/
    ├── index.html        # Create note page
    ├── note.html         # View note page
    ├── style.css
    ├── app.js            # Encryption + create flow
    └── view.js           # Decryption + view flow
```

---

## API

The API is intentionally minimal. Both endpoints accept and return JSON.

### `POST /api/notes`

Create a new note.

**Request body**

| Field | Type | Description |
|-------|------|-------------|
| `ciphertext` | `string` | Base64url-encoded AES-256-GCM ciphertext |
| `iv` | `string` | Base64url-encoded 12-byte IV |
| `ttl` | `number` | Expiration in seconds: `3600`, `86400`, or `604800` |

**Response `201`**

```json
{ "id": "550e8400-e29b-41d4-a716-446655440000" }
```

### `GET /api/notes/:id`

Retrieve and permanently destroy a note.

**Response `200`**

```json
{ "ciphertext": "...", "iv": "..." }
```

**Response `404`**

The note does not exist or has already been viewed. These two states are
intentionally indistinguishable.

---

## Security considerations

- **Link security.** The share link contains the decryption key. Any service
  that logs or previews the link (email clients, Slack, messaging apps) may
  capture it. Where possible, share links over an end-to-end encrypted channel.
  The optional-passphrase feature (planned) adds a second factor for
  higher-sensitivity use cases.

- **Browser extensions.** Malicious browser extensions can intercept page
  content and JavaScript execution. Users handling very high-value secrets
  should open the link in a private/incognito window with extensions disabled.

- **Rate limiting.** The built-in rate limiter is in-process and per-instance.
  For multi-instance deployments, replace it with a Redis-backed implementation
  to share state across instances.

---

## Contributing

Contributions are welcome. Please open an issue to discuss significant changes
before submitting a pull request.

This project deliberately avoids dependencies on the frontend. Please do not
submit PRs that introduce a frontend framework or build step.

---

## License

MIT
