/**
 * app.js — create note flow
 *
 * Encryption is performed entirely in the browser using the Web Crypto API.
 * The plaintext never leaves the client; only ciphertext is sent to the server.
 *
 * Algorithm: AES-256-GCM
 *   - 256-bit key generated fresh for every note
 *   - 96-bit (12-byte) IV, randomly generated per note
 *   - GCM mode provides both confidentiality and integrity (authenticated)
 *
 * The key is encoded as base64url and placed in the URL fragment (#key).
 * Fragments are not included in HTTP requests, so the server never sees the key.
 */

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

function toBase64url(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

// ---------------------------------------------------------------------------
// Encryption
// ---------------------------------------------------------------------------

async function encrypt(plaintext) {
  const key = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,         // extractable — we need to export it for the URL
    ["encrypt"]
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);

  const ciphertextBuffer = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoded
  );

  const rawKey = await crypto.subtle.exportKey("raw", key);

  return {
    ciphertext: toBase64url(new Uint8Array(ciphertextBuffer)),
    iv:         toBase64url(iv),
    key:        toBase64url(new Uint8Array(rawKey)),
  };
}

// ---------------------------------------------------------------------------
// UI
// ---------------------------------------------------------------------------

const createSection = document.getElementById("create-section");
const resultSection = document.getElementById("result-section");
const createForm    = document.getElementById("create-form");
const noteText      = document.getElementById("note-text");
const ttlSelect     = document.getElementById("ttl");
const resultUrl     = document.getElementById("result-url");
const copyBtn       = document.getElementById("copy-btn");
const newBtn        = document.getElementById("new-btn");
const errorBanner   = document.getElementById("error-banner");
const errorText     = document.getElementById("error-text");
const submitBtn     = createForm.querySelector("button[type=submit]");

function showError(msg) {
  errorText.textContent = msg;
  errorBanner.hidden = false;
}

function clearError() {
  errorBanner.hidden = true;
  errorText.textContent = "";
}

function setLoading(loading) {
  submitBtn.disabled = loading;
  submitBtn.textContent = loading ? "Encrypting…" : "Generate secret link";
}

createForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  clearError();

  const text = noteText.value.trim();
  if (!text) {
    showError("Please enter a secret before generating a link.");
    return;
  }

  const ttl = parseInt(ttlSelect.value, 10);
  setLoading(true);

  try {
    const { ciphertext, iv, key } = await encrypt(text);

    const res = await fetch("/api/notes", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ciphertext, iv, ttl }),
    });

    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.error ?? `Server error (${res.status})`);
    }

    const { id } = await res.json();

    // The decryption key goes in the fragment — browsers never send
    // the fragment to the server, so it stays client-side only.
    const link = `${location.origin}/note/${id}#${key}`;
    resultUrl.value = link;

    createSection.hidden = true;
    resultSection.hidden = false;
  } catch (err) {
    showError(err.message ?? "Something went wrong. Please try again.");
  } finally {
    setLoading(false);
  }
});

copyBtn.addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(resultUrl.value);
    copyBtn.textContent = "Copied!";
    setTimeout(() => { copyBtn.textContent = "Copy"; }, 2000);
  } catch {
    resultUrl.select();
  }
});

newBtn.addEventListener("click", () => {
  noteText.value = "";
  resultUrl.value = "";
  resultSection.hidden = true;
  createSection.hidden = false;
  clearError();
  noteText.focus();
});

