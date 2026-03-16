/**
 * view.js — view note flow
 *
 * Retrieves ciphertext from the server and decrypts it locally.
 * The decryption key is read from the URL fragment (#key), which is
 * never sent to the server in HTTP requests.
 *
 * The server deletes the note atomically when it is fetched (GETDEL),
 * so the note can only ever be read once regardless of race conditions.
 */

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

function fromBase64url(str) {
  const padded = str
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    + "=".repeat((4 - (str.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

// ---------------------------------------------------------------------------
// Decryption
// ---------------------------------------------------------------------------

async function decrypt(ciphertext, iv, keyBase64url) {
  const keyBytes = fromBase64url(keyBase64url);
  const ivBytes  = fromBase64url(iv);
  const ctBytes  = fromBase64url(ciphertext);

  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-GCM" },
    false,          // non-extractable — no reason to export it after decryption
    ["decrypt"]
  );

  const plainBuffer = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: ivBytes },
    cryptoKey,
    ctBytes
  );

  return new TextDecoder().decode(plainBuffer);
}

// ---------------------------------------------------------------------------
// UI state
// ---------------------------------------------------------------------------

const sections = {
  loading: document.getElementById("loading-section"),
  note:    document.getElementById("note-section"),
  gone:    document.getElementById("gone-section"),
  error:   document.getElementById("error-section"),
};

function show(name) {
  for (const [key, el] of Object.entries(sections)) {
    el.hidden = key !== name;
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function init() {
  // Extract note ID from the path: /note/<uuid>
  const pathParts = location.pathname.split("/");
  const id = pathParts[pathParts.length - 1];

  // Extract the decryption key from the fragment.
  // location.hash includes the leading '#', so slice it off.
  const key = location.hash.slice(1);

  if (!id || !key) {
    document.getElementById("error-message").textContent =
      "This link is malformed. It may be missing the decryption key.";
    show("error");
    return;
  }

  // Remove the key from the browser's address bar so it is not captured
  // in browser history or visible if someone looks over the user's shoulder.
  // history.replaceState does not trigger a page reload.
  try {
    history.replaceState(null, "", location.pathname);
  } catch {
    // Non-critical — some environments restrict history manipulation.
  }

  let data;
  try {
    const res = await fetch(`/api/notes/${id}`);
    if (res.status === 404) {
      show("gone");
      return;
    }
    if (!res.ok) {
      throw new Error(`Unexpected server response (${res.status})`);
    }
    data = await res.json();
  } catch (err) {
    document.getElementById("error-message").textContent =
      err.message ?? "Could not contact the server.";
    show("error");
    return;
  }

  let plaintext;
  try {
    plaintext = await decrypt(data.ciphertext, data.iv, key);
  } catch {
    // A decryption failure most commonly means the key in the URL does not
    // match the ciphertext — either the link was truncated or tampered with.
    // AES-GCM's authentication tag will also cause this if the ciphertext
    // was modified in storage.
    document.getElementById("error-message").textContent =
      "Decryption failed. The link may be truncated or corrupted.";
    show("error");
    return;
  }

  const secretText = document.getElementById("secret-text");
  secretText.value = plaintext;
  show("note");
  secretText.focus();
  secretText.select();

  // Copy button
  document.getElementById("copy-btn").addEventListener("click", async () => {
    const btn = document.getElementById("copy-btn");
    try {
      await navigator.clipboard.writeText(secretText.value);
      btn.textContent = "Copied!";
      setTimeout(() => { btn.textContent = "Copy"; }, 2000);
    } catch {
      secretText.select();
    }
  });

  // Clear button — removes the secret from the DOM entirely.
  // This is a courtesy feature; it does not guarantee the OS has not
  // already captured the value in swap or a clipboard manager.
  document.getElementById("clear-btn").addEventListener("click", () => {
    secretText.value = "";
    secretText.placeholder = "Cleared.";
    document.getElementById("clear-btn").hidden = true;
    document.getElementById("copy-btn").hidden = true;
  });
}

init();
