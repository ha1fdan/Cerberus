function b64urlToBuffer(b64url) {
  const pad = "=".repeat((4 - (b64url.length % 4)) % 4);
  const b64 = (b64url + pad).replace(/-/g, "+").replace(/_/g, "/");
  const str = atob(b64);
  const bytes = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) bytes[i] = str.charCodeAt(i);
  return bytes.buffer;
}

function bufferToB64url(buf) {
  const bytes = new Uint8Array(buf);
  let str = "";
  for (const b of bytes) str += String.fromCharCode(b);
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function postJSON(url, body) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  if (!res.ok) {
    const detail = await res.json().catch(() => ({}));
    throw new Error(detail.detail || `Request to ${url} failed`);
  }
  return res.json();
}

function decodeCreationOptions(publicKey) {
  return {
    ...publicKey,
    challenge: b64urlToBuffer(publicKey.challenge),
    user: { ...publicKey.user, id: b64urlToBuffer(publicKey.user.id) },
    excludeCredentials: (publicKey.excludeCredentials || []).map((c) => ({
      ...c,
      id: b64urlToBuffer(c.id),
    })),
  };
}

function decodeRequestOptions(publicKey) {
  return {
    ...publicKey,
    challenge: b64urlToBuffer(publicKey.challenge),
    allowCredentials: (publicKey.allowCredentials || []).map((c) => ({
      ...c,
      id: b64urlToBuffer(c.id),
    })),
  };
}

function encodeCredential(cred) {
  const response = { clientDataJSON: bufferToB64url(cred.response.clientDataJSON) };

  if (cred.response.attestationObject) {
    response.attestationObject = bufferToB64url(cred.response.attestationObject);
    if (cred.response.getTransports) {
      response.transports = cred.response.getTransports();
    }
  }

  if (cred.response.authenticatorData) {
    response.authenticatorData = bufferToB64url(cred.response.authenticatorData);
    response.signature = bufferToB64url(cred.response.signature);
    if (cred.response.userHandle) {
      response.userHandle = bufferToB64url(cred.response.userHandle);
    }
  }

  return {
    id: cred.id,
    rawId: bufferToB64url(cred.rawId),
    type: cred.type,
    response,
    clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
  };
}

async function registerPasskey(beginUrl, completeUrl, nickname) {
  const { publicKey, state } = await postJSON(beginUrl, {});
  const options = decodeCreationOptions(publicKey);
  const cred = await navigator.credentials.create({ publicKey: options });
  return postJSON(completeUrl, { state, credential: encodeCredential(cred), nickname });
}

function isSafeRedirectPath(path) {
  // Only allow same-origin, relative paths ("/foo") so a crafted `?rd=` query
  // param can't send a just-authenticated user to an attacker-controlled origin
  // or a `javascript:`/other non-http(s) URI via `window.location = rd`.
  if (typeof path !== "string" || path.length === 0) return false;
  if (!path.startsWith("/") || path.startsWith("//")) return false;
  if (/[\\\s\x00-\x1f]/.test(path)) return false;
  return true;
}

async function loginWithPasskey() {
  const { publicKey, state } = await postJSON("/webauthn/authenticate/begin", {});
  const options = decodeRequestOptions(publicKey);
  const cred = await navigator.credentials.get({ publicKey: options });
  return postJSON("/webauthn/authenticate/complete", { state, credential: encodeCredential(cred) });
}
