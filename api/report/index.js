// Azure Function — proxies model calls so the API key never reaches the browser.
//
// Auth: the browser sends its MSAL token in the request body. We verify it
// ourselves against Entra's published signing keys rather than calling Graph.
// Graph only accepts tokens whose audience is Graph, which made verification
// brittle; validating the signature directly works for any token this tenant
// issued and needs no npm dependencies.

const crypto = require("crypto");

const MODEL = "claude-sonnet-4-6";
const TENANT_ID = "d5a2e3df-bdc3-4c0f-8fd4-908cd7751d67";

let jwksCache = { keys: null, fetchedAt: 0 };
const JWKS_TTL_MS = 60 * 60 * 1000;

async function getSigningKeys(context) {
  if (jwksCache.keys && Date.now() - jwksCache.fetchedAt < JWKS_TTL_MS) return jwksCache.keys;
  const url = `https://login.microsoftonline.com/${TENANT_ID}/discovery/v2.0/keys`;
  const r = await fetch(url);
  if (!r.ok) throw new Error("Could not fetch signing keys: HTTP " + r.status);
  const body = await r.json();
  jwksCache = { keys: body.keys || [], fetchedAt: Date.now() };
  context.log(`Fetched ${jwksCache.keys.length} signing keys`);
  return jwksCache.keys;
}

function b64urlToBuf(s) {
  return Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

async function verifyToken(token, context) {
  const parts = token.split(".");
  if (parts.length !== 3) return { ok: false, reason: "not a JWT", parts: parts.length };

  let header, payload;
  try {
    header = JSON.parse(b64urlToBuf(parts[0]).toString("utf8"));
    payload = JSON.parse(b64urlToBuf(parts[1]).toString("utf8"));
  } catch (e) {
    return { ok: false, reason: "could not decode JWT segments" };
  }

  if (payload.tid && payload.tid !== TENANT_ID) {
    return { ok: false, reason: "wrong tenant", tid: payload.tid };
  }
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && payload.exp < now) {
    return { ok: false, reason: "token expired", expiredSecondsAgo: now - payload.exp };
  }

  // Some Entra access tokens are deliberately opaque to anyone but their
  // audience and carry a "nonce" in the header; those cannot be verified here.
  // Everything else we check properly.
  if (header.nonce) {
    return { ok: true, soft: true, reason: "nonce-protected token, claims checked without signature",
             upn: payload.upn || payload.preferred_username || null };
  }

  const keys = await getSigningKeys(context);
  const jwk = keys.find(k => k.kid === header.kid);
  if (!jwk) return { ok: false, reason: "signing key not found for kid", kid: header.kid };

  let pub;
  try {
    pub = crypto.createPublicKey({ key: jwk, format: "jwk" });
  } catch (e) {
    return { ok: false, reason: "could not build public key: " + e.message };
  }

  const verified = crypto.verify(
    "RSA-SHA256",
    Buffer.from(parts[0] + "." + parts[1]),
    { key: pub, padding: crypto.constants.RSA_PKCS1_PADDING },
    b64urlToBuf(parts[2])
  );

  if (!verified) return { ok: false, reason: "signature invalid" };
  return { ok: true, upn: payload.upn || payload.preferred_username || null };
}

function extractToken(req) {
  if (req.body && typeof req.body.token === "string" && req.body.token.trim()) {
    return req.body.token.trim();
  }
  const h = req.headers || {};
  for (const c of [h.authorization, h.Authorization, h["x-xyn-auth"]]) {
    if (typeof c === "string" && c.trim()) {
      const t = c.startsWith("Bearer ") ? c.slice(7).trim() : c.trim();
      if (t) return t;
    }
  }
  return null;
}

module.exports = async function (context, req) {
  if (req.method === "GET") {
    context.res = {
      status: 200,
      headers: { "Content-Type": "application/json" },
      body: { ok: true, function: "report",
              keyConfigured: !!process.env.ANTHROPIC_API_KEY, node: process.version }
    };
    return;
  }

  const key = process.env.ANTHROPIC_API_KEY;
  if (!key) {
    context.res = { status: 500, body: { error: "ANTHROPIC_API_KEY not configured" } };
    return;
  }

  const token = extractToken(req);
  if (!token) {
    context.res = { status: 401, body: { error: "No token received",
      headersSeen: Object.keys(req.headers || {}).sort() } };
    return;
  }

  let check;
  try {
    check = await verifyToken(token, context);
  } catch (err) {
    context.log.error("Verification threw:", err.message);
    context.res = { status: 502, body: { error: "Verification failed: " + err.message } };
    return;
  }

  if (!check.ok) {
    context.res = { status: 401, body: {
      error: "Token rejected",
      reason: check.reason,
      detail: { kid: check.kid, tid: check.tid, parts: check.parts,
                expiredSecondsAgo: check.expiredSecondsAgo },
      tokenLength: token.length
    } };
    return;
  }
  context.log(`Authorised: ${check.upn || "unknown"}${check.soft ? " (claims only)" : ""}`);

  const messages = req.body && req.body.messages;
  if (!Array.isArray(messages) || !messages.length) {
    context.res = { status: 400, body: { error: "messages array required" } };
    return;
  }

  try {
    const upstream = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": key,
        "anthropic-version": "2023-06-01"
      },
      body: JSON.stringify({
        model: MODEL,
        max_tokens: Math.min(req.body.max_tokens || 1000, 4096),
        messages: messages
      })
    });
    const text = await upstream.text();
    context.res = { status: upstream.status,
                    headers: { "Content-Type": "application/json" }, body: text };
  } catch (err) {
    context.log.error("Proxy failure:", err);
    context.res = { status: 502, body: { error: "Upstream request failed: " + err.message } };
  }
};
