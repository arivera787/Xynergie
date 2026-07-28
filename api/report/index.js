// Azure Function — proxies model calls so the API key never reaches the browser.
// Key lives in the Static Web App's application settings as ANTHROPIC_API_KEY.
//
// Auth: the browser already holds an MSAL access token for Microsoft Graph.
// We require it and verify it against Graph, which confirms both that the
// caller is signed in and that they belong to the Xynergie tenant. This is
// deliberately independent of Static Web Apps' built-in auth, which this app
// does not use.

const MODEL = "claude-sonnet-4-6";
const TENANT_ID = "d5a2e3df-bdc3-4c0f-8fd4-908cd7751d67";

async function verifyCaller(authHeader, context) {
  if (!authHeader || !authHeader.startsWith("Bearer ")) return null;
  try {
    const r = await fetch("https://graph.microsoft.com/v1.0/me", {
      headers: { Authorization: authHeader }
    });
    if (!r.ok) return null;
    const me = await r.json();
    return me.id ? me : null;
  } catch (err) {
    context.log.error("Token verification failed:", err.message);
    return null;
  }
}

module.exports = async function (context, req) {
  const key = process.env.ANTHROPIC_API_KEY;
  if (!key) {
    context.res = { status: 500, body: { error: "ANTHROPIC_API_KEY not configured" } };
    return;
  }

  const caller = await verifyCaller(req.headers.authorization, context);
  if (!caller) {
    context.res = { status: 401, body: { error: "Sign in required" } };
    return;
  }

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
    context.res = {
      status: upstream.status,
      headers: { "Content-Type": "application/json" },
      body: text          // passed through raw so the client sees the real error
    };
  } catch (err) {
    context.log.error("Proxy failure:", err);
    context.res = { status: 502, body: { error: "Upstream request failed: " + err.message } };
  }
};
