// Azure Function — proxies model calls so the API key never reaches the browser.
// Key lives in the Static Web App's application settings as ANTHROPIC_API_KEY.
//
// Auth: the browser already holds an MSAL access token for Microsoft Graph.
// We verify it against Graph, which confirms the caller is signed in and in
// the tenant. The token is accepted from either the standard Authorization
// header or X-Xyn-Auth, because Static Web Apps consumes Authorization in
// some configurations before the Function sees it.

const MODEL = "claude-sonnet-4-6";

// The token arrives in the request BODY, not a header. Graph tokens run to
// roughly 2,000 characters and headers get size-capped and rewritten in
// transit, which silently truncates them and makes Graph reject a token that
// works fine from the browser. The body is not subject to that.
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
  // GET is a deployment health check — open /api/report in a browser.
  if (req.method === "GET") {
    context.res = {
      status: 200,
      headers: { "Content-Type": "application/json" },
      body: {
        ok: true,
        function: "report",
        keyConfigured: !!process.env.ANTHROPIC_API_KEY,
        node: process.version
      }
    };
    return;
  }

  const key = process.env.ANTHROPIC_API_KEY;
  if (!key) {
    context.res = { status: 500, body: { error: "ANTHROPIC_API_KEY not configured" } };
    return;
  }

  // ---- verify caller ----
  const token = extractToken(req);
  if (!token) {
    context.res = {
      status: 401,
      body: {
        error: "No token received",
        hint: "Neither Authorization nor X-Xyn-Auth reached the Function.",
        headersSeen: Object.keys(req.headers || {}).sort()
      }
    };
    return;
  }

  let graphStatus = 0, graphBody = "";
  try {
    const gr = await fetch("https://graph.microsoft.com/v1.0/me", {
      headers: { Authorization: "Bearer " + token }
    });
    graphStatus = gr.status;
    if (!gr.ok) graphBody = (await gr.text()).slice(0, 300);
    else {
      const me = await gr.json();
      if (!me.id) graphStatus = 0;
    }
  } catch (err) {
    context.log.error("Graph verification threw:", err.message);
    context.res = { status: 502, body: { error: "Could not reach Graph: " + err.message } };
    return;
  }

  if (graphStatus !== 200) {
    context.res = {
      status: 401,
      body: {
        error: "Token rejected by Graph",
        graphStatus: graphStatus,
        graphDetail: graphBody,
        tokenLength: token.length,
        tokenLooksJwt: token.split(".").length === 3,
        source: (req.body && req.body.token) ? "body" : "header",
        hint: graphStatus === 401
          ? "Token expired or is not a Graph token. Reload the page to re-run sign-in."
          : "Unexpected Graph response."
      }
    };
    return;
  }

  // ---- proxy ----
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
      body: text
    };
  } catch (err) {
    context.log.error("Proxy failure:", err);
    context.res = { status: 502, body: { error: "Upstream request failed: " + err.message } };
  }
};
