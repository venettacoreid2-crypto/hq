export default {
  async fetch(req, env) {
    const url = new URL(req.url);

    // Serve site assets
    if (url.pathname === "/") {
      return env.__STATIC_CONTENT.get("/index.html", { type: "text/html" });
    }
    if (url.pathname === "/bg.jpg") {
      return env.__STATIC_CONTENT.get("/bg.jpg", { type: "image/jpeg" });
    }

    if (url.pathname === "/login" && req.method === "POST") {
      return login(req, env);
    }

    if (url.pathname === "/session" && req.method === "GET") {
      return getSession(req, env);
    }

    return new Response("Not Found", { status: 404 });
  }
};

async function login(req, env) {
  try {
    const { username, password } = await req.json();

    // Dummy credentials (ganti sesuai kebutuhan)
    const VALID_USERS = {
      "gito.ismoyo@vencorio.com": "V3nP@ss292929"
    };

    if (!(username in VALID_USERS) || VALID_USERS[username] !== password) {
      return json({ error: "Invalid credentials" }, 401);
    }

    const sessionId = crypto.randomUUID();
    const sessionData = {
      username,
      created: Date.now()
    };

    await env.SESSIONS.put(sessionId, JSON.stringify(sessionData), { expirationTtl: 3600 });

    return json({ sessionId });
  } catch (err) {
    return json({ error: "Login failed" }, 500);
  }
}

async function getSession(req, env) {
  try {
    const sid = req.headers.get("Authorization");
    if (!sid) return json({ valid: false }, 401);

    const session = await env.SESSIONS.get(sid, "json");
    if (!session) return json({ valid: false }, 401);

    return json({ valid: true, username: session.username });
  } catch {
    return json({ valid: false }, 500);
  }
}

const json = (d, status = 200) =>
  new Response(JSON.stringify(d), {
    status,
    headers: { "Content-Type": "application/json" }
  });
