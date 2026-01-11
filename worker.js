export default {
  async fetch(req, env) {
    const url = new URL(req.url);

    // HEALTH CHECK
    if (url.pathname === "/") {
      return new Response(
        JSON.stringify({
          service: "Venetta Auth HQ",
          status: "ok",
          time: new Date().toISOString()
        }),
        { headers: { "Content-Type": "application/json" } }
      );
    }

    // LOGIN (POST)
    if (url.pathname === "/login" && req.method === "POST") return login(req, env);

    // VERIFY OTP (POST)
    if (url.pathname === "/verify-otp" && req.method === "POST") return verifyOtp(req, env);

    // SESSION CHECK (GET)
    if (url.pathname === "/session" && req.method === "GET") return session(req, env);

    // FAVICON (avoid 404 logs)
    if (url.pathname === "/favicon.ico") {
      return new Response("", { status: 204 });
    }

    return new Response("Not Found", { status: 404 });
  }
};

// --- LOGIN HANDLER ---
async function login(req, env) {
  try {
    const { username, password } = await req.json();

    // Pastikan table users punya kolom password!
    const user = await env.DB.prepare(
      "SELECT id, role, password FROM users WHERE username=?"
    ).bind(username).first();

    if (!user || user.password !== password) {
      return json({ error: "Invalid credentials" }, 401);
    }

    const sessionId = crypto.randomUUID();
    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    await env.DB.batch([
      env.DB.prepare(
        "INSERT INTO sessions(id,user_id,otp_verified,expires_at,ip,user_agent) VALUES (?,?,?,?,?,?)"
      ).bind(
        sessionId,
        user.id,
        0,
        new Date(Date.now() + 10 * 60e3).toISOString(),
        req.headers.get("cf-connecting-ip"),
        req.headers.get("user-agent")
      ),
      env.DB.prepare(
        "INSERT INTO otp_tokens(id,session_id,code,expires_at) VALUES (?,?,?,?)"
      ).bind(
        crypto.randomUUID(),
        sessionId,
        otp,
        new Date(Date.now() + 5 * 60e3).toISOString()
      )
    ]);

    console.log("OTP (stub):", otp); // nanti diganti kirim email/sms

    return json({ sessionId });
  } catch (err) {
    return json({ error: err.message }, 500);
  }
}

// --- VERIFY OTP HANDLER ---
async function verifyOtp(req, env) {
  try {
    const { sessionId, otp } = await req.json();

    const token = await env.DB.prepare(
      "SELECT * FROM otp_tokens WHERE session_id=? AND code=?"
    ).bind(sessionId, otp).first();

    if (!token) return json({ error: "Invalid OTP" }, 401);

    await env.DB.prepare(
      "UPDATE sessions SET otp_verified=1 WHERE id=?"
    ).bind(sessionId).run();

    const user = await env.DB.prepare(
      "SELECT role FROM users WHERE id=(SELECT user_id FROM sessions WHERE id=?)"
    ).bind(sessionId).first();

    return json({ success: true, role: user.role });
  } catch (err) {
    return json({ error: err.message }, 500);
  }
}

// --- SESSION CHECK ---
async function session(req, env) {
  try {
    const sid = req.headers.get("authorization");
    const s = await env.DB.prepare(
      "SELECT * FROM sessions WHERE id=? AND otp_verified=1"
    ).bind(sid).first();

    if (!s) return json({ valid: false }, 401);

    const user = await env.DB.prepare(
      "SELECT role FROM users WHERE id=?"
    ).bind(s.user_id).first();

    return json({ valid: true, role: user.role });
  } catch (err) {
    return json({ error: err.message }, 500);
  }
}

// --- RESPONSE HELPERS ---
const json = (data, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } });
