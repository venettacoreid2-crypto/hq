export default {
  async fetch(req, env) {
    const url = new URL(req.url);

    if (url.pathname === "/") {
      return new Response(
        await env.INDEX.text(),
        { headers: { "Content-Type": "text/html" } }
      );
    }

    if (url.pathname === "/login") return login(req, env);
    if (url.pathname === "/verify-otp") return verifyOtp(req, env);
    if (url.pathname === "/session") return session(req, env);

    return new Response("Not Found", { status: 404 });
  }
};

async function login(req, env) {
  const { username, password } = await req.json();

  const user = await env.DB.prepare(
    "SELECT * FROM users WHERE username=?"
  ).bind(username).first();

  if (!user || user.password !== password) {
    return json({ error: "Invalid credentials" }, 401);
  }

  const sessionId = crypto.randomUUID();
  const otp = Math.floor(100000 + Math.random() * 900000).toString();

  await env.DB.batch([
    env.DB.prepare(
      "INSERT INTO sessions(id,user_id,otp_verified,expires,ip,user_agent) VALUES (?,?,?,?,?,?)"
    ).bind(
      sessionId, user.id, 0,
      new Date(Date.now() + 10 * 60e3).toISOString(),
      req.headers.get("cf-connecting-ip"),
      req.headers.get("user-agent")
    ),
    env.DB.prepare(
      "INSERT INTO otp_tokens(id,session_id,code,expires) VALUES (?,?,?,?)"
    ).bind(
      crypto.randomUUID(),
      sessionId,
      otp,
      new Date(Date.now() + 5 * 60e3).toISOString()
    )
  ]);

  console.log("OTP:", otp); // telemetry/logging

  return json({ sessionId });
}

async function verifyOtp(req, env) {
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
}

async function session(req, env) {
  const sid = req.headers.get("authorization");
  const s = await env.DB.prepare(
    "SELECT * FROM sessions WHERE id=? AND otp_verified=1"
  ).bind(sid).first();

  if (!s) return json({ valid: false }, 401);
  return json({ valid: true, role: s.role });
}

const json = (d, s = 200) =>
  new Response(JSON.stringify(d), { status: s });
