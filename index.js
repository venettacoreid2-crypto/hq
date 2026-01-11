export default {
  async fetch(req, env) {
    const url = new URL(req.url);

    // ROOT / HEALTH CHECK
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

    if (url.pathname === "/login") return login(req, env);
    if (url.pathname === "/verify-otp") return verifyOtp(req, env);
    if (url.pathname === "/session") return session(req, env);

    return new Response("Not Found", { status: 404 });
  }
};
