
const encoder = new TextEncoder();

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization"
};

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...corsHeaders,
      "Content-Type": "application/json"
    }
  });
}

async function createSignature(data, password) {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(data)
  );

  return btoa(
    String.fromCharCode(...new Uint8Array(signature))
  );
}

async function verifyToken(token, password) {
  try {
    if (!password || typeof token !== "string") return false;

    const parts = token.split(".");
    if (parts.length !== 2) return false;

    const [payload, signature] = parts;

    const key = await crypto.subtle.importKey(
      "raw",
      encoder.encode(password),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );

    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      Uint8Array.from(
        atob(signature),
        c => c.charCodeAt(0)
      ),
      encoder.encode(payload)
    );

    if (!valid) return false;

    const data = JSON.parse(atob(payload));

    return Number.isFinite(data.expires) &&
      data.expires > Date.now();

  } catch {
    return false;
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders
      });
    }

    // Admin Login
    if (
      url.pathname === "/api/admin/login" &&
      request.method === "POST"
    ) {
      try {
        if (!env.ADMIN_PASSWORD) {
          return jsonResponse(
            { success: false, message: "Server configuration error" },
            500
          );
        }

        const body = await request.json();

        if (
          typeof body.password !== "string" ||
          body.password.length > 256 ||
          body.password !== env.ADMIN_PASSWORD
        ) {
          return jsonResponse(
            { success: false, message: "Wrong password" },
            401
          );
        }

        const expires = Date.now() + 60 * 60 * 1000;
        const payload = btoa(JSON.stringify({ expires }));

        const signature = await createSignature(
          payload,
          env.ADMIN_PASSWORD
        );

        return jsonResponse({
          success: true,
          token: `${payload}.${signature}`
        });

      } catch {
        return jsonResponse(
          { success: false, message: "Invalid request" },
          400
        );
      }
    }

    // Verify Admin Token
    if (url.pathname.startsWith("/api/admin/")) {
      const auth = request.headers.get("Authorization") || "";

      const token = auth.startsWith("Bearer ")
        ? auth.slice(7)
        : "";

      const valid = await verifyToken(
        token,
        env.ADMIN_PASSWORD
      );

      if (!valid) {
        return jsonResponse(
          { success: false, message: "Unauthorized" },
          401
        );
      }
    }

    // Admin Session Check
    if (
      url.pathname === "/api/admin/session" &&
      request.method === "GET"
    ) {
      return jsonResponse({
        success: true,
        message: "Admin session verified"
      });
    }

    // Database Health Check
    if (
      url.pathname === "/api/health" &&
      request.method === "GET"
    ) {
      try {
        const result = await env.DB.prepare(
          "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).all();

        return jsonResponse({
          success: true,
          database: "Connected",
          tables: result.results
        });

      } catch (error) {
        return jsonResponse({
          success: false,
          error: error.message
        }, 500);
      }
    }

    // Other requests go to website assets
    return env.ASSETS.fetch(request);
  }
};
