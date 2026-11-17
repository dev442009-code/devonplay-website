
const encoder = new TextEncoder();

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

  return btoa(String.fromCharCode(...new Uint8Array(signature)));
}

async function verifyToken(token, password) {
  try {
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
      Uint8Array.from(atob(signature), c => c.charCodeAt(0)),
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
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization"
        }
      });
    }

    if (url.pathname === "/api/admin/login" &&
        request.method === "POST") {
      try {
        const body = await request.json();

        if (
          typeof body.password !== "string" ||
          body.password.length > 256 ||
          body.password !== env.ADMIN_PASSWORD
        ) {
          return Response.json(
            { success: false, message: "Wrong password" },
            { status: 401 }
          );
        }

        const expires = Date.now() + 60 * 60 * 1000;
        const payload = btoa(JSON.stringify({ expires }));
        const signature = await createSignature(
          payload,
          env.ADMIN_PASSWORD
        );

        return Response.json(
          { success: true, token: `${payload}.${signature}` },
          {
            headers: {
              "Access-Control-Allow-Origin": "*"
            }
          }
        );
      } catch {
        return Response.json(
          { success: false, message: "Invalid request" },
          { status: 400 }
        );
      }
    }

    if (url.pathname === "/api/health") {
      try {
        const result = await env.DB.prepare(
          "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).all();

        return Response.json({
          success: true,
          database: "Connected",
          tables: result.results
        });
      } catch (error) {
        return Response.json({
          success: false,
          error: error.message
        }, { status: 500 });
      }
    }

    return env.ASSETS.fetch(request);
  }
};
