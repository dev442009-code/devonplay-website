
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

    // Database and KV Health Check
if (
  url.pathname === "/api/health" &&
  request.method === "GET"
) {
  try {
    const result = await env.DB.prepare(
      "SELECT name FROM sqlite_master WHERE type = 'table'"
    ).all();

    let mediaStatus = "Not Connected";

    try {
      if (!env.MEDIA) {
        throw new Error("MEDIA binding missing");
      }

      await env.MEDIA.get("__devonplay_health_check__");
      mediaStatus = "Connected";
    } catch {
      mediaStatus = "Not Connected";
    }

    return jsonResponse({
      success: true,
      database: "Connected",
      media: mediaStatus,
      tables: result.results
    });

  } catch (error) {
    return jsonResponse({
      success: false,
      error: error.message
    }, 500);
  }
}
// Get Orders
if (
  url.pathname === "/api/admin/orders" &&
  request.method === "GET"
) {
  try {
    const result = await env.DB.prepare(
      "SELECT * FROM orders ORDER BY id DESC"
    ).all();

    const orders = result.results.map(order => ({
      id: order.order_code || String(order.id),
      db_id: order.id,
      name: order.customer_name || "",
      phone: order.customer_phone || "",
      email: order.customer_email || "",
      uid: order.user_id || "",
      gameName: order.game || "",
      folder: order.folder || "",
      prod: order.product_name || "",
      quantity: order.quantity || 1,
      price: order.price || 0,
      bonus: order.bonus || "",
      player: order.player_id || "",
      zone: order.zone_id || "",
      extra: order.extra || "",
      telegram: order.telegram || "",
      pay: order.payment_method || "",
      screenshot: order.screenshot_url || "",
      timestamp: order.order_timestamp || order.created_at,
      status: order.status || "Pending",
      reason: order.rejection_reason || "",
      delivery_end: order.delivery_end || 0,
      delivery_remaining: order.delivery_remaining || 0
    }));

    return jsonResponse({
      success: true,
      orders
    });

  } catch (error) {
    return jsonResponse({
      success: false,
      message: "Could not load orders"
    }, 500);
  }
}

// Update Order
if (
  url.pathname === "/api/admin/orders/update" &&
  request.method === "POST"
) {
  try {
    const body = await request.json();

    const allowedStatuses = [
      "Pending",
      "Submitted",
      "Payment Under Review",
      "Approved",
      "Delivery in Progress",
      "Delivered",
      "Rejected"
    ];

    if (
      !Number.isInteger(Number(body.db_id)) ||
      !allowedStatuses.includes(body.status)
    ) {
      return jsonResponse({
        success: false,
        message: "Invalid order data"
      }, 400);
    }

    await env.DB.prepare(`
      UPDATE orders
      SET status = ?,
          rejection_reason = ?,
          delivery_end = ?,
          delivery_remaining = ?
      WHERE id = ?
    `).bind(
      body.status,
      body.reason || "",
      Number(body.delivery_end) || 0,
      Number(body.delivery_remaining) || 0,
      Number(body.db_id)
    ).run();

    return jsonResponse({
      success: true,
      message: "Order updated"
    });

  } catch (error) {
    return jsonResponse({
      success: false,
      message: "Could not update order"
    }, 500);
  }
}
    // Other requests go to website assets
    return env.ASSETS.fetch(request);
  }
};
