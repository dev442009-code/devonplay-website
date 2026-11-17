
const encoder = new TextEncoder();
const CUSTOMER_TOKEN_LIFETIME = 7 * 24 * 60 * 60 * 1000;

function toBase64(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)));
}

function fromBase64(value) {
  return Uint8Array.from(atob(value), c => c.charCodeAt(0));
}

async function hashCustomerPassword(password, salt) {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: 310000,
      hash: "SHA-256"
    },
    key,
    256
  );

  return toBase64(bits);
}

async function createCustomerToken(customerId, secret) {
  const payload = toBase64(
    encoder.encode(JSON.stringify({
      sub: customerId,
      expires: Date.now() + CUSTOMER_TOKEN_LIFETIME
    }))
  );

  const signature = await createSignature(payload, secret);
  return `${payload}.${signature}`;
}

async function verifyCustomerToken(token, secret) {
  try {
    if (!secret || typeof token !== "string") return null;

    const parts = token.split(".");
    if (parts.length !== 2) return null;

    const [payload, signature] = parts;
    const key = await crypto.subtle.importKey(
      "raw",
      encoder.encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );

    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      fromBase64(signature),
      encoder.encode(payload)
    );

    if (!valid) return null;

    const data = JSON.parse(
      new TextDecoder().decode(fromBase64(payload))
    );

    if (
      typeof data.sub !== "string" ||
      !Number.isFinite(data.expires) ||
      data.expires <= Date.now()
    ) return null;

    return data;
  } catch {
    return null;
  }
}
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
// Customer Registration
if (
  url.pathname === "/api/customer/register" &&
  request.method === "POST"
) {
  try {
    if (!env.CUSTOMER_TOKEN_SECRET) {
      return jsonResponse({
        success: false,
        message: "Server configuration error"
      }, 500);
    }

    const body = await request.json();

    const name = String(body.name || "").trim();
    const phone = String(body.phone || "").trim();
    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "");

    if (
      name.length < 2 || name.length > 100 ||
      phone.length < 5 || phone.length > 30 ||
      email.length > 254 ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email !== "" ||
      password.length < 8 || password.length > 128
    ) {
      return jsonResponse({
        success: false,
        message: "Invalid registration details"
      }, 400);
    }

    const salt = crypto.getRandomValues(new Uint8Array(16));
    const passwordHash = await hashCustomerPassword(
      password,
      salt
    );

    const customerId = "U" + crypto.randomUUID();

    await env.DB.prepare(`
      INSERT INTO customers
      (id, name, phone, email, password_hash, password_salt)
      VALUES (?, ?, ?, ?, ?, ?)
    `).bind(
      customerId,
      name,
      phone,
      email || null,
      passwordHash,
      toBase64(salt)
    ).run();

    const token = await createCustomerToken(
      customerId,
      env.CUSTOMER_TOKEN_SECRET
    );

    return jsonResponse({
      success: true,
      token,
      customer: {
        id: customerId,
        name,
        phone,
        email
      }
    }, 201);

  } catch (error) {
    if (String(error.message).includes("UNIQUE")) {
      return jsonResponse({
        success: false,
        message: "Phone number already registered"
      }, 409);
    }

    return jsonResponse({
      success: false,
      message: "Registration failed"
    }, 500);
  }
}

// Customer Login
if (
  url.pathname === "/api/customer/login" &&
  request.method === "POST"
) {
  try {
    if (!env.CUSTOMER_TOKEN_SECRET) {
      return jsonResponse({
        success: false,
        message: "Server configuration error"
      }, 500);
    }

    const body = await request.json();
    const identifier = String(body.identifier || "").trim();
    const password = String(body.password || "");

    if (
      !identifier || identifier.length > 254 ||
      !password || password.length > 128
    ) {
      return jsonResponse({
        success: false,
        message: "Invalid login details"
      }, 400);
    }

    const customer = await env.DB.prepare(`
      SELECT * FROM customers
      WHERE phone = ? OR email = ?
      LIMIT 1
    `).bind(
      identifier,
      identifier.toLowerCase()
    ).first();

    if (!customer) {
      return jsonResponse({
        success: false,
        message: "Incorrect login details"
      }, 401);
    }

    const salt = fromBase64(customer.password_salt);
    const passwordHash = await hashCustomerPassword(
      password,
      salt
    );

    if (passwordHash !== customer.password_hash) {
      return jsonResponse({
        success: false,
        message: "Incorrect login details"
      }, 401);
    }

    const token = await createCustomerToken(
      customer.id,
      env.CUSTOMER_TOKEN_SECRET
    );

    return jsonResponse({
      success: true,
      token,
      customer: {
        id: customer.id,
        name: customer.name,
        phone: customer.phone,
        email: customer.email || ""
      }
    });

  } catch {
    return jsonResponse({
      success: false,
      message: "Login failed"
    }, 500);
  }
}

// Customer Session Check
if (
  url.pathname === "/api/customer/session" &&
  request.method === "GET"
) {
  const auth = request.headers.get("Authorization") || "";
  const token = auth.startsWith("Bearer ")
    ? auth.slice(7)
    : "";

  const session = await verifyCustomerToken(
    token,
    env.CUSTOMER_TOKEN_SECRET
  );

  if (!session) {
    return jsonResponse({
      success: false,
      message: "Unauthorized"
    }, 401);
  }

  const customer = await env.DB.prepare(`
    SELECT id, name, phone, email, saved_game_ids
    FROM customers WHERE id = ?
  `).bind(session.sub).first();

  if (!customer) {
    return jsonResponse({
      success: false,
      message: "Customer not found"
    }, 404);
  }

  return jsonResponse({
    success: true,
    customer
  });
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
    // Upload Website Media (Admin Only)
if (
  url.pathname === "/api/admin/media" &&
  request.method === "POST"
) {
  try {
    if (!env.MEDIA) {
      return jsonResponse({
        success: false,
        message: "MEDIA binding missing"
      }, 500);
    }

    const body = await request.json();
    const key = String(body.key || "");
    const dataUrl = String(body.dataUrl || "");

    if (
      !/^[a-zA-Z0-9_-]{1,80}$/.test(key) ||
      !/^data:image\/(png|jpeg|webp|gif);base64,/.test(dataUrl) ||
      dataUrl.length > 4 * 1024 * 1024
    ) {
      return jsonResponse({
        success: false,
        message: "Invalid image or image too large"
      }, 400);
    }

    await env.MEDIA.put(`media:${key}`, dataUrl);

    return jsonResponse({
      success: true,
      key,
      url: `/api/media/${key}`
    });

  } catch (error) {
    return jsonResponse({
      success: false,
      message: "Media upload failed"
    }, 500);
  }
}

// Retrieve Website Media (Public)
if (
  url.pathname.startsWith("/api/media/") &&
  request.method === "GET"
) {
  try {
    if (!env.MEDIA) {
      return jsonResponse({
        success: false,
        message: "MEDIA binding missing"
      }, 500);
    }

    const key = decodeURIComponent(
      url.pathname.slice("/api/media/".length)
    );

    if (!/^[a-zA-Z0-9_-]{1,80}$/.test(key)) {
      return jsonResponse({
        success: false,
        message: "Invalid media key"
      }, 400);
    }

    const dataUrl = await env.MEDIA.get(`media:${key}`);

    if (!dataUrl) {
      return jsonResponse({
        success: false,
        message: "Image not found"
      }, 404);
    }

    const match = dataUrl.match(
      /^data:image\/(png|jpeg|webp|gif);base64,([A-Za-z0-9+/=]+)$/
    );

    if (!match) {
      return jsonResponse({
        success: false,
        message: "Invalid stored image"
      }, 500);
    }

    const mime = `image/${match[1]}`;
    const binary = atob(match[2]);
    const bytes = Uint8Array.from(
      binary,
      character => character.charCodeAt(0)
    );

    return new Response(bytes, {
      headers: {
        ...corsHeaders,
        "Content-Type": mime,
        "Cache-Control": "public, max-age=3600",
        "X-Content-Type-Options": "nosniff"
      }
    });

  } catch (error) {
    return jsonResponse({
      success: false,
      message: "Media retrieval failed"
    }, 500);
  }
}
    // Other requests go to website assets
    return env.ASSETS.fetch(request);
  }
};
