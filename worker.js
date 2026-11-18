/*
 * DEVON Play Worker
 *
 * Public:    GET /api/health, GET /api/config, GET /api/media/:key,
 *            POST /api/customer/register, POST /api/customer/login, GET /api/customer/session
 * Customer:  POST /api/customer/orders, GET /api/customer/orders,
 *            GET /api/customer/screenshot/:code, POST /api/customer/saved-ids
 * Admin:     POST /api/admin/login, GET /api/admin/session,
 *            GET /api/admin/orders, POST /api/admin/orders/update, POST /api/admin/orders/delete,
 *            GET /api/admin/customers, POST /api/admin/customers/delete,
 *            POST /api/admin/config, POST /api/admin/media, GET /api/admin/screenshot/:code,
 *            POST /api/admin/telegram/test
 *
 * Bindings:  DB (D1), MEDIA (KV), ASSETS
 * Secrets:   ADMIN_PASSWORD, CUSTOMER_TOKEN_SECRET
 *            optional: ADMIN_TOKEN_SECRET, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID
 */
const encoder = new TextEncoder();
const CUSTOMER_TOKEN_LIFETIME = 7 * 24 * 60 * 60 * 1000;
const ADMIN_TOKEN_LIFETIME = 60 * 60 * 1000;
const DELIVERY_SECONDS = 120;
const ID_RE = /^[a-zA-Z0-9_-]{1,40}$/;
const IMG_URL_RE = /^\/api\/media\/[a-zA-Z0-9_-]{1,80}$/;
const DATA_IMG_RE = /^data:image\/(png|jpeg|webp|gif);base64,([A-Za-z0-9+/=]+)$/;
const CODE_RE = /^[A-Za-z0-9_-]{1,60}$/;
const STATUSES = ["Pending", "Submitted", "Payment Under Review", "Approved", "Delivery in Progress", "Delivered", "Rejected"];
const CFG = { catalog: "dp_catalog", payments: "dp_payments", site: "dp_site" };
const PAY_LABEL = { kbz: "KBZPay", wave: "WavePay" };

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization"
};

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
const bad = (m) => { throw new HttpError(400, m); };

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json", "Cache-Control": "no-store" }
  });
}

/* ---------- crypto helpers ---------- */
function toBase64(bytes) { return btoa(String.fromCharCode(...new Uint8Array(bytes))); }
function fromBase64(value) { return Uint8Array.from(atob(value), c => c.charCodeAt(0)); }

async function safeEqual(a, b) {
  const [x, y] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(String(a))),
    crypto.subtle.digest("SHA-256", encoder.encode(String(b)))
  ]);
  const u = new Uint8Array(x), v = new Uint8Array(y);
  let d = 0;
  for (let i = 0; i < u.length; i++) d |= u[i] ^ v[i];
  return d === 0;
}

async function hashCustomerPassword(password, salt) {
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 310000, hash: "SHA-256" }, key, 256);
  return toBase64(bits);
}

async function createSignature(data, secret) {
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, encoder.encode(data));
  return btoa(String.fromCharCode(...new Uint8Array(sig)));
}

async function verifySignature(payload, signature, secret) {
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
  return crypto.subtle.verify("HMAC", key, fromBase64(signature), encoder.encode(payload));
}

async function createCustomerToken(customerId, secret) {
  const payload = toBase64(encoder.encode(JSON.stringify({ sub: customerId, expires: Date.now() + CUSTOMER_TOKEN_LIFETIME })));
  return `${payload}.${await createSignature(payload, secret)}`;
}

async function verifyCustomerToken(token, secret) {
  try {
    if (!secret || typeof token !== "string") return null;
    const parts = token.split(".");
    if (parts.length !== 2) return null;
    if (!(await verifySignature(parts[0], parts[1], secret))) return null;
    const data = JSON.parse(new TextDecoder().decode(fromBase64(parts[0])));
    if (typeof data.sub !== "string" || !Number.isFinite(data.expires) || data.expires <= Date.now()) return null;
    return data;
  } catch { return null; }
}

const adminKey = (env) => env.ADMIN_TOKEN_SECRET || env.ADMIN_PASSWORD;

async function verifyAdminToken(token, env) {
  try {
    const key = adminKey(env);
    if (!key || typeof token !== "string") return false;
    const parts = token.split(".");
    if (parts.length !== 2) return false;
    if (!(await verifySignature(parts[0], parts[1], key))) return false;
    const data = JSON.parse(atob(parts[0]));
    return Number.isFinite(data.expires) && data.expires > Date.now();
  } catch { return false; }
}

const bearer = (request) => {
  const a = request.headers.get("Authorization") || "";
  return a.startsWith("Bearer ") ? a.slice(7) : "";
};

async function authCustomer(request, env) {
  const s = await verifyCustomerToken(bearer(request), env.CUSTOMER_TOKEN_SECRET);
  return s ? s.sub : null;
}

/* ---------- misc helpers ---------- */
async function readJson(request, max = 4 * 1024 * 1024) {
  if (Number(request.headers.get("Content-Length") || 0) > max) throw new HttpError(413, "Request too large");
  let text;
  try { text = await request.text(); } catch { throw new HttpError(400, "Invalid request"); }
  if (text.length > max) throw new HttpError(413, "Request too large");
  let b;
  try { b = JSON.parse(text); } catch { throw new HttpError(400, "Invalid JSON"); }
  if (!b || typeof b !== "object" || Array.isArray(b)) throw new HttpError(400, "Invalid request");
  return b;
}

const normPhone = (s) => String(s || "").replace(/[\s\-().]/g, "");
const str = (v, max) => String(v ?? "").trim().slice(0, max);
const clientIp = (request) => request.headers.get("CF-Connecting-IP") || "unknown";

// Atomic counter in one SQL statement (no read-modify-write race).
// If the limiter itself errors: failClosed=true -> throws 503 (request blocked),
// otherwise the request is allowed and the error is logged.
async function rateLimit(env, bucket, max, windowMs, failClosed = false) {
  try {
    const key = "rl:" + bucket, now = Date.now();
    const row = await env.DB.prepare(`
      INSERT INTO website_settings (setting_key, setting_value, updated_at)
      VALUES (?, json_object('c', 1, 't', ?), datetime('now'))
      ON CONFLICT(setting_key) DO UPDATE SET
        setting_value = CASE
          WHEN ? - json_extract(setting_value, '$.t') > ? THEN json_object('c', 1, 't', ?)
          ELSE json_set(setting_value, '$.c', json_extract(setting_value, '$.c') + 1)
        END,
        updated_at = datetime('now')
      RETURNING json_extract(setting_value, '$.c') AS c
    `).bind(key, now, now, windowMs, now).first();
    if (!row) throw new Error("Rate limit counter returned no row");
    if (Math.random() < 0.02) {
      // housekeeping: drop counters older than 24h (a failure here must not affect the check)
      try {
        await env.DB.prepare("DELETE FROM website_settings WHERE setting_key LIKE 'rl:%' AND ? - json_extract(setting_value, '$.t') > 86400000").bind(now).run();
      } catch { /* ignore */ }
    }
    return Number(row.c) <= max;
  } catch (e) {
    console.error("Rate limit check failed:", e && e.message);
    if (failClosed) throw new HttpError(503, "Login is temporarily unavailable. Please try again later.");
    return true;
  }
}

async function getSetting(env, key) {
  const row = await env.DB.prepare("SELECT setting_value AS v FROM website_settings WHERE setting_key = ?").bind(key).first();
  if (!row) return null;
  try { return JSON.parse(row.v); } catch { return null; }
}

async function putSetting(env, key, value) {
  await env.DB.prepare(`INSERT INTO website_settings (setting_key, setting_value, updated_at) VALUES (?, ?, datetime('now'))
    ON CONFLICT(setting_key) DO UPDATE SET setting_value = excluded.setting_value, updated_at = excluded.updated_at`)
    .bind(key, JSON.stringify(value)).run();
}

function imageResponse(dataUrl, cache) {
  const m = String(dataUrl).match(DATA_IMG_RE);
  if (!m) return jsonResponse({ success: false, message: "Invalid stored image" }, 500);
  const bytes = Uint8Array.from(atob(m[2]), c => c.charCodeAt(0));
  return new Response(bytes, {
    headers: { ...corsHeaders, "Content-Type": `image/${m[1]}`, "Cache-Control": cache, "X-Content-Type-Options": "nosniff" }
  });
}

/* ---------- Telegram (never breaks the request) ----------
 * Each event has one row: website_settings "tg:<event>" = {"s":"pending"|"sent","t":ms}.
 * - pending claim blocks other senders for TG_CLAIM_TTL, then can be taken over (crashed sender)
 * - sent  = never sent again
 * - failed send OR any error before delivery releases the claim, so the same admin action can retry it
 * - if Telegram already accepted the message but marking "sent" fails, the claim is NOT released
 *   (releasing would cause a duplicate message)
 * - release only deletes the claim this call created (value match), never someone else's
 */
const TG_CLAIM_TTL = 5 * 60 * 1000;

async function telegramPost(env, text) {
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const res = await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ chat_id: env.TELEGRAM_CHAT_ID, text: text.slice(0, 3900), disable_web_page_preview: true })
      });
      if (res.ok) return true;
      console.error("Telegram rejected message, status", res.status);
      if (res.status !== 429 && res.status < 500) return false; // bad token/chat id: retrying won't help
    } catch { console.error("Telegram request failed"); }
    if (attempt === 0) await new Promise(r => setTimeout(r, 1000));
  }
  return false;
}

async function releaseClaim(env, dk, claim) {
  await env.DB.prepare("DELETE FROM website_settings WHERE setting_key = ? AND setting_value = ?").bind(dk, claim).run();
}

async function markSent(env, dk) {
  await env.DB.prepare("UPDATE website_settings SET setting_value = ? WHERE setting_key = ?").bind(JSON.stringify({ s: "sent", t: Date.now() }), dk).run();
}

async function sendTelegramOnce(env, eventKey, text) {
  const dk = "tg:" + eventKey;
  const claim = JSON.stringify({ s: "pending", t: Date.now() });
  let claimed = false, delivered = false;
  try {
    let r = await env.DB.prepare("INSERT OR IGNORE INTO website_settings (setting_key, setting_value) VALUES (?, ?)").bind(dk, claim).run();
    if (!r.meta || !r.meta.changes) {
      const row = await env.DB.prepare("SELECT setting_value AS v FROM website_settings WHERE setting_key = ?").bind(dk).first();
      if (!row) return;
      let st = null;
      try { st = JSON.parse(row.v); } catch {}
      if (st && (st.s === "sent" || (st.s === "pending" && Date.now() - st.t < TG_CLAIM_TTL))) return;
      // stale or unreadable claim: take it over atomically
      r = await env.DB.prepare("UPDATE website_settings SET setting_value = ? WHERE setting_key = ? AND setting_value = ?").bind(claim, dk, row.v).run();
      if (!r.meta || !r.meta.changes) return;
    }
    claimed = true;
    if (await telegramPost(env, text)) {
      delivered = true;
      await markSent(env, dk);
    } else {
      await releaseClaim(env, dk, claim);
    }
  } catch (e) {
    console.error("Telegram notify error:", e && e.message);
    try {
      if (delivered) await markSent(env, dk);            // message was sent: keep it from being re-sent
      else if (claimed) await releaseClaim(env, dk, claim); // not sent: allow a retry
    } catch { /* nothing more we can do */ }
  }
}

function notify(env, ctx, eventKey, text) {
  if (!env.TELEGRAM_BOT_TOKEN || !env.TELEGRAM_CHAT_ID) return;
  ctx.waitUntil(sendTelegramOnce(env, eventKey, text));
}

/* ---------- order mapping ---------- */
function mapOrder(o, admin) {
  const code = o.order_code || String(o.id);
  const hasShot = String(o.screenshot_url || "").startsWith("shot:");
  return {
    id: code,
    db_id: o.id,
    name: o.customer_name || "",
    phone: o.customer_phone || "",
    email: o.customer_email || "",
    uid: o.user_id || "",
    gameName: o.game || "",
    folder: o.folder || "",
    prod: o.product_name || "",
    quantity: o.quantity || 1,
    price: o.price || 0,
    bonus: o.bonus || "",
    player: o.player_id || "",
    zone: o.zone_id || "",
    extra: o.extra || "",
    telegram: o.telegram || "",
    pay: o.payment_method || "",
    screenshot: hasShot ? `/api/${admin ? "admin" : "customer"}/screenshot/${code}` : (admin ? (o.screenshot_url || "") : ""),
    timestamp: o.order_timestamp || o.created_at,
    status: o.status || "Pending",
    reason: o.rejection_reason || "",
    delivery_end: o.delivery_end || 0,
    delivery_remaining: o.delivery_remaining || 0
  };
}

/* ---------- config sanitizers ---------- */
function img(v) {
  v = String(v || "");
  if (v === "") return "";
  if (IMG_URL_RE.test(v)) return v;
  bad("Images must be uploaded first (use /api/admin/media)");
}
function imgList(a, max) {
  if (a === undefined || a === null) return [];
  if (!Array.isArray(a) || a.length > max) bad("Too many images");
  return a.map(img);
}
const num = (v, min, max) => { const n = Number(v); return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : min; };

function sanitizeCatalog(v) {
  if (!v || typeof v !== "object" || !Array.isArray(v.games) || v.games.length > 30) bad("Invalid catalog");
  const seen = new Set();
  const games = v.games.map(g => {
    if (!g || typeof g !== "object") bad("Invalid game");
    const id = String(g.id || "");
    if (!ID_RE.test(id) || seen.has(id)) bad("Invalid or duplicate game id");
    seen.add(id);
    if (!Array.isArray(g.folders) || g.folders.length > 40) bad("Invalid folders");
    const pseen = new Set(), fseen = new Set();
    return {
      id, name: str(g.name, 80) || id, desc: str(g.desc, 300), img: img(g.img), on: g.on ? 1 : 0,
      pidLabel: str(g.pidLabel, 40) || "Player ID", zone: !!g.zone, zoneLabel: str(g.zoneLabel, 40) || "Zone ID",
      extra: str(g.extra, 80), banners: imgList(g.banners, 5),
      folders: g.folders.map(f => {
        if (!f || typeof f !== "object") bad("Invalid folder");
        const fid = String(f.id || "");
        if (!ID_RE.test(fid) || fseen.has(fid)) bad("Invalid or duplicate folder id");
        fseen.add(fid);
        if (!Array.isArray(f.products) || f.products.length > 200) bad("Invalid products");
        return {
          id: fid, name: str(f.name, 80) || fid,
          products: f.products.map(p => {
            if (!p || typeof p !== "object") bad("Invalid product");
            const pid = String(p.id || "");
            if (!ID_RE.test(pid) || pseen.has(pid)) bad("Invalid or duplicate product id");
            pseen.add(pid);
            return {
              id: pid, name: str(p.name, 120) || pid, qty: Math.round(num(p.qty, 0, 1e9)),
              price: num(p.price, 0, 1e9), bonus: str(p.bonus, 80), disc: num(p.disc, 0, 90),
              img: img(p.img), desc: str(p.desc, 300), avail: p.avail === "out" ? "out" : "in"
            };
          })
        };
      })
    };
  });
  const chars = {};
  if (v.chars && typeof v.chars === "object") {
    const ks = Object.keys(v.chars);
    if (ks.length > 30) bad("Too many character images");
    for (const k of ks) { if (!ID_RE.test(k)) bad("Invalid character key"); chars[k] = img(v.chars[k]); }
  }
  return { games, banners: imgList(v.banners, 10), logo: img(v.logo), chars };
}

function sanitizePayments(v) {
  if (!v || typeof v !== "object") bad("Invalid payment settings");
  const out = {};
  for (const k of ["kbz", "wave"]) {
    const p = v[k] || {};
    out[k] = { on: p.on ? 1 : 0, qr: img(p.qr), name: str(p.name, 80), phone: str(p.phone, 30) };
  }
  return out;
}

function sanitizeSite(v) {
  if (!v || typeof v !== "object") bad("Invalid settings");
  const tg = str(v.tg, 200);
  if (tg && !/^https?:\/\/[^\s"'<>]+$/.test(tg)) bad("Telegram link must start with https://");
  return {
    name: str(v.name, 60) || "DEVON Play", desc: str(v.desc, 300), status: v.status === "open" ? "open" : "maint",
    tg, phone: str(v.phone, 30), email: str(v.email, 120), footer: str(v.footer, 300), promo: str(v.promo, 200)
  };
}

const SANITIZERS = { catalog: sanitizeCatalog, payments: sanitizePayments, site: sanitizeSite };

/* ---------- handlers ---------- */
async function customerOrderCreate(request, env, ctx, cid) {
  const body = await readJson(request);
  const customer = await env.DB.prepare("SELECT id, name, phone, email, saved_game_ids FROM customers WHERE id = ?").bind(cid).first();
  if (!customer) throw new HttpError(404, "Customer not found");

  const [catalog, payments, site] = await Promise.all([
    getSetting(env, CFG.catalog), getSetting(env, CFG.payments), getSetting(env, CFG.site)
  ]);
  if (site && site.status !== "open") throw new HttpError(503, "The shop is in maintenance mode");
  if (!catalog) throw new HttpError(503, "The shop catalog is not configured yet");

  const game = catalog.games.find(g => g.id === String(body.game));
  const folder = game && game.folders.find(f => f.id === String(body.folder));
  const prod = folder && folder.products.find(p => p.id === String(body.prod));
  if (!game || !game.on || !prod || prod.avail === "out") bad("This product is not available");

  const qty = Number(body.qty);
  if (!Number.isInteger(qty) || qty < 1 || qty > 20) bad("Invalid quantity");

  const payKey = String(body.pay);
  if (!PAY_LABEL[payKey] || !payments || !payments[payKey] || !payments[payKey].on) bad("Payment method unavailable");

  const phone = normPhone(body.phone);
  if (!/^\+?[0-9]{5,20}$/.test(phone)) bad("Invalid phone number");
  const player = str(body.player, 64), zone = str(body.zone, 64), extra = str(body.extra, 200), tg = str(body.tg, 64);
  if (!player) bad("Player ID is required");
  if (game.zone && !zone) bad("Zone ID is required");

  const shot = String(body.shot || "");
  if (!DATA_IMG_RE.test(shot) || shot.length > 3 * 1024 * 1024) bad("Invalid or too large payment screenshot");

  const unit = Math.round(prod.price * (1 - (prod.disc || 0) / 100));
  const total = unit * qty;
  if (!(total > 0)) bad("This product is not available");
  const rnd = crypto.getRandomValues(new Uint8Array(3));
  const code = "ORD-" + Date.now().toString(36).toUpperCase() + Array.from(rnd, b => (b % 36).toString(36)).join("").toUpperCase();
  const shotKey = "shot:" + code;
  const now = Date.now();

  try { await env.MEDIA.put(shotKey, shot); }
  catch { throw new HttpError(500, "Screenshot upload failed"); }

  let rowId;
  try {
    const r = await env.DB.prepare(`
      INSERT INTO orders
      (game, product_name, quantity, player_id, payment_method, screenshot_url, status, order_code, user_id,
       customer_name, customer_phone, customer_email, folder, price, bonus, zone_id, extra, telegram, order_timestamp)
      VALUES (?, ?, ?, ?, ?, ?, 'Payment Under Review', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(game.name, prod.name, qty, player, PAY_LABEL[payKey], shotKey, code, customer.id,
      customer.name, phone, customer.email || "", folder.name, total, prod.bonus || "", zone, extra, tg, now).run();
    rowId = r.meta.last_row_id;
  } catch {
    try { await env.MEDIA.delete(shotKey); } catch {}
    throw new HttpError(500, "Could not save order");
  }

  // remember the player details for next time (best effort)
  try {
    let saved = {};
    try { saved = JSON.parse(customer.saved_game_ids || "{}") || {}; } catch {}
    saved[game.id] = { pid: player, zone, tg, extra };
    await env.DB.prepare("UPDATE customers SET saved_game_ids = ? WHERE id = ?").bind(JSON.stringify(saved), customer.id).run();
  } catch {}

  notify(env, ctx, `order:${code}:new`,
    `🆕 New order ${code}\nCustomer: ${customer.name} (${phone})\nGame: ${game.name}\nProduct: ${prod.name} × ${qty}\n` +
    `Price: ${total.toLocaleString("en-US")} MMK\nPlayer ID: ${player}${zone ? " (" + zone + ")" : ""}\nPayment: ${PAY_LABEL[payKey]}\nStatus: Payment Under Review`);

  const row = await env.DB.prepare("SELECT * FROM orders WHERE id = ?").bind(rowId).first();
  return jsonResponse({ success: true, order: mapOrder(row, false), now }, 201);
}

async function adminUpdateOrder(request, env, ctx) {
  const body = await readJson(request);
  const dbId = Number(body.db_id);
  if (!Number.isInteger(dbId) || dbId <= 0) bad("Invalid order data");
  const o = await env.DB.prepare("SELECT * FROM orders WHERE id = ?").bind(dbId).first();
  if (!o) throw new HttpError(404, "Order not found");

  const now = Date.now();
  let status = o.status, reason = "", end = Number(o.delivery_end) || 0, remain = Number(o.delivery_remaining) || 0;
  const action = body.action ? String(body.action) : "";

  if (action) {
    switch (action) {
      case "review": status = "Payment Under Review"; end = 0; remain = 0; break;
      case "approve": status = "Approved"; end = now + DELIVERY_SECONDS * 1000; remain = DELIVERY_SECONDS; break;
      case "start": {
        status = "Delivery in Progress";
        const s = remain > 0 && !end ? remain : (end > now ? Math.ceil((end - now) / 1000) : DELIVERY_SECONDS);
        end = now + s * 1000; remain = s; break;
      }
      case "stop": if (end) remain = Math.max(0, Math.ceil((end - now) / 1000)); end = 0; break;
      case "deliver": status = "Delivered"; end = 0; remain = 0; break;
      case "reject": status = "Rejected"; reason = str(body.reason, 500); end = 0; remain = 0; break;
      default: bad("Unknown action");
    }
  } else {
    // legacy form: explicit status and timer values
    if (!STATUSES.includes(body.status)) bad("Invalid order data");
    status = body.status; reason = str(body.reason, 500);
    end = Number(body.delivery_end) || 0; remain = Number(body.delivery_remaining) || 0;
  }

  await env.DB.prepare(`UPDATE orders SET status = ?, rejection_reason = ?, delivery_end = ?, delivery_remaining = ? WHERE id = ?`)
    .bind(status, reason, end, remain, dbId).run();

  const code = o.order_code || String(o.id);
  {
    const ev = { Approved: ["approved", "✅"], Rejected: ["rejected", "❌"], Delivered: ["delivered", "📦"] }[status];
    if (ev) notify(env, ctx, `order:${code}:${ev[0]}`,
      `${ev[1]} Order ${code} ${ev[0]}\nCustomer: ${o.customer_name || ""}\n${o.game || ""} · ${o.product_name || ""} × ${o.quantity}` +
      (status === "Rejected" && reason ? `\nReason: ${reason}` : ""));
  }

  const row = await env.DB.prepare("SELECT * FROM orders WHERE id = ?").bind(dbId).first();
  return jsonResponse({ success: true, message: "Order updated", order: mapOrder(row, true), now });
}

async function handle(request, env, ctx) {
  const url = new URL(request.url);
  const p = url.pathname, m = request.method;

  if (m === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders });

  /* ----- public ----- */
  if (p === "/api/admin/login" && m === "POST") {
    if (!env.ADMIN_PASSWORD) throw new HttpError(500, "Server configuration error");
    if (!(await rateLimit(env, "alogin:" + clientIp(request), 8, 15 * 60 * 1000, true))) throw new HttpError(429, "Too many attempts. Try again later.");
    const body = await readJson(request, 4096);
    if (typeof body.password !== "string" || body.password.length > 256 || !(await safeEqual(body.password, env.ADMIN_PASSWORD))) {
      return jsonResponse({ success: false, message: "Wrong password" }, 401);
    }
    const payload = btoa(JSON.stringify({ expires: Date.now() + ADMIN_TOKEN_LIFETIME }));
    return jsonResponse({ success: true, token: `${payload}.${await createSignature(payload, adminKey(env))}` });
  }

  if (p === "/api/customer/register" && m === "POST") {
    if (!env.CUSTOMER_TOKEN_SECRET) throw new HttpError(500, "Server configuration error");
    if (!(await rateLimit(env, "reg:" + clientIp(request), 10, 60 * 60 * 1000))) throw new HttpError(429, "Too many attempts. Try again later.");
    const body = await readJson(request, 8192);
    const name = String(body.name || "").trim();
    const phone = normPhone(body.phone);
    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "");
    if (name.length < 2 || name.length > 100 || !/^\+?[0-9]{5,25}$/.test(phone) ||
        email.length > 254 || (email !== "" && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) ||
        password.length < 8 || password.length > 128) {
      return jsonResponse({ success: false, message: "Invalid registration details" }, 400);
    }
    const dup = await env.DB.prepare("SELECT id FROM customers WHERE REPLACE(REPLACE(phone, ' ', ''), '-', '') = ? LIMIT 1").bind(phone).first();
    if (dup) return jsonResponse({ success: false, message: "Phone number already registered" }, 409);

    const salt = crypto.getRandomValues(new Uint8Array(16));
    const passwordHash = await hashCustomerPassword(password, salt);
    const customerId = "U" + crypto.randomUUID();
    try {
      await env.DB.prepare(`INSERT INTO customers (id, name, phone, email, password_hash, password_salt) VALUES (?, ?, ?, ?, ?, ?)`)
        .bind(customerId, name, phone, email || null, passwordHash, toBase64(salt)).run();
    } catch (e) {
      if (String(e.message).includes("UNIQUE")) return jsonResponse({ success: false, message: "Phone number already registered" }, 409);
      throw e;
    }
    const token = await createCustomerToken(customerId, env.CUSTOMER_TOKEN_SECRET);
    return jsonResponse({ success: true, token, customer: { id: customerId, name, phone, email, saved: {} } }, 201);
  }

  if (p === "/api/customer/login" && m === "POST") {
    if (!env.CUSTOMER_TOKEN_SECRET) throw new HttpError(500, "Server configuration error");
    if (!(await rateLimit(env, "login:" + clientIp(request), 15, 10 * 60 * 1000))) throw new HttpError(429, "Too many attempts. Try again later.");
    const body = await readJson(request, 4096);
    const identifier = String(body.identifier || "").trim();
    const password = String(body.password || "");
    if (!identifier || identifier.length > 254 || !password || password.length > 128) {
      return jsonResponse({ success: false, message: "Invalid login details" }, 400);
    }
    const customer = await env.DB.prepare(`
      SELECT * FROM customers
      WHERE phone = ? OR REPLACE(REPLACE(phone, ' ', ''), '-', '') = ? OR (email IS NOT NULL AND email = ?)
      LIMIT 1
    `).bind(identifier, normPhone(identifier), identifier.toLowerCase()).first();
    if (!customer) return jsonResponse({ success: false, message: "Incorrect login details" }, 401);

    const hash = await hashCustomerPassword(password, fromBase64(customer.password_salt));
    if (!(await safeEqual(hash, customer.password_hash))) return jsonResponse({ success: false, message: "Incorrect login details" }, 401);

    let saved = {};
    try { saved = JSON.parse(customer.saved_game_ids || "{}") || {}; } catch {}
    const token = await createCustomerToken(customer.id, env.CUSTOMER_TOKEN_SECRET);
    return jsonResponse({ success: true, token, customer: { id: customer.id, name: customer.name, phone: customer.phone, email: customer.email || "", saved } });
  }

  if (p === "/api/customer/session" && m === "GET") {
    const cid = await authCustomer(request, env);
    if (!cid) return jsonResponse({ success: false, message: "Unauthorized" }, 401);
    const c = await env.DB.prepare("SELECT id, name, phone, email, saved_game_ids, created_at FROM customers WHERE id = ?").bind(cid).first();
    if (!c) return jsonResponse({ success: false, message: "Customer not found" }, 404);
    let saved = {};
    try { saved = JSON.parse(c.saved_game_ids || "{}") || {}; } catch {}
    return jsonResponse({ success: true, customer: { ...c, email: c.email || "", saved } });
  }

  if (p === "/api/config" && m === "GET") {
    const [catalog, payments, site] = await Promise.all([
      getSetting(env, CFG.catalog), getSetting(env, CFG.payments), getSetting(env, CFG.site)
    ]);
    return jsonResponse({ success: true, catalog, payments, site, now: Date.now() });
  }

  if (p === "/api/health" && m === "GET") {
    try {
      const result = await env.DB.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all();
      let media = "Not Connected";
      try { if (!env.MEDIA) throw 0; await env.MEDIA.get("__devonplay_health_check__"); media = "Connected"; } catch {}
      const out = { success: true, database: "Connected", media };
      if (await verifyAdminToken(bearer(request), env)) out.tables = result.results;
      return jsonResponse(out);
    } catch (e) {
      return jsonResponse({ success: false, error: "Database not available" }, 500);
    }
  }

  if (p.startsWith("/api/media/") && m === "GET") {
    if (!env.MEDIA) throw new HttpError(500, "MEDIA binding missing");
    let key;
    try { key = decodeURIComponent(p.slice("/api/media/".length)); } catch { bad("Invalid media key"); }
    if (!/^[a-zA-Z0-9_-]{1,80}$/.test(key)) bad("Invalid media key");
    const dataUrl = await env.MEDIA.get(`media:${key}`);
    if (!dataUrl) throw new HttpError(404, "Image not found");
    return imageResponse(dataUrl, "public, max-age=3600");
  }

  /* ----- customer (token required) ----- */
  if (p.startsWith("/api/customer/")) {
    const cid = await authCustomer(request, env);
    if (!cid) return jsonResponse({ success: false, message: "Unauthorized" }, 401);
    // a deleted customer's still-valid token must stop working
    const exists = await env.DB.prepare("SELECT 1 AS ok FROM customers WHERE id = ?").bind(cid).first();
    if (!exists) return jsonResponse({ success: false, message: "Unauthorized" }, 401);

    if (p === "/api/customer/orders" && m === "POST") {
      if (!(await rateLimit(env, "order:" + cid, 20, 60 * 60 * 1000))) throw new HttpError(429, "Too many orders. Try again later.");
      return customerOrderCreate(request, env, ctx, cid);
    }
    if (p === "/api/customer/orders" && m === "GET") {
      const r = await env.DB.prepare("SELECT * FROM orders WHERE user_id = ? ORDER BY id DESC LIMIT 200").bind(cid).all();
      return jsonResponse({ success: true, orders: r.results.map(o => mapOrder(o, false)), now: Date.now() });
    }
    if (p.startsWith("/api/customer/screenshot/") && m === "GET") {
      const code = p.slice("/api/customer/screenshot/".length);
      if (!CODE_RE.test(code)) bad("Invalid order code");
      const o = await env.DB.prepare("SELECT user_id, screenshot_url FROM orders WHERE order_code = ?").bind(code).first();
      if (!o || o.user_id !== cid || !String(o.screenshot_url || "").startsWith("shot:")) throw new HttpError(404, "Not found");
      const d = await env.MEDIA.get(o.screenshot_url);
      if (!d) throw new HttpError(404, "Not found");
      return imageResponse(d, "private, no-store");
    }
    if (p === "/api/customer/saved-ids" && m === "POST") {
      const body = await readJson(request, 4096);
      const gid = String(body.game || "");
      if (!ID_RE.test(gid)) bad("Invalid game");
      const c = await env.DB.prepare("SELECT saved_game_ids FROM customers WHERE id = ?").bind(cid).first();
      if (!c) throw new HttpError(404, "Customer not found");
      let saved = {};
      try { saved = JSON.parse(c.saved_game_ids || "{}") || {}; } catch {}
      if (!saved[gid] && Object.keys(saved).length >= 50) bad("Too many saved games");
      saved[gid] = { ...saved[gid], pid: str(body.pid, 64), zone: str(body.zone, 64) };
      await env.DB.prepare("UPDATE customers SET saved_game_ids = ? WHERE id = ?").bind(JSON.stringify(saved), cid).run();
      return jsonResponse({ success: true, saved });
    }
    return jsonResponse({ success: false, message: "Not found" }, 404);
  }

  /* ----- admin (token required) ----- */
  if (p.startsWith("/api/admin/")) {
    if (!(await verifyAdminToken(bearer(request), env))) return jsonResponse({ success: false, message: "Unauthorized" }, 401);

    if (p === "/api/admin/session" && m === "GET") return jsonResponse({ success: true, message: "Admin session verified" });

    if (p === "/api/admin/orders" && m === "GET") {
      const r = await env.DB.prepare("SELECT * FROM orders ORDER BY id DESC").all();
      return jsonResponse({ success: true, orders: r.results.map(o => mapOrder(o, true)), now: Date.now() });
    }
    if (p === "/api/admin/orders/update" && m === "POST") return adminUpdateOrder(request, env, ctx);

    if (p === "/api/admin/orders/delete" && m === "POST") {
      const body = await readJson(request, 4096);
      const dbId = Number(body.db_id);
      if (!Number.isInteger(dbId) || dbId <= 0) bad("Invalid order data");
      const o = await env.DB.prepare("SELECT screenshot_url FROM orders WHERE id = ?").bind(dbId).first();
      if (!o) throw new HttpError(404, "Order not found");
      await env.DB.prepare("DELETE FROM orders WHERE id = ?").bind(dbId).run();
      if (String(o.screenshot_url || "").startsWith("shot:")) { try { await env.MEDIA.delete(o.screenshot_url); } catch {} }
      return jsonResponse({ success: true, message: "Order deleted" });
    }

    if (p === "/api/admin/customers" && m === "GET") {
      const r = await env.DB.prepare(`
        SELECT c.id, c.name, c.phone, c.email, c.saved_game_ids, c.created_at,
               (SELECT COUNT(*) FROM orders o WHERE o.user_id = c.id) AS order_count
        FROM customers c ORDER BY c.created_at DESC, c.id DESC LIMIT 5000`).all();
      const customers = r.results.map(c => {
        let saved = {};
        try { saved = JSON.parse(c.saved_game_ids || "{}") || {}; } catch {}
        return { id: c.id, name: c.name, phone: c.phone, email: c.email || "", saved, created_at: c.created_at, order_count: c.order_count || 0 };
      });
      return jsonResponse({ success: true, customers });
    }
    if (p === "/api/admin/customers/delete" && m === "POST") {
      const body = await readJson(request, 4096);
      const id = String(body.id || "");
      if (!id || id.length > 80) bad("Invalid customer");
      const kept = await env.DB.prepare("SELECT COUNT(*) AS n FROM orders WHERE user_id = ?").bind(id).first();
      const del = await env.DB.prepare("DELETE FROM customers WHERE id = ?").bind(id).run();
      if (!del.meta || !del.meta.changes) throw new HttpError(404, "Customer not found");
      return jsonResponse({ success: true, message: "Customer deleted", orders_kept: (kept && kept.n) || 0 });
    }

    if (p === "/api/admin/config" && m === "POST") {
      const body = await readJson(request, 1.5 * 1024 * 1024);
      const key = String(body.key || "");
      if (!SANITIZERS[key]) bad("Unknown config key");
      const clean = SANITIZERS[key](body.value);
      const text = JSON.stringify(clean);
      if (text.length > 1000000) bad("Configuration too large");
      await putSetting(env, CFG[key], clean);
      return jsonResponse({ success: true, key, value: clean });
    }

    if (p === "/api/admin/media" && m === "POST") {
      if (!env.MEDIA) throw new HttpError(500, "MEDIA binding missing");
      const body = await readJson(request, 6 * 1024 * 1024);
      const key = String(body.key || ""), dataUrl = String(body.dataUrl || "");
      if (!/^[a-zA-Z0-9_-]{1,80}$/.test(key) || !DATA_IMG_RE.test(dataUrl) || dataUrl.length > 4 * 1024 * 1024) {
        return jsonResponse({ success: false, message: "Invalid image or image too large" }, 400);
      }
      await env.MEDIA.put(`media:${key}`, dataUrl);
      return jsonResponse({ success: true, key, url: `/api/media/${key}` });
    }

    if (p.startsWith("/api/admin/screenshot/") && m === "GET") {
      const code = p.slice("/api/admin/screenshot/".length);
      if (!CODE_RE.test(code)) bad("Invalid order code");
      const d = await env.MEDIA.get("shot:" + code);
      if (!d) throw new HttpError(404, "Screenshot not found");
      return imageResponse(d, "private, no-store");
    }

    if (p === "/api/admin/telegram/test" && m === "POST") {
      if (!env.TELEGRAM_BOT_TOKEN || !env.TELEGRAM_CHAT_ID) return jsonResponse({ success: false, configured: false, message: "Telegram secrets are not set" });
      try {
        const res = await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ chat_id: env.TELEGRAM_CHAT_ID, text: "✅ DEVON Play: Telegram test message" })
        });
        return jsonResponse({ success: res.ok, configured: true, status: res.status });
      } catch { return jsonResponse({ success: false, configured: true, message: "Could not reach Telegram" }); }
    }

    return jsonResponse({ success: false, message: "Not found" }, 404);
  }

  /* ----- website assets ----- */
  if (!env.ASSETS) return jsonResponse({ success: false, message: "Not found" }, 404);
  return env.ASSETS.fetch(request);
}

// 500 messages of the original endpoints, kept so existing callers see the same text
function failureMessage(path) {
  if (path.startsWith("/api/media/")) return "Media retrieval failed";
  return {
    "/api/customer/register": "Registration failed",
    "/api/customer/login": "Login failed",
    "/api/admin/orders": "Could not load orders",
    "/api/admin/orders/update": "Could not update order",
    "/api/admin/media": "Media upload failed"
  }[path] || "Server error";
}

export default {
  async fetch(request, env, ctx) {
    try {
      return await handle(request, env, ctx);
    } catch (e) {
      if (e instanceof HttpError) return jsonResponse({ success: false, message: e.message }, e.status);
      console.error("Unhandled error:", e && e.message);
      return jsonResponse({ success: false, message: failureMessage(new URL(request.url).pathname) }, 500);
    }
  }
};
