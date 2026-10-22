/*
 * Trendify Nexus - single Worker edition
 * Panel + Gateways + Subscriptions + Configs + VLESS/WS proxy, all in ONE worker.
 *
 * Setup:
 *   1) Bind a D1 database with the binding name:  DB
 *   2) (optional) env vars:  ADMIN_PASSWORD  (first-run admin password, default "admin")
 *                            PROXYIP         (fallback proxy "host" or "host:port", comma separated)
 *                            CF_API_TOKEN / CF_ACCOUNT_ID / CF_DB_ID  (Worker gateways, optional;
 *                            can also be set from Settings in the panel)
 *   3) Deploy, open the worker URL, login admin / admin (change it in Settings).
 */
import { connect } from "cloudflare:sockets";

const APP_NAME = "Trendify Nexus";
const LEGACY_ADMIN_HASH =
  "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918";
const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const IPV4_RE =
  /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const SESSION_SECONDS = 604800;

const CF_RANGES_FALLBACK = [
  "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
  "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
  "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
  "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22"
];

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

const encoder = new TextEncoder();

function toHex(buf) {
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      ...extra
    }
  });
}

function plain(body, status = 200, extra = {}) {
  return new Response(body, {
    status,
    headers: {
      "Content-Type": "text/plain; charset=UTF-8",
      "Cache-Control": "no-store",
      ...extra
    }
  });
}

function randomString(length = 16) {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  let out = "";
  for (let i = 0; i < length; i++) out += chars[bytes[i] % chars.length];
  return out;
}

function randomHex(bytes) {
  return toHex(crypto.getRandomValues(new Uint8Array(bytes)));
}

function newUuid() {
  return crypto.randomUUID();
}

function cleanHost(v) {
  return String(v || "")
    .trim()
    .replace(/^https?:\/\//i, "")
    .replace(/\/.*$/, "")
    .toLowerCase();
}

async function sha256Hex(value) {
  return toHex(await crypto.subtle.digest("SHA-256", encoder.encode(String(value))));
}

function safeEqual(a, b) {
  a = String(a);
  b = String(b);
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

async function pbkdf2Hex(password, saltBytes, iterations) {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(String(password)),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: saltBytes, iterations },
    key,
    256
  );
  return toHex(bits);
}

async function makePasswordHash(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iterations = 100000;
  const h = await pbkdf2Hex(password, salt, iterations);
  return "pbkdf2$" + iterations + "$" + toHex(salt) + "$" + h;
}

async function verifyPassword(password, stored) {
  stored = String(stored || "");
  if (stored.startsWith("pbkdf2$")) {
    const parts = stored.split("$");
    if (parts.length !== 4) return false;
    const iterations = Number(parts[1]);
    const salt = new Uint8Array(
      (parts[2].match(/.{2}/g) || []).map((x) => parseInt(x, 16))
    );
    const h = await pbkdf2Hex(password, salt, iterations);
    return safeEqual(h, parts[3]);
  }
  // legacy plain sha256
  return safeEqual(await sha256Hex(password), stored);
}

function getCookie(request, name) {
  const header = request.headers.get("Cookie");
  if (!header) return null;
  for (const item of header.split(";")) {
    const i = item.indexOf("=");
    if (i === -1) continue;
    if (item.slice(0, i).trim() !== name) continue;
    const v = item.slice(i + 1).trim();
    try {
      return decodeURIComponent(v);
    } catch {
      return v;
    }
  }
  return null;
}

function sessionCookie(token) {
  return (
    "nexus_session=" + encodeURIComponent(token) +
    "; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=" + SESSION_SECONDS
  );
}

const CLEAR_COOKIE =
  "nexus_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";

async function readJson(request) {
  try {
    const b = await request.json();
    return b && typeof b === "object" ? b : {};
  } catch {
    return null;
  }
}

/* ------------------------------------------------------------------ */
/* database                                                            */
/* ------------------------------------------------------------------ */

let initPromise = null;

function init(env, host) {
  if (!initPromise) {
    initPromise = setupDatabase(env, host).catch((e) => {
      initPromise = null;
      throw e;
    });
  }
  return initPromise;
}

async function addColumns(env, table, cols) {
  const info = await env.DB.prepare("PRAGMA table_info(" + table + ")").all();
  const have = new Set((info.results || []).map((c) => c.name));
  for (const [name, def] of cols) {
    if (!have.has(name)) {
      await env.DB.prepare(
        "ALTER TABLE " + table + " ADD COLUMN " + name + " " + def
      ).run();
    }
  }
}

async function setupDatabase(env, host) {
  if (!env.DB) {
    throw new Error('D1 binding named "DB" is missing');
  }

  const creates = [
    `CREATE TABLE IF NOT EXISTS accounts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL,
      display_name TEXT,
      uuid TEXT,
      enabled INTEGER NOT NULL DEFAULT 1,
      data_limit INTEGER DEFAULT 0,
      data_used INTEGER DEFAULT 0,
      device_limit INTEGER DEFAULT 0,
      expires_at TEXT,
      note TEXT,
      service_id INTEGER,
      gateway_id INTEGER,
      created_at INTEGER NOT NULL DEFAULT (unixepoch()),
      updated_at INTEGER
    )`,
    `CREATE TABLE IF NOT EXISTS gateways (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      worker_name TEXT NOT NULL UNIQUE,
      worker_url TEXT,
      enabled INTEGER NOT NULL DEFAULT 1,
      region TEXT DEFAULT 'default',
      status TEXT DEFAULT 'unknown',
      latency_ms INTEGER DEFAULT NULL,
      last_seen TEXT DEFAULT NULL,
      last_error TEXT DEFAULT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS subscriptions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      account_id INTEGER NOT NULL,
      token TEXT NOT NULL UNIQUE,
      name TEXT,
      enabled INTEGER NOT NULL DEFAULT 1,
      scanner_ip TEXT DEFAULT 'auto',
      scanner_port INTEGER DEFAULT 443,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT
    )`,
    `CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT
    )`,
    `CREATE TABLE IF NOT EXISTS admin_users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 1,
      created_at INTEGER NOT NULL DEFAULT (unixepoch()),
      updated_at INTEGER
    )`,
    `CREATE TABLE IF NOT EXISTS admin_sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      token_hash TEXT NOT NULL UNIQUE,
      admin_id INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      created_at INTEGER NOT NULL DEFAULT (unixepoch())
    )`,
    `CREATE TABLE IF NOT EXISTS scanner_results (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      target TEXT NOT NULL,
      port INTEGER DEFAULT 443,
      protocol TEXT DEFAULT 'tls',
      status TEXT DEFAULT 'pending',
      latency_ms INTEGER DEFAULT NULL,
      ip TEXT DEFAULT NULL,
      country TEXT DEFAULT NULL,
      score INTEGER DEFAULT 0,
      last_checked TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS gateway_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      gateway_id INTEGER DEFAULT 0,
      event TEXT,
      detail TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )`
  ];

  await env.DB.batch(creates.map((s) => env.DB.prepare(s)));

  // migrations for databases created by older versions
  await addColumns(env, "accounts", [
    ["display_name", "TEXT"],
    ["uuid", "TEXT"],
    ["note", "TEXT"],
    ["updated_at", "INTEGER"],
    ["data_limit", "INTEGER DEFAULT 0"],
    ["data_used", "INTEGER DEFAULT 0"],
    ["device_limit", "INTEGER DEFAULT 0"],
    ["expires_at", "TEXT"],
    ["service_id", "INTEGER"],
    ["gateway_id", "INTEGER"]
  ]);
  await addColumns(env, "gateways", [
    ["region", "TEXT DEFAULT 'default'"],
    ["status", "TEXT DEFAULT 'unknown'"],
    ["latency_ms", "INTEGER DEFAULT NULL"],
    ["last_seen", "TEXT DEFAULT NULL"],
    ["last_error", "TEXT DEFAULT NULL"]
  ]);
  await addColumns(env, "subscriptions", [
    ["name", "TEXT"],
    ["scanner_ip", "TEXT DEFAULT 'auto'"],
    ["scanner_port", "INTEGER DEFAULT 443"],
    ["updated_at", "TEXT"]
  ]);
  await addColumns(env, "scanner_results", [
    ["latency_ms", "INTEGER DEFAULT NULL"],
    ["ip", "TEXT DEFAULT NULL"],
    ["country", "TEXT DEFAULT NULL"],
    ["score", "INTEGER DEFAULT 0"],
    ["last_checked", "TEXT"]
  ]);

  // first admin
  const admin = await env.DB.prepare("SELECT id FROM admin_users LIMIT 1").first();
  if (!admin) {
    const pass = env.ADMIN_PASSWORD ? String(env.ADMIN_PASSWORD) : "admin";
    await env.DB.prepare(
      "INSERT INTO admin_users (username, password_hash, enabled) VALUES (?, ?, 1)"
    )
      .bind("admin", await makePasswordHash(pass))
      .run();
    if (!env.ADMIN_PASSWORD) {
      await env.DB.prepare(
        "INSERT OR REPLACE INTO settings (key, value) VALUES ('must_change_password', '1')"
      ).run();
    }
  }

  // default gateway = this worker
  const gw = await env.DB.prepare("SELECT id FROM gateways LIMIT 1").first();
  if (!gw) {
    await env.DB.prepare(
      `INSERT INTO gateways (name, worker_name, worker_url, enabled, region, status)
       VALUES ('Default', ?, ?, 1, 'default', 'unknown')`
    )
      .bind("gw-" + randomString(10), host)
      .run();
  }
}

async function getSetting(env, key) {
  const row = await env.DB.prepare("SELECT value FROM settings WHERE key = ? LIMIT 1")
    .bind(key)
    .first();
  return row ? row.value : null;
}

async function setSetting(env, key, value) {
  await env.DB.prepare(
    "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value"
  )
    .bind(key, value)
    .run();
}

function logEvent(env, ctx, gatewayId, event, detail) {
  ctx.waitUntil(
    env.DB.prepare(
      "INSERT INTO gateway_logs (gateway_id, event, detail) VALUES (?, ?, ?)"
    )
      .bind(
        Number(gatewayId || 0),
        String(event || "").slice(0, 60),
        String(detail || "").slice(0, 400)
      )
      .run()
      .then(() => {
        if (Math.random() < 0.02) {
          return env.DB.prepare(
            "DELETE FROM gateway_logs WHERE id < (SELECT MAX(id) - 500 FROM gateway_logs)"
          ).run();
        }
      })
      .catch(() => {})
  );
}

/* ------------------------------------------------------------------ */
/* main router                                                         */
/* ------------------------------------------------------------------ */

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const path = url.pathname.replace(/\/+$/, "") || "/";
      const method = request.method;

      // VLESS websocket endpoint: /ws or /ws/<gatewayId>
      const wsMatch = path.match(/^\/ws(?:\/(\d+))?$/);
      if (wsMatch) {
        if ((request.headers.get("Upgrade") || "").toLowerCase() !== "websocket") {
          return plain("WS Upgrade Required", 426);
        }
        await init(env, url.host);
        return handleVLESS(request, env, ctx, Number(wsMatch[1] || 0));
      }

      if (path === "/health" || path === "/api/health") {
        return json(
          { success: true, app: APP_NAME, status: "online", timestamp: new Date().toISOString() },
          200,
          { "Access-Control-Allow-Origin": "*" }
        );
      }

      if (method === "OPTIONS") {
        return new Response(null, {
          status: 204,
          headers: {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type"
          }
        });
      }

      await init(env, url.host);
      if (path === "/tg/webhook" && method === "POST") return await tgWebhook(request, env, ctx, url);
      // public subscription
      const sub = path.match(/^\/sub\/([^/]+)$/);
      if (sub && method === "GET") {
        return await publicSubscription(decodeURIComponent(sub[1]), env, url);
      }

      // panel
      if (path === "/" || path === "/dashboard") {
        return new Response(app(), {
          status: 200,
          headers: {
            "Content-Type": "text/html; charset=UTF-8",
            "Cache-Control": "no-store"
          }
        });
      }

      if (!path.startsWith("/api/")) return plain("Not Found", 404);

      // auth endpoints
      if (path === "/api/auth/login" && method === "POST") return await loginAdmin(request, env);
      if (path === "/api/auth/logout" && method === "POST") return await logoutAdmin(request, env);

      const admin = await getAuthenticatedAdmin(request, env);
      if (!admin) return json({ success: false, error: "Unauthorized" }, 401);

      if (path === "/api/auth/me" && method === "GET") return await currentAdmin(admin, env);
      if (path === "/api/auth/change-password" && method === "POST")
        return await changePassword(admin, request, env);

      if (path === "/api/stats" && method === "GET") return await getStats(env);

      // accounts
      if (path === "/api/accounts" && method === "GET") return await getAccounts(env);
      if (path === "/api/accounts" && method === "POST") return await createAccount(request, env);
      let m = path.match(/^\/api\/accounts\/(\d+)$/);
      if (m) {
        const id = Number(m[1]);
        if (method === "PUT") return await updateAccount(id, request, env);
        if (method === "PATCH") return await toggleAccount(id, env);
        if (method === "DELETE") return await deleteAccount(id, env);
      }
      m = path.match(/^\/api\/accounts\/(\d+)\/reset$/);
      if (m && method === "POST") return await resetTraffic(Number(m[1]), env);
      m = path.match(/^\/api\/accounts\/(\d+)\/config$/);
      if (m && method === "GET") return await accountConfig(Number(m[1]), env, url);

      // gateways
      if (path === "/api/gateways" && method === "GET") return await getGateways(env);
      if (path === "/api/gateways" && method === "POST") return await createGateway(request, env, url);
      m = path.match(/^\/api\/gateways\/(\d+)$/);
      if (m) {
        const id = Number(m[1]);
        if (method === "PUT") return await updateGateway(id, request, env, url);
        if (method === "PATCH") return await toggleGateway(id, env);
        if (method === "DELETE") return await deleteGateway(id, env);
      }
      m = path.match(/^\/api\/gateways\/(\d+)\/health-result$/);
      if (m && method === "POST") return await saveHealth(Number(m[1]), request, env);
      m = path.match(/^\/api\/gateways\/(\d+)\/redeploy$/);
      if (m && method === "POST") return await redeployGateway(Number(m[1]), env);

      // subscriptions
      if (path === "/api/subscriptions" && method === "GET") return await getSubscriptions(env);
      if (path === "/api/subscriptions" && method === "POST") return await createSubscription(request, env, url);
      m = path.match(/^\/api\/subscriptions\/(\d+)$/);
      if (m) {
        if (method === "DELETE") return await deleteSubscription(Number(m[1]), env);
        if (method === "PATCH") return await toggleSubscription(Number(m[1]), env);
      }

      // scanner
      if (path === "/api/scanner/results" && method === "GET") return await scannerResults(env);
      if (path === "/api/scanner/candidates" && method === "POST") return await scannerCandidates(request);
      if (path === "/api/scanner/save" && method === "POST") return await scannerSave(request, env);
      if (path === "/api/scanner/add" && method === "POST") return await scannerAdd(request, env);
      if (path === "/api/scanner" && method === "DELETE") {
        await env.DB.prepare("DELETE FROM scanner_results").run();
        return json({ success: true });
      }
      m = path.match(/^\/api\/scanner\/(\d+)$/);
      if (m && method === "DELETE") {
        await env.DB.prepare("DELETE FROM scanner_results WHERE id = ?").bind(Number(m[1])).run();
        return json({ success: true });
      }

      // logs + settings
      if (path === "/api/logs" && method === "GET") {
        const r = await env.DB.prepare(
          "SELECT id, gateway_id, event, detail, created_at FROM gateway_logs ORDER BY id DESC LIMIT 100"
        ).all();
        return json({ success: true, logs: r.results || [] });
      }
      if (path === "/api/logs" && method === "DELETE") {
        await env.DB.prepare("DELETE FROM gateway_logs").run();
        return json({ success: true });
      }
      if (path === "/api/settings" && method === "GET") {
        return json({
          success: true,
          settings: { proxy_ip: (await getSetting(env, "proxy_ip")) || "" },
          env_proxy_ip: env.PROXYIP ? String(env.PROXYIP) : "",
          host: url.host
        });
      }
      if (path === "/api/settings" && method === "POST") {
        const body = await readJson(request);
        if (!body) return json({ success: false, error: "Invalid JSON" }, 400);
        const v = String(body.proxy_ip || "").trim().slice(0, 300);
        if (v && !/^[A-Za-z0-9.:,_\-\s]+$/.test(v))
          return json({ success: false, error: "Invalid proxy value" }, 400);
        await setSetting(env, "proxy_ip", v);
        return json({ success: true });
      }
      if (path === "/api/telegram" && method === "GET") return await tgGetSettings(env, url);
      if (path === "/api/telegram" && method === "POST") return await tgSaveSettings(request, env);
      if (path === "/api/telegram/activate" && method === "POST") return await tgActivate(env, url);
      if (path === "/api/telegram/deactivate" && method === "POST") return await tgDeactivate(env);
      if (path === "/api/cfdeploy" && method === "GET") return await cfdGet(env);
      if (path === "/api/cfdeploy" && method === "POST") return await cfdSave(request, env);
      return json({ success: false, error: "Not Found" }, 404);
    } catch (error) {
      console.log("Nexus error:", error && error.message ? error.message : String(error));
      return json({ success: false, error: error && error.message ? error.message : String(error) }, 500);
    }
  }
};

/* ------------------------------------------------------------------ */
/* auth                                                                */
/* ------------------------------------------------------------------ */

async function loginAdmin(request, env) {
  const body = await readJson(request);
  if (!body) return json({ success: false, error: "Invalid JSON" }, 400);

  const username = String(body.username || "").trim();
  const password = String(body.password || "");
  if (!username || !password)
    return json({ success: false, error: "Username and password are required" }, 400);

  const admin = await env.DB.prepare(
    "SELECT id, username, password_hash, enabled FROM admin_users WHERE username = ? LIMIT 1"
  )
    .bind(username)
    .first();

  const ok =
    admin && Number(admin.enabled) === 1 && (await verifyPassword(password, admin.password_hash));
  if (!ok) return json({ success: false, error: "Invalid username or password" }, 401);

  // upgrade legacy hash silently
  if (!String(admin.password_hash).startsWith("pbkdf2$")) {
    await env.DB.prepare("UPDATE admin_users SET password_hash = ? WHERE id = ?")
      .bind(await makePasswordHash(password), admin.id)
      .run();
  }

  const now = Math.floor(Date.now() / 1000);
  await env.DB.prepare("DELETE FROM admin_sessions WHERE expires_at <= ?").bind(now).run();

  const token = randomHex(32);
  await env.DB.prepare(
    "INSERT INTO admin_sessions (token_hash, admin_id, expires_at) VALUES (?, ?, ?)"
  )
    .bind(await sha256Hex(token), admin.id, now + SESSION_SECONDS)
    .run();

  return json(
    { success: true, admin: { id: admin.id, username: admin.username } },
    200,
    { "Set-Cookie": sessionCookie(token) }
  );
}

async function getAuthenticatedAdmin(request, env) {
  const token = getCookie(request, "nexus_session");
  if (!token) return null;
  const tokenHash = await sha256Hex(token);
  const row = await env.DB.prepare(
    `SELECT a.id, a.username, a.enabled, s.expires_at
     FROM admin_sessions s JOIN admin_users a ON a.id = s.admin_id
     WHERE s.token_hash = ? LIMIT 1`
  )
    .bind(tokenHash)
    .first();
  if (!row || Number(row.enabled) !== 1) return null;
  if (Number(row.expires_at) <= Math.floor(Date.now() / 1000)) {
    await env.DB.prepare("DELETE FROM admin_sessions WHERE token_hash = ?").bind(tokenHash).run();
    return null;
  }
  return row;
}

async function currentAdmin(admin, env) {
  const row = await env.DB.prepare("SELECT password_hash FROM admin_users WHERE id = ?")
    .bind(admin.id)
    .first();
  const flag = await getSetting(env, "must_change_password");
  const isDefault =
    flag === "1" || (row && String(row.password_hash) === LEGACY_ADMIN_HASH);
  return json({
    success: true,
    admin: { id: admin.id, username: admin.username },
    default_password: !!isDefault
  });
}

async function logoutAdmin(request, env) {
  const token = getCookie(request, "nexus_session");
  if (token) {
    await env.DB.prepare("DELETE FROM admin_sessions WHERE token_hash = ?")
      .bind(await sha256Hex(token))
      .run();
  }
  return json({ success: true }, 200, { "Set-Cookie": CLEAR_COOKIE });
}

async function changePassword(admin, request, env) {
  const body = await readJson(request);
  if (!body) return json({ success: false, error: "Invalid JSON" }, 400);
  const current = String(body.current_password || "");
  const next = String(body.new_password || "");
  if (!current || !next)
    return json({ success: false, error: "Current password and new password are required" }, 400);
  if (next.length < 8)
    return json({ success: false, error: "New password must be at least 8 characters" }, 400);

  const stored = await env.DB.prepare("SELECT password_hash FROM admin_users WHERE id = ?")
    .bind(admin.id)
    .first();
  if (!stored || !(await verifyPassword(current, stored.password_hash)))
    return json({ success: false, error: "Current password is incorrect" }, 401);

  await env.DB.prepare(
    "UPDATE admin_users SET password_hash = ?, updated_at = unixepoch() WHERE id = ?"
  )
    .bind(await makePasswordHash(next), admin.id)
    .run();
  await setSetting(env, "must_change_password", "0");
  return json({ success: true, message: "Password changed successfully" });
}

/* ------------------------------------------------------------------ */
/* accounts                                                            */
/* ------------------------------------------------------------------ */

async function readAccountFields(body, env) {
  const username = String(body.username || "").trim().slice(0, 100);
  if (!username) return { error: "Username is required" };

  const display = String(body.display_name || "").trim().slice(0, 150) || username;

  let uid = String(body.uuid || "").trim().toLowerCase();
  if (!uid) uid = newUuid();
  if (!UUID_RE.test(uid)) return { error: "Invalid UUID" };

  const note = String(body.note || "").trim().slice(0, 500);
  const dataLimit = Math.max(0, Math.round(Number(body.data_limit) || 0));

  let expires = null;
  if (body.expires_at) {
    const t = Date.parse(String(body.expires_at));
    if (!Number.isFinite(t)) return { error: "Invalid expiry date" };
    expires = new Date(t).toISOString();
  }

  let gatewayId = null;
  if (body.gateway_id) {
    gatewayId = Number(body.gateway_id);
    if (!Number.isInteger(gatewayId) || gatewayId <= 0) return { error: "Invalid gateway_id" };
    const gw = await env.DB.prepare("SELECT id FROM gateways WHERE id = ? LIMIT 1")
      .bind(gatewayId)
      .first();
    if (!gw) return { error: "Gateway not found" };
  }

  return { username, display, uid, note, dataLimit, expires, gatewayId };
}

async function getAccounts(env) {
  const r = await env.DB.prepare(
    `SELECT a.id, a.username, a.display_name, a.uuid, a.enabled, a.data_limit, a.data_used,
            a.expires_at, a.note, a.gateway_id, a.created_at, a.updated_at,
            g.name AS gateway_name
     FROM accounts a LEFT JOIN gateways g ON g.id = a.gateway_id
     ORDER BY a.id DESC`
  ).all();
  return json({ success: true, accounts: r.results || [] });
}

async function createAccount(request, env) {
  const body = await readJson(request);
  if (!body) return json({ success: false, error: "Invalid JSON" }, 400);
  if (!String(body.username || "").trim()) body.username = "user-" + randomString(6);

  const f = await readAccountFields(body, env);
  if (f.error) return json({ success: false, error: f.error }, 400);

  const dupUser = await env.DB.prepare("SELECT id FROM accounts WHERE username = ? LIMIT 1")
    .bind(f.username)
    .first();
  if (dupUser) return json({ success: false, error: "Username already exists" }, 400);
  const dupUuid = await env.DB.prepare("SELECT id FROM accounts WHERE uuid = ? LIMIT 1")
    .bind(f.uid)
    .first();
  if (dupUuid) return json({ success: false, error: "UUID already exists" }, 400);

  const r = await env.DB.prepare(
    `INSERT INTO accounts
     (username, display_name, uuid, enabled, data_limit, data_used, device_limit, expires_at, note, gateway_id)
     VALUES (?, ?, ?, 1, ?, 0, 0, ?, ?, ?)`
  )
    .bind(f.username, f.display, f.uid, f.dataLimit, f.expires, f.note, f.gatewayId)
    .run();

  return json({
    success: true,
    account: { id: r.meta && r.meta.last_row_id, username: f.username, uuid: f.uid }
  });
}

async function updateAccount(id, request, env) {
  const body = await readJson(request);
  if (!body) return json({ success: false, error: "Invalid JSON" }, 400);

  const existing = await env.DB.prepare("SELECT id FROM accounts WHERE id = ? LIMIT 1")
    .bind(id)
    .first();
  if (!existing) return json({ success: false, error: "Account not found" }, 404);

  const f = await readAccountFields(body, env);
  if (f.error) return json({ success: false, error: f.error }, 400);

  const dupUser = await env.DB.prepare(
    "SELECT id FROM accounts WHERE username = ? AND id != ? LIMIT 1"
  )
    .bind(f.username, id)
    .first();
  if (dupUser) return json({ success: false, error: "Username already exists" }, 400);
  const dupUuid = await env.DB.prepare(
    "SELECT id FROM accounts WHERE uuid = ? AND id != ? LIMIT 1"
  )
    .bind(f.uid, id)
    .first();
  if (dupUuid) return json({ success: false, error: "UUID already exists" }, 400);

  await env.DB.prepare(
    `UPDATE accounts SET username = ?, display_name = ?, uuid = ?, note = ?, data_limit = ?,
       expires_at = ?, gateway_id = ?, updated_at = unixepoch() WHERE id = ?`
  )
    .bind(f.username, f.display, f.uid, f.note, f.dataLimit, f.expires, f.gatewayId, id)
    .run();
  return json({ success: true });
}

async function toggleAccount(id, env) {
  const a = await env.DB.prepare("SELECT enabled FROM accounts WHERE id = ? LIMIT 1")
    .bind(id)
    .first();
  if (!a) return json({ success: false, error: "Account not found" }, 404);
  const enabled = Number(a.enabled) === 1 ? 0 : 1;
  await env.DB.prepare("UPDATE accounts SET enabled = ?, updated_at = unixepoch() WHERE id = ?")
    .bind(enabled, id)
    .run();
  return json({ success: true, enabled });
}

async function resetTraffic(id, env) {
  const r = await env.DB.prepare(
    "UPDATE accounts SET data_used = 0, updated_at = unixepoch() WHERE id = ?"
  )
    .bind(id)
    .run();
  if (!r.meta || !r.meta.changes) return json({ success: false, error: "Account not found" }, 404);
  return json({ success: true });
}

async function deleteAccount(id, env) {
  await env.DB.batch([
    env.DB.prepare("DELETE FROM subscriptions WHERE account_id = ?").bind(id),
    env.DB.prepare("DELETE FROM accounts WHERE id = ?").bind(id)
  ]);
  return json({ success: true });
}

/* ------------------------------------------------------------------ */
/* links / configs / subscriptions                                     */
/* ------------------------------------------------------------------ */

function buildVlessLink(userUuid, address, host, gatewayId, name) {
  const wsPath = gatewayId ? "/ws/" + gatewayId : "/ws";
  return (
    "vless://" + userUuid + "@" + address + ":443" +
    "?encryption=none&security=tls" +
    "&sni=" + encodeURIComponent(host) +
    "&fp=chrome&alpn=http%2F1.1&type=ws" +
    "&host=" + encodeURIComponent(host) +
    "&path=" + encodeURIComponent(wsPath) +
    "#" + encodeURIComponent(name)
  );
}

async function topScannerIps(env, limit) {
  const r = await env.DB.prepare(
    `SELECT ip FROM scanner_results
     WHERE ip IS NOT NULL AND status IN ('online', 'manual')
     ORDER BY score DESC, COALESCE(latency_ms, 999999) ASC
     LIMIT ?`
  )
    .bind(limit)
    .all();
  return (r.results || []).map((x) => x.ip);
}

// returns { error?, status?, links: [{name, link}] }
async function buildAccountLinks(env, acc, selfHost, mode) {
  let gw = null;
  if (acc.gateway_id) {
    gw = await env.DB.prepare(
      "SELECT id, name, worker_url, enabled FROM gateways WHERE id = ? LIMIT 1"
    )
      .bind(acc.gateway_id)
      .first();
    if (!gw) return { error: "Assigned gateway not found", status: 503, links: [] };
    if (Number(gw.enabled) !== 1) return { error: "Gateway disabled", status: 503, links: [] };
  }

  const host = (gw && cleanHost(gw.worker_url)) || selfHost;
  const gwId = gw ? gw.id : 0;
  const base = acc.display_name || acc.username;
  const label = gw ? base + " | " + gw.name : base;

  const links = [{ name: label + " | direct", link: buildVlessLink(acc.uuid, host, host, gwId, label + " | direct") }];

  mode = String(mode || "auto");
  let ips = [];
  if (mode === "auto") ips = await topScannerIps(env, 5);
  else if (IPV4_RE.test(mode)) ips = [mode];

  for (const ip of ips) {
    const n = label + " | " + ip;
    links.push({ name: n, link: buildVlessLink(acc.uuid, ip, host, gwId, n) });
  }
  return { links };
}

async function accountConfig(id, env, url) {
  const acc = await env.DB.prepare(
    "SELECT id, username, display_name, uuid, gateway_id FROM accounts WHERE id = ? LIMIT 1"
  )
    .bind(id)
    .first();
  if (!acc) return json({ success: false, error: "Account not found" }, 404);
  const r = await buildAccountLinks(env, acc, url.host, "auto");
  if (r.error) return json({ success: false, error: r.error }, 400);
  return json({ success: true, links: r.links });
}

async function getSubscriptions(env) {
  const r = await env.DB.prepare(
    `SELECT s.id, s.token, s.name, s.enabled, s.scanner_ip, s.created_at,
            a.id AS account_id, a.username, a.display_name
     FROM subscriptions s JOIN accounts a ON a.id = s.account_id
     ORDER BY s.id DESC`
  ).all();
  return json({ success: true, subscriptions: r.results || [] });
}

async function createSubscription(request, env, url) {
  const body = await readJson(request);
  if (!body) return json({ success: false, error: "Invalid JSON" }, 400);

  const accountId = Number(body.account_id);
  const name = String(body.name || "").trim().slice(0, 100);
  let mode = String(body.mode || "auto").trim();
  if (mode !== "auto" && mode !== "direct" && !IPV4_RE.test(mode)) mode = "auto";

  if (!name) return json({ success: false, error: "Subscription name is required" }, 400);
  if (!accountId) return json({ success: false, error: "account_id is required" }, 400);

  const acc = await env.DB.prepare("SELECT id FROM accounts WHERE id = ? LIMIT 1")
    .bind(accountId)
    .first();
  if (!acc) return json({ success: false, error: "Account not found" }, 404);

  const token = randomHex(24);
  await env.DB.prepare(
    "INSERT INTO subscriptions (account_id, token, name, enabled, scanner_ip, scanner_port) VALUES (?, ?, ?, 1, ?, 443)"
  )
    .bind(accountId, token, name, mode)
    .run();

  return json({
    success: true,
    subscription: { token, name, url: url.origin + "/sub/" + token }
  });
}

async function toggleSubscription(id, env) {
  const s = await env.DB.prepare("SELECT enabled FROM subscriptions WHERE id = ? LIMIT 1")
    .bind(id)
    .first();
  if (!s) return json({ success: false, error: "Subscription not found" }, 404);
  const enabled = Number(s.enabled) === 1 ? 0 : 1;
  await env.DB.prepare("UPDATE subscriptions SET enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?")
    .bind(enabled, id)
    .run();
  return json({ success: true, enabled });
}

async function deleteSubscription(id, env) {
  const r = await env.DB.prepare("DELETE FROM subscriptions WHERE id = ?").bind(id).run();
  if (!r.meta || !r.meta.changes)
    return json({ success: false, error: "Subscription not found" }, 404);
  return json({ success: true });
}

async function publicSubscription(token, env, url) {
  const row = await env.DB.prepare(
    `SELECT s.enabled AS sub_enabled, s.scanner_ip, s.name AS sub_name,
            a.id AS account_id, a.uuid, a.username, a.display_name, a.enabled AS acc_enabled,
            a.expires_at, a.data_limit, a.data_used, a.gateway_id
     FROM subscriptions s JOIN accounts a ON a.id = s.account_id
     WHERE s.token = ? LIMIT 1`
  )
    .bind(token)
    .first();

  if (!row) return plain("Subscription not found", 404);
  if (Number(row.sub_enabled) !== 1 || Number(row.acc_enabled) !== 1)
    return plain("Subscription disabled", 403);

  let expireUnix = 0;
  if (row.expires_at) {
    const t = Date.parse(String(row.expires_at));
    if (Number.isFinite(t) && t > 0) {
      expireUnix = Math.floor(t / 1000);
      if (Date.now() >= t) return plain("Subscription expired", 403);
    }
  }
  const limit = Number(row.data_limit || 0);
  const used = Number(row.data_used || 0);
  if (limit > 0 && used >= limit) return plain("Traffic limit reached", 403);

  const r = await buildAccountLinks(env, row, url.host, row.scanner_ip || "auto");
  if (r.error) return plain(r.error, r.status || 503);

  const body = r.links.map((l) => l.link).join("\n");
  const out = url.searchParams.get("raw") === "1" ? body : btoa(body);

  return plain(out, 200, {
    "Subscription-Userinfo":
      "upload=0; download=" + used + "; total=" + limit + "; expire=" + expireUnix,
    "Profile-Update-Interval": "6"
  });
}

/* ------------------------------------------------------------------ */
/* gateways                                                            */
/* ------------------------------------------------------------------ */

async function getGateways(env) {
  const r = await env.DB.prepare(
    `SELECT g.id, g.name, g.worker_name, g.worker_url, g.enabled, g.region, g.status,
            g.latency_ms, g.last_seen, g.last_error, g.created_at,
            (SELECT COUNT(*) FROM accounts a WHERE a.gateway_id = g.id) AS users
     FROM gateways g ORDER BY g.id DESC`
  ).all();
  return json({ success: true, gateways: r.results || [] });
}

function readGatewayFields(body, url) {
  const name = String(body.name || "").trim().slice(0, 100);
  if (!name) return { error: "Gateway name is required" };
  const host = cleanHost(body.host || body.worker_url) || url.host;
  if (!/^[a-z0-9.\-]+(:\d+)?$/.test(host)) return { error: "Invalid host" };
  const region = String(body.region || "default").trim().slice(0, 50) || "default";
  return { name, host, region };
}

async function createGateway(request, env, url) {
  const body = await readJson(request);
  if (!body) return json({ success: false, error: "Invalid JSON" }, 400);
  const f = readGatewayFields(body, url);
  if (f.error) return json({ success: false, error: f.error }, 400);

  let host = f.host;
  let workerName = "gw-" + randomString(10);

  // optional: deploy this gateway as its own Worker on workers.dev
  if (body.deploy) {
    const c = await cfdConfig(env);
    if (!c.token || !c.accountId || !c.dbId)
      return json({ success: false, error: "Configure Worker gateways in Settings first" }, 400);
    workerName = GW_PREFIX + randomString(8);
    try {
      await cfdUpload(c, workerName);
      host = await cfdSubdomain(c, workerName);
    } catch (e) {
      await cfdRemove(c, workerName);
      return json({ success: false, error: "Deploy failed: " + (e && e.message ? e.message : String(e)) }, 400);
    }
  }

  const r = await env.DB.prepare(
    `INSERT INTO gateways (name, worker_name, worker_url, enabled, region, status)
     VALUES (?, ?, ?, 1, ?, 'unknown')`
  )
    .bind(f.name, workerName, host, f.region)
    .run();

  return json({
    success: true,
    gateway: { id: r.meta && r.meta.last_row_id, name: f.name, host, region: f.region }
  });
}

async function updateGateway(id, request, env, url) {
  const body = await readJson(request);
  if (!body) return json({ success: false, error: "Invalid JSON" }, 400);
  const f = readGatewayFields(body, url);
  if (f.error) return json({ success: false, error: f.error }, 400);
  const r = await env.DB.prepare(
    "UPDATE gateways SET name = ?, worker_url = ?, region = ?, status = 'unknown' WHERE id = ?"
  )
    .bind(f.name, f.host, f.region, id)
    .run();
  if (!r.meta || !r.meta.changes) return json({ success: false, error: "Gateway not found" }, 404);
  return json({ success: true });
}

async function toggleGateway(id, env) {
  const g = await env.DB.prepare("SELECT enabled FROM gateways WHERE id = ? LIMIT 1")
    .bind(id)
    .first();
  if (!g) return json({ success: false, error: "Gateway not found" }, 404);
  const enabled = Number(g.enabled) === 1 ? 0 : 1;
  await env.DB.prepare("UPDATE gateways SET enabled = ? WHERE id = ?").bind(enabled, id).run();
  return json({ success: true, enabled });
}

async function deleteGateway(id, env) {
  const g = await env.DB.prepare("SELECT worker_name FROM gateways WHERE id = ? LIMIT 1").bind(id).first();
  await env.DB.batch([
    env.DB.prepare("UPDATE accounts SET gateway_id = NULL WHERE gateway_id = ?").bind(id),
    env.DB.prepare("DELETE FROM gateways WHERE id = ?").bind(id)
  ]);
  // if it was deployed as its own Worker, remove that Worker too
  if (g && String(g.worker_name).startsWith(GW_PREFIX)) {
    const c = await cfdConfig(env);
    if (c.token && c.accountId) await cfdRemove(c, g.worker_name);
  }
  return json({ success: true });
}

async function saveHealth(id, request, env) {
  const body = await readJson(request);
  if (!body) return json({ success: false, error: "Invalid JSON" }, 400);
  const status = String(body.status || "unknown").slice(0, 32);
  const latency =
    body.latency_ms == null ? null : Math.max(0, Math.round(Number(body.latency_ms)));
  const lastError = body.error ? String(body.error).slice(0, 500) : null;
  const r = await env.DB.prepare(
    "UPDATE gateways SET status = ?, latency_ms = ?, last_seen = ?, last_error = ? WHERE id = ?"
  )
    .bind(status, Number.isFinite(latency) ? latency : null, new Date().toISOString(), lastError, id)
    .run();
  if (!r.meta || !r.meta.changes) return json({ success: false, error: "Gateway not found" }, 404);
  return json({ success: true });
}

/* ------------------------------------------------------------------ */
/* Worker gateways (deployed through the Cloudflare API)               */
/* ------------------------------------------------------------------ */

const CF_API = "https://api.cloudflare.com/client/v4";
const GW_SOURCE_DEFAULT =
  "https://raw.githubusercontent.com/Trendiify/trendify-v2-cloud/main/_worker.js";
const GW_COMPAT = "2025-01-01";
const GW_PREFIX = "nexus-gw-";

async function cfApi(token, path, opts = {}) {
  const r = await fetch(CF_API + path, {
    ...opts,
    headers: { Authorization: "Bearer " + token, ...(opts.headers || {}) }
  });
  const j = await r.json().catch(() => null);
  if (!r.ok || !j || j.success === false) {
    const msg = j && j.errors && j.errors.length
      ? j.errors.map((e) => e.message + (e.code ? " (" + e.code + ")" : "")).join("; ")
      : "HTTP " + r.status;
    const e = new Error(msg);
    e.status = r.status;
    throw e;
  }
  return j.result;
}

async function cfdConfig(env) {
  const g = async (k) => (await getSetting(env, k)) || "";
  return {
    token: env.CF_API_TOKEN ? String(env.CF_API_TOKEN) : await g("cfd_token"),
    accountId: env.CF_ACCOUNT_ID ? String(env.CF_ACCOUNT_ID) : await g("cfd_account"),
    dbId: env.CF_DB_ID ? String(env.CF_DB_ID) : await g("cfd_db"),
    source: (await g("cfd_source")) || GW_SOURCE_DEFAULT,
    fromEnv: !!env.CF_API_TOKEN
  };
}

async function cfdGet(env) {
  const c = await cfdConfig(env);
  return json({
    success: true,
    cfd: {
      token_set: !!c.token,
      from_env: c.fromEnv,
      account_id: c.accountId,
      db_id: c.dbId,
      source: c.source
    }
  });
}

async function cfdSave(request, env) {
  const body = await readJson(request);
  if (!body) return json({ success: false, error: "Invalid JSON" }, 400);

  if (body.clear) {
    for (const k of ["cfd_token", "cfd_account", "cfd_db"]) await setSetting(env, k, "");
    return json({ success: true });
  }

  const src = String(body.source || "").trim();
  if (src) {
    if (!/^https:\/\/\S+$/.test(src))
      return json({ success: false, error: "Code URL must start with https://" }, 400);
    await setSetting(env, "cfd_source", src);
  }

  const cur = await cfdConfig(env);
  const newToken = String(body.token || "").trim();
  const token = newToken || cur.token;
  if (!token) return json({ success: true });

  let accountId = String(body.account_id || "").trim() || (newToken ? "" : cur.accountId);
  let dbId = String(body.db_id || "").trim() || (newToken ? "" : cur.dbId);

  try {
    if (!accountId) {
      const acc = await cfApi(token, "/accounts?per_page=50");
      if (!acc.length) throw new Error("No account is accessible with this token");
      if (acc.length > 1)
        throw new Error("Several accounts found, enter Account ID: " + acc.map((a) => a.name + " = " + a.id).join(", "));
      accountId = acc[0].id;
    }
    if (!dbId) {
      const dbs = await cfApi(token, "/accounts/" + accountId + "/d1/database");
      if (!dbs.length) throw new Error("No D1 database found");
      if (dbs.length > 1)
        throw new Error("Several databases found, enter D1 database ID: " + dbs.map((d) => d.name + " = " + d.uuid).join(", "));
      dbId = dbs[0].uuid;
    }
    if (!UUID_RE.test(dbId)) throw new Error("Invalid database ID");
    await cfApi(token, "/accounts/" + accountId + "/workers/subdomain");
  } catch (e) {
    return json({ success: false, error: e && e.message ? e.message : String(e) }, 400);
  }

  if (newToken) await setSetting(env, "cfd_token", newToken);
  await setSetting(env, "cfd_account", accountId);
  await setSetting(env, "cfd_db", dbId);
  return json({ success: true, account_id: accountId, db_id: dbId });
}

async function cfdUpload(c, name) {
  const r = await fetch(c.source, { cf: { cacheTtl: 0 } });
  if (!r.ok) throw new Error("Could not download panel code (HTTP " + r.status + ")");
  const code = await r.text();
  if (code.length < 2000 || code.indexOf("export default") === -1)
    throw new Error("Downloaded file does not look like the panel code");

  const meta = {
    main_module: "worker.js",
    compatibility_date: GW_COMPAT,
    bindings: [{ type: "d1", name: "DB", id: c.dbId }]
  };
  const form = new FormData();
  form.append("metadata", new File([JSON.stringify(meta)], "metadata.json", { type: "application/json" }));
  form.append("worker.js", new File([code], "worker.js", { type: "application/javascript+module" }));
  await cfApi(c.token, "/accounts/" + c.accountId + "/workers/scripts/" + name, { method: "PUT", body: form });
}

async function cfdSubdomain(c, name) {
  await cfApi(c.token, "/accounts/" + c.accountId + "/workers/scripts/" + name + "/subdomain", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ enabled: true })
  });
  const s = await cfApi(c.token, "/accounts/" + c.accountId + "/workers/subdomain");
  return name + "." + s.subdomain + ".workers.dev";
}

async function cfdRemove(c, name) {
  try {
    await cfApi(c.token, "/accounts/" + c.accountId + "/workers/scripts/" + name + "?force=true", { method: "DELETE" });
  } catch {}
}

async function redeployGateway(id, env) {
  const g = await env.DB.prepare("SELECT worker_name FROM gateways WHERE id = ? LIMIT 1").bind(id).first();
  if (!g) return json({ success: false, error: "Gateway not found" }, 404);
  if (!String(g.worker_name).startsWith(GW_PREFIX))
    return json({ success: false, error: "This gateway is not a deployed Worker" }, 400);
  const c = await cfdConfig(env);
  if (!c.token || !c.accountId || !c.dbId)
    return json({ success: false, error: "Configure Worker gateways in Settings first" }, 400);
  try {
    await cfdUpload(c, g.worker_name);
  } catch (e) {
    return json({ success: false, error: e && e.message ? e.message : String(e) }, 400);
  }
  return json({ success: true });
}

/* ------------------------------------------------------------------ */
/* stats                                                               */
/* ------------------------------------------------------------------ */

async function getStats(env) {
  const q = async (sql) => Number(((await env.DB.prepare(sql).first()) || {}).c || 0);
  return json({
    success: true,
    stats: {
      accounts: await q("SELECT COUNT(*) AS c FROM accounts"),
      active_accounts: await q("SELECT COUNT(*) AS c FROM accounts WHERE enabled = 1"),
      gateways: await q("SELECT COUNT(*) AS c FROM gateways"),
      active_gateways: await q("SELECT COUNT(*) AS c FROM gateways WHERE enabled = 1"),
      subscriptions: await q("SELECT COUNT(*) AS c FROM subscriptions WHERE enabled = 1"),
      traffic: await q("SELECT COALESCE(SUM(data_used), 0) AS c FROM accounts")
    }
  });
}

/* ------------------------------------------------------------------ */
/* scanner (candidate generation here, probing in the browser)         */
/* ------------------------------------------------------------------ */

function ipToNum(ip) {
  const p = ip.split(".").map(Number);
  return ((p[0] << 24) + (p[1] << 16) + (p[2] << 8) + p[3]) >>> 0;
}
function numToIp(n) {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
}

async function scannerCandidates(request) {
  const body = (await readJson(request)) || {};
  let count = Number(body.count || 100);
  if (!Number.isFinite(count)) count = 100;
  count = Math.max(10, Math.min(200, Math.floor(count)));

  let cidrs = [];
  try {
    const r = await fetch("https://www.cloudflare.com/ips-v4");
    if (r.ok) {
      cidrs = (await r.text())
        .split(/\r?\n/)
        .map((x) => x.trim())
        .filter((x) => /^\d+\.\d+\.\d+\.\d+\/\d+$/.test(x));
    }
  } catch {}
  if (!cidrs.length) cidrs = CF_RANGES_FALLBACK;

  const ranges = cidrs.map((c) => {
    const [ip, pre] = c.split("/");
    const prefix = Number(pre);
    return { base: ipToNum(ip), prefix, weight: Math.pow(2, Math.max(0, 24 - prefix)) };
  });
  const total = ranges.reduce((s, r) => s + r.weight, 0);

  const picked = new Set();
  let tries = 0;
  while (picked.size < count && tries < count * 60) {
    tries++;
    let x = Math.random() * total;
    let range = ranges[ranges.length - 1];
    for (const r of ranges) {
      x -= r.weight;
      if (x <= 0) {
        range = r;
        break;
      }
    }
    const hostBits = 32 - range.prefix;
    const size = Math.pow(2, hostBits);
    const mask = (size - 1) >>> 0;
    const network = (range.base & ~mask) >>> 0;
    const ip = numToIp((network + Math.floor(Math.random() * size)) >>> 0);
    const last = Number(ip.split(".")[3]);
    if (last === 0 || last === 255) continue;
    picked.add(ip);
  }
  return json({ success: true, candidates: Array.from(picked) });
}

async function scannerSave(request, env) {
  const body = await readJson(request);
  if (!body || !Array.isArray(body.results))
    return json({ success: false, error: "No scanner results" }, 400);

  const clean = [];
  for (const it of body.results) {
    const ip = String((it && it.ip) || "").trim();
    const lat = Number(it && it.latency_ms);
    if (!IPV4_RE.test(ip) || !Number.isFinite(lat) || lat < 0) continue;
    const latency = Math.round(lat);
    clean.push({ ip, latency, score: Math.max(1, 100 - Math.round(latency / 10)) });
  }
  if (!clean.length) return json({ success: false, error: "No valid results" }, 400);

  clean.sort((a, b) => b.score - a.score || a.latency - b.latency);
  const top = clean.slice(0, 30);
  const now = new Date().toISOString();

  const stmts = [env.DB.prepare("DELETE FROM scanner_results WHERE status != 'manual'")];
  for (const it of top) {
    stmts.push(
      env.DB.prepare(
        `INSERT INTO scanner_results (target, port, protocol, status, latency_ms, ip, score, last_checked)
         VALUES (?, 443, 'tls', 'online', ?, ?, ?, ?)`
      ).bind(it.ip, it.latency, it.ip, it.score, now)
    );
  }
  await env.DB.batch(stmts);
  return json({ success: true, saved: top.length });
}

async function scannerAdd(request, env) {
  const body = await readJson(request);
  if (!body) return json({ success: false, error: "Invalid JSON" }, 400);
  const ip = String(body.ip || body.target || "").trim();
  if (!IPV4_RE.test(ip)) return json({ success: false, error: "Enter a valid IPv4 address" }, 400);
  await env.DB.prepare(
    `INSERT INTO scanner_results (target, port, protocol, status, ip, score, last_checked)
     VALUES (?, 443, 'tls', 'manual', ?, 50, ?)`
  )
    .bind(ip, ip, new Date().toISOString())
    .run();
  return json({ success: true });
}

async function scannerResults(env) {
  const r = await env.DB.prepare(
    `SELECT id, ip, port, status, latency_ms, score, last_checked FROM scanner_results
     ORDER BY score DESC, COALESCE(latency_ms, 999999) ASC`
  ).all();
  return json({ success: true, results: r.results || [] });
}

/* ------------------------------------------------------------------ */
/* VLESS over WebSocket                                                */
/* ------------------------------------------------------------------ */

// Fallback used when PROXYIP env / panel setting is empty.
// This is a third-party host: replace it with your own proxy in Settings.
const DEFAULT_PROXY_IPS = ["bpb.yousef.isegaro.com"];

function uuidFromBytes(b) {
  const h = Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
  return (
    h.slice(0, 8) + "-" + h.slice(8, 12) + "-" + h.slice(12, 16) + "-" +
    h.slice(16, 20) + "-" + h.slice(20)
  );
}

function parseVLESS(view) {
  if (view.length < 24) throw new Error("Invalid VLESS request");
  const version = view[0];
  const uid = uuidFromBytes(view.slice(1, 17));
  let offset = 18 + view[17];
  if (view.length < offset + 4) throw new Error("Invalid VLESS header");

  const command = view[offset++];
  if (command !== 1 && command !== 2)
    throw new Error("Unsupported command " + command + " (disable Mux in your client)");

  const port = (view[offset] << 8) | view[offset + 1];
  offset += 2;

  const type = view[offset++];
  let address = "";
  if (type === 1) {
    if (view.length < offset + 4) throw new Error("Invalid IPv4 address");
    address = view[offset] + "." + view[offset + 1] + "." + view[offset + 2] + "." + view[offset + 3];
    offset += 4;
  } else if (type === 2) {
    const len = view[offset++];
    if (view.length < offset + len) throw new Error("Invalid domain length");
    address = new TextDecoder().decode(view.slice(offset, offset + len));
    offset += len;
  } else if (type === 3) {
    if (view.length < offset + 16) throw new Error("Invalid IPv6 address");
    const parts = [];
    for (let i = 0; i < 16; i += 2)
      parts.push(((view[offset + i] << 8) | view[offset + i + 1]).toString(16));
    address = parts.join(":");
    offset += 16;
  } else {
    throw new Error("Unsupported address type");
  }
  return { version, uuid: uid, command, address, port, data: view.slice(offset) };
}

function withTimeout(promise, ms, msg) {
  let t;
  const timer = new Promise((_, rej) => {
    t = setTimeout(() => rej(new Error(msg)), ms);
  });
  return Promise.race([promise, timer]).finally(() => clearTimeout(t));
}

async function getProxyList(env) {
  let raw = env.PROXYIP ? String(env.PROXYIP) : "";
  if (!raw) {
    try {
      raw = (await getSetting(env, "proxy_ip")) || "";
    } catch {}
  }
  const list = raw.split(",").map((s) => s.trim()).filter(Boolean);
  return list.length ? list : DEFAULT_PROXY_IPS;
}

function parseProxy(p, defPort) {
  const idx = p.lastIndexOf(":");
  const hasPort = idx > 0 && p.indexOf(":") === idx && /^\d+$/.test(p.slice(idx + 1));
  return {
    host: hasPort ? p.slice(0, idx) : p,
    port: hasPort ? Number(p.slice(idx + 1)) : defPort
  };
}

async function connectTo(host, port) {
  const s = connect({ hostname: host, port });
  try {
    await withTimeout(s.opened, 8000, "connect timeout");
  } catch (e) {
    try { s.close(); } catch {}
    throw e;
  }
  return s;
}

async function toUint8(data) {
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  if (typeof Blob !== "undefined" && data instanceof Blob) {
    return new Uint8Array(await data.arrayBuffer());
  }
  if (typeof data === "string") {
    const e = new Error("Text frame received (len " + data.length + ", starts: " +
      JSON.stringify(data.slice(0, 20)) + ")");
    throw e;
  }
  throw new Error("Unknown WebSocket data type: " + Object.prototype.toString.call(data));
}

function handleVLESS(request, env, ctx, pathGatewayId) {
  const pair = new WebSocketPair();
  const client = pair[0];
  const server = pair[1];
  server.accept();

  let remote = null;
  let writer = null;
  let headerSent = false;
  let closed = false;
  let started = false;
  let isUdp = false;
  let udpBuf = new Uint8Array(0);
  let pending = 0;
  let userId = 0;
  let version = 0;
  let target = null;
  let firstData = new Uint8Array(0);
  let retried = false;
  let retrying = null;
  let effectiveGateway = pathGatewayId || 0;
  let chain = Promise.resolve();

  const flush = () => {
    if (pending > 0 && userId) {
      const n = pending;
      pending = 0;
      ctx.waitUntil(
        env.DB.prepare("UPDATE accounts SET data_used = data_used + ? WHERE id = ?")
          .bind(n, userId)
          .run()
          .catch(() => {})
      );
    }
  };

  const closeAll = () => {
    if (closed) return;
    closed = true;
    flush();
    try { if (writer) writer.releaseLock(); } catch {}
    try { if (remote) remote.close(); } catch {}
    try {
      if (server.readyState === 1 || server.readyState === 2) server.close(1000, "closed");
    } catch {}
  };

  const reject = (msg, quiet) => {
    const e = new Error(msg);
    e.quiet = !!quiet;
    throw e;
  };

  // send bytes to the client, prefixing the VLESS response header once
  const send = (chunk) => {
    if (closed || server.readyState !== 1) return;
    try {
      if (!headerSent) {
        headerSent = true;
        const out = new Uint8Array(2 + chunk.byteLength);
        out[0] = version;
        out[1] = 0;
        out.set(chunk, 2);
        server.send(out);
      } else {
        server.send(chunk);
      }
    } catch {}
  };

  function pipeRemote(sock, canRetry) {
    let got = false;
    sock.readable
      .pipeTo(
        new WritableStream({
          write(chunk) {
            if (closed) return;
            got = true;
            pending += chunk.byteLength;
            send(chunk);
            if (pending > 5 * 1024 * 1024) flush();
          }
        })
      )
      .catch(() => {})
      .finally(() => {
        if (closed || remote !== sock) return;
        // connected but got nothing back (typical for Cloudflare-hosted targets) -> retry via proxy
        if (!got && canRetry && !retried) {
          retried = true;
          retrying = (async () => {
            try { writer.releaseLock(); } catch {}
            try { sock.close(); } catch {}
            const ok = await tryProxies();
            if (!ok) closeAll();
          })();
        } else {
          closeAll();
        }
      });
  }

  async function attachRemote(sock, canRetry) {
    const w = sock.writable.getWriter();
    if (firstData.length > 0) await w.write(firstData);
    remote = sock;
    writer = w;
    pipeRemote(sock, canRetry);
  }

  async function tryProxies() {
    const proxies = await getProxyList(env);
    for (const p of proxies) {
      const pr = parseProxy(p, target.port);
      let s = null;
      try {
        s = await connectTo(pr.host, pr.port);
        await attachRemote(s, false);
        logEvent(env, ctx, effectiveGateway, "CONNECT_VIA_PROXY", p + " -> " + target.address + ":" + target.port);
        return true;
      } catch {
        try { s && s.close(); } catch {}
      }
    }
    return false;
  }

  // UDP is only supported for DNS (port 53); queries are answered via DoH
  async function handleUdp(data) {
    const merged = new Uint8Array(udpBuf.length + data.length);
    merged.set(udpBuf, 0);
    merged.set(data, udpBuf.length);
    let off = 0;
    while (merged.length - off >= 2) {
      const len = (merged[off] << 8) | merged[off + 1];
      if (merged.length - off - 2 < len) break;
      const q = merged.slice(off + 2, off + 2 + len);
      off += 2 + len;
      pending += q.length;
      try {
        const resp = await fetch("https://1.1.1.1/dns-query", {
          method: "POST",
          headers: { "content-type": "application/dns-message", accept: "application/dns-message" },
          body: q
        });
        const ans = new Uint8Array(await resp.arrayBuffer());
        const out = new Uint8Array(2 + ans.length);
        out[0] = (ans.length >> 8) & 255;
        out[1] = ans.length & 255;
        out.set(ans, 2);
        pending += ans.length;
        send(out);
      } catch {}
    }
    udpBuf = merged.slice(off);
  }

  async function onFirstPacket(data) {
    const p = parseVLESS(data);

    const user = await env.DB.prepare(
      `SELECT id, enabled, gateway_id, data_limit, data_used, expires_at
       FROM accounts WHERE uuid = ? LIMIT 1`
    )
      .bind(p.uuid)
      .first();

    if (!user) reject("Invalid UUID " + p.uuid);
    if (Number(user.enabled) !== 1) reject("Account disabled");

    if (pathGatewayId && user.gateway_id && Number(user.gateway_id) !== pathGatewayId)
      reject("Wrong gateway for user " + user.id);

    effectiveGateway = pathGatewayId || Number(user.gateway_id || 0);
    if (effectiveGateway) {
      const gw = await env.DB.prepare("SELECT enabled FROM gateways WHERE id = ? LIMIT 1")
        .bind(effectiveGateway)
        .first();
      if (!gw || Number(gw.enabled) !== 1) reject("Gateway disabled or missing");
    }

    if (user.expires_at) {
      const t = Date.parse(String(user.expires_at));
      if (Number.isFinite(t) && t > 0 && Date.now() >= t) reject("Account expired");
    }
    const limit = Number(user.data_limit || 0);
    if (limit > 0 && Number(user.data_used || 0) >= limit) reject("Traffic limit reached");

    userId = Number(user.id);
    version = p.version;
    target = { address: p.address, port: p.port };
    firstData = p.data;

    if (p.command === 2) {
      if (p.port !== 53) reject("UDP is only supported for DNS (port 53)");
      isUdp = true;
      // reply header immediately so the client knows the tunnel is up
      send(new Uint8Array(0));
      if (p.data.length) await handleUdp(p.data);
      return;
    }

    pending += firstData.length;

    let connected = false;
    let directError = "";
    try {
      const s = await connectTo(p.address, p.port);
      await attachRemote(s, true);
      connected = true;
    } catch (e) {
      directError = e && e.message ? e.message : String(e);
    }
    if (!connected) {
      retried = true;
      if (!(await tryProxies()))
        reject("connect failed " + p.address + ":" + p.port + " (" + directError + ")");
    }
  }

  server.addEventListener("message", (event) => {
    chain = chain
      .then(async () => {
        if (closed) return;
        const data = await toUint8(event.data);
        if (!started) {
          started = true;
          await onFirstPacket(data);
        } else if (isUdp) {
          await handleUdp(data);
        } else {
          if (retrying) await retrying;
          if (!writer) return;
          pending += data.byteLength;
          await writer.write(data);
        }
      })
      .catch((error) => {
        if (!error || !error.quiet) {
          logEvent(env, ctx, effectiveGateway, "VLESS_ERROR", error && error.message ? error.message : String(error));
        }
        closeAll();
      });
  });

  server.addEventListener("close", closeAll);
  server.addEventListener("error", closeAll);

  return new Response(null, { status: 101, webSocket: client });
}

/* ------------------------------------------------------------------ */
/* Telegram bot                                                        */
/* ------------------------------------------------------------------ */

const TG_API = "https://api.telegram.org/bot";

function hx(v) {
  return String(v == null ? "" : v).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
function tgb(text, data) {
  return { text, callback_data: data };
}
function tgBytes(n) {
  n = Number(n || 0);
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return n.toFixed(n >= 10 || i === 0 ? 0 : 2) + " " + u[i];
}
function tgIcon(g) {
  if (Number(g.enabled) !== 1) return "⚪";
  if (g.status === "online") return "🟢";
  if (g.status === "offline") return "🔴";
  return "🟡";
}

async function tgCall(token, method, body) {
  try {
    const r = await fetch(TG_API + token + "/" + method, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {})
    });
    return await r.json();
  } catch (e) {
    return { ok: false, description: e && e.message ? e.message : "network error" };
  }
}

async function tgConfig(env) {
  const token = (await getSetting(env, "tg_token")) || "";
  const admins = ((await getSetting(env, "tg_admins")) || "")
    .split(",").map((s) => s.trim()).filter(Boolean);
  const secret = (await getSetting(env, "tg_secret")) || "";
  return { token, admins, secret };
}

/* ---- panel API for bot settings ---- */

async function tgGetSettings(env, url) {
  const c = await tgConfig(env);
  return json({
    success: true,
    telegram: {
      token_set: !!c.token,
      token_masked: c.token ? c.token.slice(0, 6) + "..." + c.token.slice(-4) : "",
      admins: c.admins.join(", "),
      webhook_url: url.origin + "/tg/webhook",
      active: (await getSetting(env, "tg_active")) === "1",
      username: (await getSetting(env, "tg_username")) || ""
    }
  });
}

async function tgSaveSettings(request, env) {
  const body = await readJson(request);
  if (!body) return json({ success: false, error: "Invalid JSON" }, 400);

  const token = String(body.token || "").trim();
  if (token) {
    if (!/^\d{6,}:[A-Za-z0-9_-]{30,}$/.test(token))
      return json({ success: false, error: "Invalid bot token format" }, 400);
    await setSetting(env, "tg_token", token);
    await setSetting(env, "tg_active", "0");
  }

  const ids = String(body.admins || "").split(/[,\s]+/).map((s) => s.trim()).filter(Boolean);
  for (const id of ids) {
    if (!/^-?\d{3,20}$/.test(id))
      return json({ success: false, error: "Admin IDs must be numeric Telegram IDs" }, 400);
  }
  await setSetting(env, "tg_admins", ids.join(","));
  return json({ success: true });
}

async function tgActivate(env, url) {
  const c = await tgConfig(env);
  if (!c.token) return json({ success: false, error: "Save the bot token first" }, 400);

  const me = await tgCall(c.token, "getMe");
  if (!me.ok) return json({ success: false, error: "Telegram: " + (me.description || "invalid token") }, 400);

  const secret = randomHex(16);
  await setSetting(env, "tg_secret", secret);

  const hook = await tgCall(c.token, "setWebhook", {
    url: url.origin + "/tg/webhook",
    secret_token: secret,
    allowed_updates: ["message", "callback_query"],
    drop_pending_updates: true
  });
  if (!hook.ok) return json({ success: false, error: "Telegram: " + (hook.description || "setWebhook failed") }, 400);

  await tgCall(c.token, "setMyCommands", { commands: [{ command: "start", description: "Open the menu" }] });
  await setSetting(env, "tg_active", "1");
  await setSetting(env, "tg_username", (me.result && me.result.username) || "");
  return json({ success: true, username: me.result && me.result.username });
}

async function tgDeactivate(env) {
  const c = await tgConfig(env);
  if (c.token) await tgCall(c.token, "deleteWebhook", { drop_pending_updates: true });
  await setSetting(env, "tg_active", "0");
  await setSetting(env, "tg_secret", "");
  return json({ success: true });
}

/* ---- webhook entry ---- */

async function tgWebhook(request, env, ctx, url) {
  const c = await tgConfig(env);
  if (!c.token || !c.secret) return plain("off", 404);
  const got = request.headers.get("X-Telegram-Bot-Api-Secret-Token") || "";
  if (!safeEqual(got, c.secret)) return plain("forbidden", 403);

  const update = await request.json().catch(() => null);
  if (!update) return plain("ok");

  ctx.waitUntil(
    tgHandleUpdate(env, ctx, c, update, url.host).catch((e) => {
      logEvent(env, ctx, 0, "TG_ERROR", e && e.message ? e.message : String(e));
    })
  );
  return plain("ok");
}

/* ---- state (stored in settings table) ---- */

async function tgGetState(env, uid) {
  const v = await getSetting(env, "tg_state_" + uid);
  try { return v ? JSON.parse(v) : null; } catch { return null; }
}
async function tgSetState(env, uid, st) {
  await setSetting(env, "tg_state_" + uid, JSON.stringify(st));
}
async function tgClearState(env, uid) {
  await env.DB.prepare("DELETE FROM settings WHERE key = ?").bind("tg_state_" + uid).run();
}

/* ---- sending ---- */

async function tgShow(t, text, rows) {
  const body = {
    chat_id: t.chatId,
    text,
    parse_mode: "HTML",
    disable_web_page_preview: true,
    reply_markup: { inline_keyboard: rows || [] }
  };
  if (t.msgId) {
    const r = await tgCall(t.token, "editMessageText", Object.assign({}, body, { message_id: t.msgId }));
    if (r.ok || /not modified/i.test(r.description || "")) return;
  }
  await tgCall(t.token, "sendMessage", body);
}

/* ---- update dispatcher ---- */

async function tgHandleUpdate(env, ctx, c, update, host) {
  const cb = update.callback_query;
  const msg = update.message;
  const from = cb ? cb.from : msg && msg.from;
  if (!from) return;
  const chatId = cb ? (cb.message && cb.message.chat.id) : msg.chat.id;
  if (!chatId) return;

  const uid = String(from.id);
  const t = {
    token: c.token,
    chatId,
    uid,
    host,
    msgId: cb && cb.message ? cb.message.message_id : 0
  };

  if (!c.admins.includes(uid)) {
    if (cb) {
      await tgCall(c.token, "answerCallbackQuery", { callback_query_id: cb.id, text: "Not allowed", show_alert: true });
    } else {
      await tgShow(
        t,
        "⛔ Not authorized.\nYour Telegram ID: <code>" + hx(uid) + "</code>\nAdd it in panel → Settings → Telegram Bot.",
        []
      );
    }
    return;
  }

  try {
    if (cb) {
      await tgCall(c.token, "answerCallbackQuery", { callback_query_id: cb.id });
      return await tgOnCallback(env, ctx, t, String(cb.data || ""));
    }
    const text = String(msg.text || "").trim();
    if (!text) return;
    if (text.startsWith("/")) {
      await tgClearState(env, uid);
      return await tgMain(t);
    }
    const st = await tgGetState(env, uid);
    if (st) return await tgOnText(env, t, st, text);
    return await tgMain(t);
  } catch (e) {
    await tgClearState(env, uid).catch(() => {});
    t.msgId = 0;
    await tgShow(t, "⚠️ Error: " + hx(e && e.message ? e.message : String(e)), [[tgb("🏠 Menu", "m")]]);
  }
}

async function tgMain(t) {
  return tgShow(t, "🛰 <b>Trendify Nexus</b>\nChoose a section:", [
    [tgb("📊 Monitoring", "mon")],
    [tgb("🌐 Gateways", "g"), tgb("👤 Configs", "u")],
    [tgb("🔗 Subscriptions", "s")]
  ]);
}

async function tgOnCallback(env, ctx, t, data) {
  const p = data.split(":");
  const k = p[0];
  if (k === "m") {
    await tgClearState(env, t.uid);
    return tgMain(t);
  }
  if (k === "mon") {
    if (p[1] === "chk") await tgCheckGateways(env, t.host, 0);
    return tgMonitor(env, t);
  }
  if (k === "g") return tgGw(env, t, p);
  if (k === "u") return tgUser(env, t, p);
  if (k === "s") return tgSub(env, t, p);
  return tgMain(t);
}

/* ---- monitoring ---- */

async function tgCheckGateways(env, selfHost, onlyId) {
  const r = await env.DB.prepare(
    "SELECT id, worker_url FROM gateways WHERE enabled = 1" + (onlyId ? " AND id = ?" : "")
  ).bind(...(onlyId ? [onlyId] : [])).all();

  await Promise.all((r.results || []).map(async (g) => {
    const host = cleanHost(g.worker_url) || selfHost;
    let status = "online", latency = null, err = null;
    if (host !== selfHost) {
      const t0 = Date.now();
      const ctl = new AbortController();
      const to = setTimeout(() => ctl.abort(), 5000);
      try {
        const res = await fetch("https://" + host + "/health", { signal: ctl.signal, headers: { "Cache-Control": "no-store" } });
        const j = await res.json().catch(() => null);
        latency = Date.now() - t0;
        if (!res.ok || !j || j.success !== true) { status = "offline"; err = "HTTP " + res.status; }
      } catch (e) {
        status = "offline";
        err = e && e.message ? e.message : "unreachable";
      }
      clearTimeout(to);
    }
    await env.DB.prepare(
      "UPDATE gateways SET status = ?, latency_ms = ?, last_seen = ?, last_error = ? WHERE id = ?"
    ).bind(status, latency, new Date().toISOString(), err, g.id).run();
  }));
}

async function tgMonitor(env, t) {
  const q = async (sql, ...args) =>
    Number(((await env.DB.prepare(sql).bind(...args).first()) || {}).c || 0);
  const soon = new Date(Date.now() + 3 * 86400000).toISOString();

  const [acc, act, gw, gwOn, subs, traffic] = await Promise.all([
    q("SELECT COUNT(*) AS c FROM accounts"),
    q("SELECT COUNT(*) AS c FROM accounts WHERE enabled = 1"),
    q("SELECT COUNT(*) AS c FROM gateways"),
    q("SELECT COUNT(*) AS c FROM gateways WHERE enabled = 1"),
    q("SELECT COUNT(*) AS c FROM subscriptions WHERE enabled = 1"),
    q("SELECT COALESCE(SUM(data_used), 0) AS c FROM accounts")
  ]);

  const top = (await env.DB.prepare(
    "SELECT username, data_used FROM accounts ORDER BY data_used DESC LIMIT 5"
  ).all()).results || [];
  const gws = (await env.DB.prepare(
    "SELECT name, enabled, status, latency_ms FROM gateways ORDER BY id DESC LIMIT 10"
  ).all()).results || [];
  const near = (await env.DB.prepare(
    "SELECT username, data_used, data_limit FROM accounts WHERE enabled = 1 AND data_limit > 0 AND data_used * 10 >= data_limit * 9 LIMIT 5"
  ).all()).results || [];
  const exp = (await env.DB.prepare(
    "SELECT username, expires_at FROM accounts WHERE enabled = 1 AND expires_at IS NOT NULL AND expires_at <= ? ORDER BY expires_at LIMIT 5"
  ).bind(soon).all()).results || [];
  const logs = (await env.DB.prepare(
    "SELECT event, detail, created_at FROM gateway_logs ORDER BY id DESC LIMIT 5"
  ).all()).results || [];

  let s = "📊 <b>Monitoring</b>\n\n";
  s += "👤 Users: <b>" + act + "</b> active / " + acc + "\n";
  s += "🌐 Gateways: <b>" + gwOn + "</b> enabled / " + gw + "\n";
  s += "🔗 Subscriptions: <b>" + subs + "</b>\n";
  s += "📶 Total traffic: <b>" + tgBytes(traffic) + "</b>\n";

  if (gws.length) {
    s += "\n<b>Gateways</b>\n";
    for (const g of gws)
      s += tgIcon(g) + " " + hx(g.name) + (g.latency_ms != null ? " - " + g.latency_ms + " ms" : "") + "\n";
  }
  if (top.length) {
    s += "\n<b>Top usage</b>\n";
    for (const u of top) s += "• " + hx(u.username) + " - " + tgBytes(u.data_used) + "\n";
  }
  if (near.length) {
    s += "\n⚠️ <b>Near data limit</b>\n";
    for (const u of near) s += "• " + hx(u.username) + " (" + tgBytes(u.data_used) + " / " + tgBytes(u.data_limit) + ")\n";
  }
  if (exp.length) {
    s += "\n⏳ <b>Expiring / expired</b>\n";
    for (const u of exp) s += "• " + hx(u.username) + " - " + hx(String(u.expires_at).slice(0, 16).replace("T", " ")) + "\n";
  }
  if (logs.length) {
    s += "\n🧾 <b>Recent events</b>\n";
    for (const l of logs) s += "• " + hx(l.event) + ": " + hx(String(l.detail || "").slice(0, 70)) + "\n";
  }

  return tgShow(t, s, [
    [tgb("🔄 Refresh", "mon"), tgb("🩺 Check gateways", "mon:chk")],
    [tgb("🏠 Menu", "m")]
  ]);
}

/* ---- gateways ---- */

async function tgGwDetail(env, t, id) {
  const g = await env.DB.prepare(
    `SELECT g.*, (SELECT COUNT(*) FROM accounts a WHERE a.gateway_id = g.id) AS users
     FROM gateways g WHERE g.id = ? LIMIT 1`
  ).bind(id).first();
  if (!g) return tgShow(t, "Gateway not found.", [[tgb("⬅️ Back", "g")]]);
  const on = Number(g.enabled) === 1;
  let s = "🌐 <b>" + hx(g.name) + "</b> " + tgIcon(g) + "\n\n";
  s += "Host: <code>" + hx(g.worker_url || t.host) + "</code>\n";
  s += "WS path: <code>/ws/" + g.id + "</code>\n";
  s += "Region: " + hx(g.region || "default") + "\n";
  s += "Status: " + hx(g.status || "unknown") + (g.latency_ms != null ? " (" + g.latency_ms + " ms)" : "") + "\n";
  s += "Enabled: " + (on ? "yes" : "no") + "\n";
  s += "Users: " + g.users + "\n";
  if (g.last_error) s += "Last error: " + hx(g.last_error) + "\n";
  return tgShow(t, s, [
    [tgb("🩺 Check", "g:c:" + id), tgb(on ? "⏸ Disable" : "▶️ Enable", "g:t:" + id)],
    [tgb("🗑 Delete", "g:x:" + id)],
    [tgb("⬅️ Back", "g")]
  ]);
}

async function tgGw(env, t, p) {
  const a = p[1];
  const id = Number(p[2] || 0);

  if (!a) {
    await tgClearState(env, t.uid);
    const r = await env.DB.prepare("SELECT id, name, enabled, status FROM gateways ORDER BY id DESC LIMIT 20").all();
    const rows = [[tgb("➕ New gateway", "g:new")]];
    for (const g of r.results || []) rows.push([tgb(tgIcon(g) + " " + g.name, "g:v:" + g.id)]);
    rows.push([tgb("🏠 Menu", "m")]);
    return tgShow(t, "🌐 <b>Gateways</b>\nSelect one or create a new gateway.", rows);
  }
  if (a === "new") {
    await tgSetState(env, t.uid, { step: "gw_name", d: {} });
    return tgShow(t, "🌐 Send the <b>gateway name</b>:", [[tgb("✖ Cancel", "g")]]);
  }
  if (a === "host") {
    const st = await tgGetState(env, t.uid);
    if (!st || st.step !== "gw_host") return tgGw(env, t, ["g"]);
    return tgFinishGateway(env, t, st.d.name, t.host);
  }
  if (a === "v") return tgGwDetail(env, t, id);
  if (a === "c") {
    await tgCheckGateways(env, t.host, id);
    return tgGwDetail(env, t, id);
  }
  if (a === "t") {
    await env.DB.prepare("UPDATE gateways SET enabled = CASE WHEN enabled = 1 THEN 0 ELSE 1 END WHERE id = ?").bind(id).run();
    return tgGwDetail(env, t, id);
  }
  if (a === "x") {
    return tgShow(t, "Delete this gateway? Users on it will be unassigned.", [
      [tgb("✅ Yes, delete", "g:xx:" + id), tgb("✖ No", "g:v:" + id)]
    ]);
  }
  if (a === "xx") {
    const g = await env.DB.prepare("SELECT worker_name FROM gateways WHERE id = ? LIMIT 1").bind(id).first();
    await env.DB.batch([
      env.DB.prepare("UPDATE accounts SET gateway_id = NULL WHERE gateway_id = ?").bind(id),
      env.DB.prepare("DELETE FROM gateways WHERE id = ?").bind(id)
    ]);
    if (g && String(g.worker_name).startsWith(GW_PREFIX)) {
      const c = await cfdConfig(env);
      if (c.token && c.accountId) await cfdRemove(c, g.worker_name);
    }
    return tgGw(env, t, ["g"]);
  }
  return tgGw(env, t, ["g"]);
}

async function tgFinishGateway(env, t, name, host) {
  await tgClearState(env, t.uid);
  const r = await env.DB.prepare(
    `INSERT INTO gateways (name, worker_name, worker_url, enabled, region, status)
     VALUES (?, ?, ?, 1, 'default', 'unknown')`
  ).bind(name, "gw-" + randomString(10), host).run();
  const id = r.meta && r.meta.last_row_id;
  t.msgId = t.msgId || 0;
  await tgShow(t, "✅ Gateway created.", []);
  t.msgId = 0;
  return tgGwDetail(env, t, id);
}

/* ---- users / configs ---- */

async function tgUserDetail(env, t, id) {
  const u = await env.DB.prepare(
    `SELECT a.*, g.name AS gw FROM accounts a LEFT JOIN gateways g ON g.id = a.gateway_id
     WHERE a.id = ? LIMIT 1`
  ).bind(id).first();
  if (!u) return tgShow(t, "User not found.", [[tgb("⬅️ Back", "u")]]);
  const on = Number(u.enabled) === 1;
  const lim = Number(u.data_limit || 0);
  let s = "👤 <b>" + hx(u.display_name || u.username) + "</b> " + (on ? "🟢" : "🔴") + "\n\n";
  s += "Username: <code>" + hx(u.username) + "</code>\n";
  s += "UUID: <code>" + hx(u.uuid) + "</code>\n";
  s += "Traffic: " + tgBytes(u.data_used) + " / " + (lim ? tgBytes(lim) : "Unlimited") + "\n";
  s += "Expiry: " + (u.expires_at ? hx(String(u.expires_at).slice(0, 16).replace("T", " ")) : "Never") + "\n";
  s += "Gateway: " + hx(u.gw || "this worker") + "\n";
  return tgShow(t, s, [
    [tgb("🔑 Config", "u:c:" + id), tgb("🔗 Create sub", "s:p:" + id)],
    [tgb(on ? "⏸ Disable" : "▶️ Enable", "u:t:" + id), tgb("♻️ Reset traffic", "u:r:" + id)],
    [tgb("🗑 Delete", "u:x:" + id)],
    [tgb("⬅️ Back", "u")]
  ]);
}

async function tgShowConfig(env, t, id, header) {
  const acc = await env.DB.prepare(
    "SELECT id, username, display_name, uuid, gateway_id FROM accounts WHERE id = ? LIMIT 1"
  ).bind(id).first();
  if (!acc) return tgShow(t, "User not found.", [[tgb("⬅️ Back", "u")]]);
  const r = await buildAccountLinks(env, acc, t.host, "auto");
  if (r.error) return tgShow(t, "⚠️ " + hx(r.error), [[tgb("⬅️ Back", "u:v:" + id)]]);
  let s = (header || "🔑 <b>Config</b>") + "\n\n";
  for (const l of r.links) s += "<b>" + hx(l.name) + "</b>\n<code>" + hx(l.link) + "</code>\n\n";
  s += "Tap a link to copy it.";
  return tgShow(t, s, [
    [tgb("🔗 Create sub", "s:p:" + id)],
    [tgb("⬅️ User", "u:v:" + id), tgb("🏠 Menu", "m")]
  ]);
}

function tgAskGb(t) {
  return tgShow(t, "📦 <b>Data limit</b> (GB)\nPick one or type a number:", [
    [tgb("♾ Unlimited", "u:gb:0"), tgb("5", "u:gb:5"), tgb("10", "u:gb:10")],
    [tgb("20", "u:gb:20"), tgb("50", "u:gb:50"), tgb("100", "u:gb:100")],
    [tgb("✖ Cancel", "u")]
  ]);
}
function tgAskDays(t) {
  return tgShow(t, "⏳ <b>Duration</b> (days)\nPick one or type a number:", [
    [tgb("♾ Never", "u:dy:0"), tgb("7", "u:dy:7"), tgb("30", "u:dy:30")],
    [tgb("60", "u:dy:60"), tgb("90", "u:dy:90"), tgb("180", "u:dy:180")],
    [tgb("✖ Cancel", "u")]
  ]);
}
async function tgAskGateway(env, t) {
  const r = await env.DB.prepare("SELECT id, name FROM gateways WHERE enabled = 1 ORDER BY id DESC LIMIT 20").all();
  const rows = [[tgb("🏠 This worker (no gateway)", "u:gw:0")]];
  for (const g of r.results || []) rows.push([tgb("🌐 " + g.name, "u:gw:" + g.id)]);
  rows.push([tgb("✖ Cancel", "u")]);
  return tgShow(t, "🌐 <b>Gateway</b>\nWhich gateway should this user use?", rows);
}

async function tgFinishUser(env, t, d, gatewayId) {
  await tgClearState(env, t.uid);
  const uuid = newUuid();
  const limit = Math.max(0, Math.round(Number(d.gb || 0) * 1073741824));
  const days = Math.max(0, Math.round(Number(d.days || 0)));
  const expires = days ? new Date(Date.now() + days * 86400000).toISOString() : null;
  const r = await env.DB.prepare(
    `INSERT INTO accounts
     (username, display_name, uuid, enabled, data_limit, data_used, device_limit, expires_at, note, gateway_id)
     VALUES (?, ?, ?, 1, ?, 0, 0, ?, 'created by telegram', ?)`
  ).bind(d.username, d.username, uuid, limit, expires, gatewayId || null).run();
  return tgShowConfig(env, t, r.meta && r.meta.last_row_id, "✅ <b>User created</b>");
}

async function tgUser(env, t, p) {
  const a = p[1];
  const id = Number(p[2] || 0);

  if (!a) {
    await tgClearState(env, t.uid);
    const r = await env.DB.prepare("SELECT id, username, display_name, enabled FROM accounts ORDER BY id DESC LIMIT 12").all();
    const rows = [[tgb("➕ New config", "u:new")]];
    for (const u of r.results || [])
      rows.push([tgb((Number(u.enabled) === 1 ? "🟢 " : "🔴 ") + (u.display_name || u.username), "u:v:" + u.id)]);
    rows.push([tgb("🏠 Menu", "m")]);
    return tgShow(t, "👤 <b>Configs</b>\nLatest users (newest first):", rows);
  }
  if (a === "new") {
    await tgSetState(env, t.uid, { step: "u_name", d: {} });
    return tgShow(t, "👤 Send the <b>username</b> (letters, numbers, _ . -):", [
      [tgb("🎲 Random", "u:rnd")],
      [tgb("✖ Cancel", "u")]
    ]);
  }
  if (a === "rnd") {
    const st = await tgGetState(env, t.uid);
    if (!st || st.step !== "u_name") return tgUser(env, t, ["u"]);
    st.d.username = "user-" + randomString(6);
    st.step = "u_gb";
    await tgSetState(env, t.uid, st);
    return tgAskGb(t);
  }
  if (a === "gb" || a === "dy" || a === "gw") {
    const st = await tgGetState(env, t.uid);
    if (!st || !st.d || !st.d.username) return tgUser(env, t, ["u"]);
    const n = Number(p[2] || 0);
    if (a === "gb") {
      st.d.gb = n; st.step = "u_days";
      await tgSetState(env, t.uid, st);
      return tgAskDays(t);
    }
    if (a === "dy") {
      st.d.days = n; st.step = "u_gw";
      await tgSetState(env, t.uid, st);
      return tgAskGateway(env, t);
    }
    return tgFinishUser(env, t, st.d, n);
  }
  if (a === "v") return tgUserDetail(env, t, id);
  if (a === "c") return tgShowConfig(env, t, id);
  if (a === "t") {
    await env.DB.prepare("UPDATE accounts SET enabled = CASE WHEN enabled = 1 THEN 0 ELSE 1 END, updated_at = unixepoch() WHERE id = ?").bind(id).run();
    return tgUserDetail(env, t, id);
  }
  if (a === "r") {
    await env.DB.prepare("UPDATE accounts SET data_used = 0, updated_at = unixepoch() WHERE id = ?").bind(id).run();
    return tgUserDetail(env, t, id);
  }
  if (a === "x") {
    return tgShow(t, "Delete this user and their subscriptions?", [
      [tgb("✅ Yes, delete", "u:xx:" + id), tgb("✖ No", "u:v:" + id)]
    ]);
  }
  if (a === "xx") {
    await env.DB.batch([
      env.DB.prepare("DELETE FROM subscriptions WHERE account_id = ?").bind(id),
      env.DB.prepare("DELETE FROM accounts WHERE id = ?").bind(id)
    ]);
    return tgUser(env, t, ["u"]);
  }
  return tgUser(env, t, ["u"]);
}

/* ---- subscriptions ---- */

async function tgSubDetail(env, t, id) {
  const s = await env.DB.prepare(
    `SELECT s.id, s.token, s.name, s.enabled, s.scanner_ip, a.username
     FROM subscriptions s JOIN accounts a ON a.id = s.account_id WHERE s.id = ? LIMIT 1`
  ).bind(id).first();
  if (!s) return tgShow(t, "Subscription not found.", [[tgb("⬅️ Back", "s")]]);
  const on = Number(s.enabled) === 1;
  let txt = "🔗 <b>" + hx(s.name || "Unnamed") + "</b> " + (on ? "🟢" : "🔴") + "\n\n";
  txt += "User: <code>" + hx(s.username) + "</code>\n";
  txt += "Mode: " + hx(s.scanner_ip || "auto") + "\n\n";
  txt += "URL:\n<code>https://" + hx(t.host) + "/sub/" + hx(s.token) + "</code>";
  return tgShow(t, txt, [
    [tgb(on ? "⏸ Disable" : "▶️ Enable", "s:t:" + id), tgb("🗑 Delete", "s:x:" + id)],
    [tgb("⬅️ Back", "s")]
  ]);
}

async function tgSub(env, t, p) {
  const a = p[1];
  const id = Number(p[2] || 0);

  if (!a) {
    await tgClearState(env, t.uid);
    const r = await env.DB.prepare(
      `SELECT s.id, s.name, s.enabled, a.username FROM subscriptions s
       JOIN accounts a ON a.id = s.account_id ORDER BY s.id DESC LIMIT 12`
    ).all();
    const rows = [[tgb("➕ New subscription", "s:new")]];
    for (const s of r.results || [])
      rows.push([tgb((Number(s.enabled) === 1 ? "🟢 " : "🔴 ") + (s.name || "Unnamed") + " - " + s.username, "s:v:" + s.id)]);
    rows.push([tgb("🏠 Menu", "m")]);
    return tgShow(t, "🔗 <b>Subscriptions</b>", rows);
  }
  if (a === "new") {
    const r = await env.DB.prepare("SELECT id, username, display_name FROM accounts ORDER BY id DESC LIMIT 15").all();
    const rows = [];
    for (const u of r.results || []) rows.push([tgb("👤 " + (u.display_name || u.username), "s:p:" + u.id)]);
    rows.push([tgb("✖ Cancel", "s")]);
    return tgShow(t, "🔗 Choose the <b>user</b> for the subscription:", rows);
  }
  if (a === "p") {
    return tgShow(t, "🔗 Which addresses should the subscription contain?", [
      [tgb("⚡ Auto (direct + top IPs)", "s:m:" + id + ":auto")],
      [tgb("🎯 Direct only", "s:m:" + id + ":direct")],
      [tgb("✖ Cancel", "s")]
    ]);
  }
  if (a === "m") {
    const mode = p[3] === "direct" ? "direct" : "auto";
    const acc = await env.DB.prepare("SELECT id, username, display_name FROM accounts WHERE id = ? LIMIT 1").bind(id).first();
    if (!acc) return tgShow(t, "User not found.", [[tgb("⬅️ Back", "s")]]);
    const token = randomHex(24);
    const name = (acc.display_name || acc.username) + " sub";
    const r = await env.DB.prepare(
      "INSERT INTO subscriptions (account_id, token, name, enabled, scanner_ip, scanner_port) VALUES (?, ?, ?, 1, ?, 443)"
    ).bind(id, token, name, mode).run();
    return tgShow(
      t,
      "✅ <b>Subscription created</b>\n\n<code>https://" + hx(t.host) + "/sub/" + token + "</code>\n\nTap to copy.",
      [[tgb("📄 Details", "s:v:" + (r.meta && r.meta.last_row_id))], [tgb("🏠 Menu", "m")]]
    );
  }
  if (a === "v") return tgSubDetail(env, t, id);
  if (a === "t") {
    await env.DB.prepare("UPDATE subscriptions SET enabled = CASE WHEN enabled = 1 THEN 0 ELSE 1 END, updated_at = CURRENT_TIMESTAMP WHERE id = ?").bind(id).run();
    return tgSubDetail(env, t, id);
  }
  if (a === "x") {
    return tgShow(t, "Delete this subscription?", [
      [tgb("✅ Yes, delete", "s:xx:" + id), tgb("✖ No", "s:v:" + id)]
    ]);
  }
  if (a === "xx") {
    await env.DB.prepare("DELETE FROM subscriptions WHERE id = ?").bind(id).run();
    return tgSub(env, t, ["s"]);
  }
  return tgSub(env, t, ["s"]);
}

/* ---- typed text steps ---- */

async function tgOnText(env, t, st, text) {
  const step = st.step;

  if (step === "gw_name") {
    st.d.name = text.slice(0, 100);
    st.step = "gw_host";
    await tgSetState(env, t.uid, st);
    return tgShow(
      t,
      "🌐 Send the <b>host</b> (domain users connect to), or use this worker:\n<code>" + hx(t.host) + "</code>",
      [[tgb("✅ Use this worker", "g:host")], [tgb("✖ Cancel", "g")]]
    );
  }
  if (step === "gw_host") {
    const host = cleanHost(text);
    if (!/^[a-z0-9.\-]+(:\d+)?$/.test(host))
      return tgShow(t, "⚠️ Invalid host. Send a domain like <code>example.com</code>:", [[tgb("✖ Cancel", "g")]]);
    return tgFinishGateway(env, t, st.d.name, host);
  }

  if (step === "u_name") {
    if (!/^[A-Za-z0-9_.\-]{1,50}$/.test(text))
      return tgShow(t, "⚠️ Use only letters, numbers, _ . - (max 50). Try again:", [[tgb("🎲 Random", "u:rnd")], [tgb("✖ Cancel", "u")]]);
    const dup = await env.DB.prepare("SELECT id FROM accounts WHERE username = ? LIMIT 1").bind(text).first();
    if (dup)
      return tgShow(t, "⚠️ That username already exists. Send another:", [[tgb("🎲 Random", "u:rnd")], [tgb("✖ Cancel", "u")]]);
    st.d.username = text;
    st.step = "u_gb";
    await tgSetState(env, t.uid, st);
    return tgAskGb(t);
  }
  if (step === "u_gb") {
    const n = Number(text);
    if (!Number.isFinite(n) || n < 0) return tgShow(t, "⚠️ Send a number (GB), 0 = unlimited:", [[tgb("✖ Cancel", "u")]]);
    st.d.gb = n; st.step = "u_days";
    await tgSetState(env, t.uid, st);
    return tgAskDays(t);
  }
  if (step === "u_days") {
    const n = Math.round(Number(text));
    if (!Number.isFinite(n) || n < 0) return tgShow(t, "⚠️ Send number of days, 0 = never:", [[tgb("✖ Cancel", "u")]]);
    st.d.days = n; st.step = "u_gw";
    await tgSetState(env, t.uid, st);
    return tgAskGateway(env, t);
  }

  await tgClearState(env, t.uid);
  return tgMain(t);
}

/* ------------------------------------------------------------------ */
/* panel UI                                                            */
/* ------------------------------------------------------------------ */

function app() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Trendify Nexus</title>
<style>
*{box-sizing:border-box}
html,body{margin:0;padding:0;min-height:100%;color:#f5f7fb;font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
:root{--logo:url("https://raw.githubusercontent.com/Trendiify/trendify-v2-cloud/main/logo/Untitled%20design.png")}
body{
  background-color:#070b14;
  background-image:linear-gradient(rgba(7,11,20,.75),rgba(7,11,20,.75)),url("https://raw.githubusercontent.com/Trendiify/trendify-v2-cloud/main/logo/6ed1ab4d-e489-42dc-8eff-36d1e07024a0.png");
  background-size:cover;
  background-position:center;
  background-attachment:fixed;
}
button,input,select,textarea{font:inherit}
button{cursor:pointer}
.layout{min-height:100vh;display:flex}
.sidebar{width:230px;background:#0a101c;border-right:1px solid #1b2638;padding:18px;position:fixed;left:0;top:0;bottom:0;overflow-y:auto}
.brand{display:flex;gap:12px;align-items:center;margin-bottom:26px}
.logo{width:40px;height:40px;border-radius:10px;background:var(--logo) center/contain no-repeat;color:transparent;font-size:0;flex:none}
.brand-title{font-weight:900}
.brand-sub{color:#7f8da5;font-size:12px;margin-top:3px}
.nav{display:grid;gap:6px}
.nav button{width:100%;text-align:left;border:0;border-radius:10px;padding:11px 12px;background:transparent;color:#9eabc1}
.nav button:hover,.nav button.active{background:#131d2d;color:#fff}
.main{margin-left:230px;width:calc(100% - 230px);padding:22px}
.topbar{display:flex;align-items:center;justify-content:space-between;gap:15px;margin-bottom:20px}
.topbar h1{margin:0;font-size:24px}
.topbar p{margin:5px 0 0;color:#78869d;font-size:13px}
.actions{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.btn{border:1px solid #29364c;background:#111a2a;color:#e9eef8;padding:9px 13px;border-radius:9px}
.btn:hover{background:#172236}
.btn:disabled{opacity:.5;cursor:not-allowed}
.btn.primary{background:#f0b90b;color:#111827;border-color:#f0b90b;font-weight:800}
.panel{background:#0c1422;border:1px solid #1b283c;border-radius:14px;overflow:hidden;margin-bottom:18px}
.panel-head{padding:15px 18px;border-bottom:1px solid #1b283c;display:flex;align-items:center;justify-content:space-between;gap:10px}
.panel-title{font-weight:800}
.pad{padding:18px}
.cards{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px}
.card{background:#0d1727;border:1px solid #1b283c;border-radius:13px;padding:16px}
.card-label{color:#7e8da6;font-size:12px}
.card-value{font-size:24px;font-weight:900;margin-top:8px}
.muted{color:#7e8da6;font-size:12px}
.table-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse}
th,td{padding:12px 14px;border-bottom:1px solid #182338;text-align:left;white-space:nowrap}
th{color:#71809a;font-size:12px;font-weight:700}
td{font-size:13px}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px}
.badge{display:inline-flex;align-items:center;padding:4px 8px;border-radius:999px;font-size:11px;font-weight:800}
.badge.green{background:#123523;color:#70e59c}
.badge.red{background:#3a171b;color:#ff8992}
.badge.yellow{background:#3b3010;color:#f8d76a}
.small-actions{display:flex;gap:5px;flex-wrap:wrap}
.icon-btn{border:1px solid #29364c;background:#111a2a;color:#d9e2f1;border-radius:7px;padding:6px 8px;font-size:12px}
.icon-btn:hover{background:#172236}
.icon-btn.danger{border-color:#6b2a2f;color:#ff8f8f}
.empty{padding:30px;text-align:center;color:#71809a}
.warn{background:#3b3010;border:1px solid #6b5a1c;color:#f8d76a;border-radius:11px;padding:12px 14px;margin-bottom:16px;font-size:13px}
.field{display:grid;gap:6px}
.field label{font-size:12px;color:#8c9ab0}
.field input,.field select,.field textarea{width:100%;background:#080f1b;color:#fff;border:1px solid #29364c;border-radius:9px;padding:10px;outline:none}
.field textarea{min-height:90px;resize:vertical;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}
.field input:focus,.field select:focus,.field textarea:focus{border-color:#5773b8}
.form-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:13px}
.row{display:flex;gap:10px;align-items:end;flex-wrap:wrap}
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.65);display:none;align-items:center;justify-content:center;padding:20px;z-index:100}
.modal{width:min(720px,100%);max-height:90vh;overflow-y:auto;background:#0c1422;border:1px solid #27354b;border-radius:15px}
.modal-head,.modal-foot{padding:15px 18px;display:flex;align-items:center;justify-content:space-between}
.modal-head{border-bottom:1px solid #1b283c}
.modal-foot{border-top:1px solid #1b283c;justify-content:flex-end;gap:8px}
.modal-body{padding:18px}
.login-wrap{min-height:100vh;display:grid;place-items:center;padding:20px}
.login-box{width:min(420px,100%);background:#0c1422;border:1px solid #1d2a3e;border-radius:17px;padding:25px}
.login-box h1{margin:0 0 7px}
.login-logo{width:84px;height:84px;margin:0 auto 14px;background:var(--logo) center/contain no-repeat}
.login-box{text-align:center}
.login-box .field{text-align:left}
.login-box p{color:#7d8ba2;font-size:13px;margin:0 0 20px}
.login-form{display:grid;gap:12px}
.check{display:flex;gap:8px;align-items:center;margin-top:14px;font-size:13px}
.check input{width:auto}
body,h1,h2,h3,p,span,div,td,th,label,strong,a,li{color:#fff}
.muted,.topbar p,.brand-sub,.card-label,th,.field label,.empty,.login-box p{color:#e6ebf5}
.field input,.field select,.field textarea,.btn,.icon-btn,.nav button{color:#fff}
select option{background:#0c1422;color:#fff}
::placeholder{color:#b8c2d6}
.btn.primary{color:#111827}
.badge.green{color:#8dffb8}
.badge.red{color:#ffb0b6}
.badge.yellow{color:#ffe58a}
.icon-btn.danger{color:#ffb0b6}
@media(max-width:900px){
 .sidebar{width:64px;padding:12px 8px}
 .brand-title,.brand-sub,.nav .lbl{display:none}
 .main{margin-left:64px;width:calc(100% - 64px)}
 .cards{grid-template-columns:repeat(2,minmax(0,1fr))}
}
@media(max-width:600px){
 .cards,.form-grid{grid-template-columns:1fr}
 .main{padding:13px}
 .topbar{align-items:flex-start;flex-direction:column}
}
</style>
</head>
<body>
<div id="root"></div>
<div id="modalOverlay" class="modal-overlay"><div id="modal" class="modal"></div></div>

<script>
(function () {
  var $ = function (id) { return document.getElementById(id); };
  var root = $('root');
  var S = { users: [], gateways: [], subs: [], scan: [], me: null, scanning: false };

  function esc(v) {
    return String(v == null ? '' : v)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function api(path, opt) {
    opt = opt || {};
    opt.credentials = 'same-origin';
    if (opt.body && typeof opt.body !== 'string') {
      opt.body = JSON.stringify(opt.body);
      opt.headers = Object.assign({ 'Content-Type': 'application/json' }, opt.headers || {});
    }
    return fetch(path, opt).then(function (r) {
      return r.text().then(function (t) {
        var d;
        try { d = t ? JSON.parse(t) : {}; } catch (e) { d = { success: false, error: t || 'Bad response' }; }
        if (r.status === 401 && path.indexOf('/api/auth/') !== 0) showLogin();
        if (!r.ok || d.success === false) {
          var err = new Error(d.error || ('HTTP ' + r.status));
          err.status = r.status;
          throw err;
        }
        return d;
      });
    });
  }

  function toast(msg) {
    var old = $('nexusToast'); if (old) old.remove();
    var el = document.createElement('div');
    el.id = 'nexusToast';
    el.textContent = msg;
    el.style.cssText = 'position:fixed;bottom:20px;right:20px;z-index:9999;background:#111a2a;border:1px solid #34445f;color:#fff;padding:12px 15px;border-radius:10px;box-shadow:0 10px 35px rgba(0,0,0,.35);max-width:80vw';
    document.body.appendChild(el);
    setTimeout(function () { el.remove(); }, 3500);
  }

  function copyText(t) {
    function fallback() {
      var ta = document.createElement('textarea');
      ta.value = t; document.body.appendChild(ta); ta.select();
      try { document.execCommand('copy'); toast('Copied'); } catch (e) { toast('Copy failed'); }
      ta.remove();
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(t).then(function () { toast('Copied'); }, fallback);
    } else { fallback(); }
  }

  function fmtBytes(n) {
    n = Number(n || 0);
    if (!n) return '0 B';
    var u = ['B', 'KB', 'MB', 'GB', 'TB'], i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return n.toFixed(n >= 10 || i === 0 ? 0 : 2) + ' ' + u[i];
  }

  function fmtDate(iso) {
    if (!iso) return 'Never';
    var d = new Date(iso);
    return isNaN(d) ? esc(iso) : d.toLocaleString();
  }

  function toLocalInput(iso) {
    if (!iso) return '';
    var d = new Date(iso);
    if (isNaN(d)) return '';
    var p = function (n) { return String(n).padStart(2, '0'); };
    return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + 'T' + p(d.getHours()) + ':' + p(d.getMinutes());
  }

  function openModal(html) { $('modal').innerHTML = html; $('modalOverlay').style.display = 'flex'; }
  function closeModal() { $('modalOverlay').style.display = 'none'; $('modal').innerHTML = ''; }

  function hdr(title, sub, actions) {
    return '<div class="topbar"><div><h1>' + esc(title) + '</h1><p>' + esc(sub || '') + '</p></div>' +
      '<div class="actions">' + (actions || '') + '</div></div>';
  }

  function fail(id) {
    return function (e) {
      var el = $(id);
      if (el) el.innerHTML = '<div class="empty">' + esc(e.message || 'Failed') + '</div>';
    };
  }

  function val(id) { var el = $(id); return el ? el.value : ''; }

  /* ---------- login / shell ---------- */

  function showLogin() {
    closeModal();
    root.innerHTML =
      '<div class="login-wrap"><div class="login-box"><div class="login-logo"></div><h1>Trendify Nexus</h1><p>Cloudflare Control Panel</p>' +
      '<form class="login-form" data-form="login">' +
      '<div class="field"><label>Username</label><input id="loginUsername" value="admin" autocomplete="username"></div>' +
      '<div class="field"><label>Password</label><input id="loginPassword" type="password" autocomplete="current-password"></div>' +
      '<button id="loginButton" class="btn primary" type="submit">Login</button>' +
      '<div id="loginError" class="muted"></div></form></div></div>';
  }

  function doLogin() {
    var b = $('loginButton'), er = $('loginError');
    b.disabled = true; b.textContent = 'Signing in...'; er.textContent = '';
    api('/api/auth/login', { method: 'POST', body: { username: val('loginUsername').trim(), password: val('loginPassword') } })
      .then(function () { return api('/api/auth/me'); })
      .then(function (me) { S.me = me; showShell(); })
      .catch(function (e) { er.textContent = e.message || 'Login failed'; b.disabled = false; b.textContent = 'Login'; });
  }

  function showShell() {
    root.innerHTML =
      '<div class="layout"><aside class="sidebar">' +
      '<div class="brand"><div class="logo">N</div><div><div class="brand-title">Trendify Nexus</div><div class="brand-sub">All-in-one Worker</div></div></div>' +
      '<nav class="nav">' +
      nb('dashboard', '&#9672;', 'Dashboard') + nb('users', '&#9673;', 'Users') +
      nb('gateways', '&#9678;', 'Gateways') + nb('scanner', '&#8982;', 'Scanner') +
      nb('subs', '&#9671;', 'Subscriptions') + nb('settings', '&#9881;', 'Settings') +
      '</nav><div style="margin-top:25px"><button class="btn" style="width:100%" data-act="logout">Logout</button></div>' +
      '</aside><main class="main"><div id="view"></div></main></div>';
    go('dashboard');
  }

  function nb(page, icon, label) {
    return '<button data-act="nav" data-id="' + page + '">' + icon + ' <span class="lbl">' + label + '</span></button>';
  }

  function go(page) {
    var btns = document.querySelectorAll('.nav button');
    for (var i = 0; i < btns.length; i++) {
      btns[i].classList.toggle('active', btns[i].getAttribute('data-id') === page);
    }
    var map = { dashboard: pDash, users: pUsers, gateways: pGateways, scanner: pScanner, subs: pSubs, settings: pSettings };
    (map[page] || pDash)();
  }

  /* ---------- dashboard ---------- */

  function pDash() {
    $('view').innerHTML = hdr('Dashboard', 'Trendify Nexus overview', '') +
      '<div id="warnBox"></div><div class="cards" id="statCards"><div class="empty">Loading...</div></div>' +
      '<div class="panel" style="margin-top:18px"><div class="panel-head"><div class="panel-title">System Status</div></div>' +
      '<div class="pad"><span class="badge green">&#9679; Nexus Online</span>' +
      '<div class="muted" style="margin-top:12px">Panel, gateways, subscriptions and the VLESS endpoint all run inside this Worker.<br>WebSocket path: <span class="mono">/ws/&lt;gatewayId&gt;</span> &middot; Host: <span class="mono">' + esc(location.host) + '</span></div></div></div>';
    api('/api/auth/me').then(function (me) {
      if (me.default_password) {
        $('warnBox').innerHTML = '<div class="warn">You are still using the default admin password. Go to Settings and change it now.</div>';
      }
    }).catch(function () {});
    api('/api/stats').then(function (d) {
      var s = d.stats || {};
      $('statCards').innerHTML =
        card('Accounts', s.accounts) + card('Active Accounts', s.active_accounts) +
        card('Gateways', s.active_gateways + ' / ' + s.gateways) + card('Subscriptions', s.subscriptions) +
        card('Total Traffic', fmtBytes(s.traffic));
    }).catch(fail('statCards'));
  }

  function card(label, value) {
    return '<div class="card"><div class="card-label">' + esc(label) + '</div><div class="card-value">' + esc(value) + '</div></div>';
  }

  /* ---------- users ---------- */

  function pUsers() {
    $('view').innerHTML = hdr('Users', 'Manage VLESS accounts', '<button class="btn primary" data-act="user-new">+ Create User</button>') +
      '<div class="panel"><div id="usersTable"><div class="empty">Loading...</div></div></div>';
    Promise.all([api('/api/accounts'), api('/api/gateways')]).then(function (r) {
      S.users = r[0].accounts || []; S.gateways = r[1].gateways || [];
      drawUsers();
    }).catch(fail('usersTable'));
  }

  function drawUsers() {
    if (!S.users.length) { $('usersTable').innerHTML = '<div class="empty">No users configured.</div>'; return; }
    var h = '<div class="table-wrap"><table><thead><tr><th>User</th><th>UUID</th><th>Gateway</th><th>Status</th><th>Traffic</th><th>Expiry</th><th>Actions</th></tr></thead><tbody>';
    S.users.forEach(function (u) {
      var on = Number(u.enabled) === 1;
      var lim = Number(u.data_limit || 0);
      h += '<tr><td><strong>' + esc(u.display_name || u.username) + '</strong><div class="mono">' + esc(u.username) + '</div></td>' +
        '<td><span class="mono">' + esc(u.uuid) + '</span></td>' +
        '<td>' + esc(u.gateway_name || '-') + '</td>' +
        '<td><span class="badge ' + (on ? 'green' : 'red') + '">' + (on ? 'Active' : 'Disabled') + '</span></td>' +
        '<td>' + fmtBytes(u.data_used) + ' / ' + (lim ? fmtBytes(lim) : 'Unlimited') + '</td>' +
        '<td>' + fmtDate(u.expires_at) + '</td>' +
        '<td><div class="small-actions">' +
        '<button class="icon-btn" data-act="user-config" data-id="' + u.id + '">Config</button>' +
        '<button class="icon-btn" data-act="user-edit" data-id="' + u.id + '">Edit</button>' +
        '<button class="icon-btn" data-act="user-toggle" data-id="' + u.id + '">' + (on ? 'Disable' : 'Enable') + '</button>' +
        '<button class="icon-btn" data-act="user-reset" data-id="' + u.id + '">Reset</button>' +
        '<button class="icon-btn danger" data-act="user-delete" data-id="' + u.id + '">Delete</button>' +
        '</div></td></tr>';
    });
    $('usersTable').innerHTML = h + '</tbody></table></div>';
  }

  function gwOptions(selected) {
    var h = '<option value="">- none (use this worker host) -</option>';
    S.gateways.forEach(function (g) {
      h += '<option value="' + g.id + '"' + (Number(g.id) === Number(selected) ? ' selected' : '') + '>' + esc(g.name) + '</option>';
    });
    return h;
  }

  function userModal(u) {
    var edit = !!u;
    u = u || {};
    var gb = u.data_limit ? Math.round((Number(u.data_limit) / 1073741824) * 100) / 100 : 0;
    openModal(
      '<div class="modal-head"><strong>' + (edit ? 'Edit User' : 'Create User') + '</strong><button class="icon-btn" data-act="close">&times;</button></div>' +
      '<div class="modal-body"><div class="form-grid">' +
      '<input type="hidden" id="fId" value="' + esc(u.id || '') + '">' +
      '<div class="field"><label>Username</label><input id="fUsername" value="' + esc(u.username || '') + '" placeholder="user01"></div>' +
      '<div class="field"><label>Display name</label><input id="fDisplay" value="' + esc(u.display_name || '') + '" placeholder="User 01"></div>' +
      (edit
        ? '<div class="field" style="grid-column:1/-1"><label>UUID</label><div class="row"><input id="fUuid" style="flex:1" value="' + esc(u.uuid || '') + '"><button class="icon-btn" data-act="uuid-gen">Regenerate</button></div></div>'
        : '') +
      '<div class="field"><label>Data limit in GB (0 = unlimited)</label><input id="fLimit" type="number" min="0" step="0.1" value="' + gb + '"></div>' +
      '<div class="field"><label>Expiry (empty = never)</label><input id="fExpires" type="datetime-local" value="' + esc(toLocalInput(u.expires_at)) + '"></div>' +
      '<div class="field"><label>Gateway</label><select id="fGateway">' + gwOptions(u.gateway_id) + '</select></div>' +
      '<div class="field"><label>Note</label><input id="fNote" value="' + esc(u.note || '') + '" placeholder="Optional"></div>' +
      '</div></div>' +
      '<div class="modal-foot"><button class="btn" data-act="close">Cancel</button><button class="btn primary" data-act="user-save">' + (edit ? 'Save' : 'Create') + '</button></div>'
    );
  }

  function saveUser() {
    var id = val('fId');
    var username = val('fUsername').trim();
    if (!username) { toast('Username is required'); return; }
    var exp = val('fExpires');
    var body = {
      username: username,
      display_name: val('fDisplay').trim(),
      data_limit: Math.round(Number(val('fLimit') || 0) * 1073741824),
      expires_at: exp ? new Date(exp).toISOString() : null,
      gateway_id: val('fGateway') ? Number(val('fGateway')) : null,
      note: val('fNote').trim()
    };
    if (id) body.uuid = val('fUuid').trim();
    api(id ? '/api/accounts/' + id : '/api/accounts', { method: id ? 'PUT' : 'POST', body: body })
      .then(function () { closeModal(); toast(id ? 'User updated' : 'User created'); pUsers(); })
      .catch(function (e) { toast(e.message); });
  }

  function findBy(list, id) {
    for (var i = 0; i < list.length; i++) if (Number(list[i].id) === Number(id)) return list[i];
    return null;
  }

  function showConfig(id) {
    api('/api/accounts/' + id + '/config').then(function (d) {
      var h = '<div class="modal-head"><strong>User Config</strong><button class="icon-btn" data-act="close">&times;</button></div><div class="modal-body">';
      d.links.forEach(function (l) {
        h += '<div class="field" style="margin-bottom:14px"><label>' + esc(l.name) + '</label>' +
          '<textarea readonly>' + esc(l.link) + '</textarea>' +
          '<div><button class="icon-btn" data-act="copy" data-val="' + esc(l.link) + '">Copy</button></div></div>';
      });
      h += '<div class="muted">The first link connects directly to your worker. Other links use the top IPs from the Scanner page.</div></div>' +
        '<div class="modal-foot"><button class="btn" data-act="close">Close</button></div>';
      openModal(h);
    }).catch(function (e) { toast(e.message); });
  }

  /* ---------- gateways ---------- */

  function pGateways() {
    $('view').innerHTML = hdr('Gateways', 'Entry points served by this worker', '<button class="btn primary" data-act="gw-new">+ Create Gateway</button>') +
      '<div class="panel"><div id="gwTable"><div class="empty">Loading...</div></div></div>' +
      '<div class="panel"><div class="panel-head"><div class="panel-title">Connection Logs</div><div class="actions">' +
      '<button class="icon-btn" data-act="logs-refresh">Refresh</button><button class="icon-btn danger" data-act="logs-clear">Clear</button></div></div>' +
      '<div id="logsTable"><div class="empty">Loading...</div></div></div>';
    loadGateways(); loadLogs();
  }

  function loadGateways() {
    api('/api/gateways').then(function (d) {
      S.gateways = d.gateways || [];
      if (!S.gateways.length) { $('gwTable').innerHTML = '<div class="empty">No gateways configured.</div>'; return; }
      var h = '<div class="table-wrap"><table><thead><tr><th>Name</th><th>Host</th><th>Users</th><th>Status</th><th>Latency</th><th>Enabled</th><th>Actions</th></tr></thead><tbody>';
      S.gateways.forEach(function (g) {
        var st = String(g.status || 'unknown');
        var cls = st === 'online' ? 'green' : (st === 'offline' ? 'red' : 'yellow');
        var on = Number(g.enabled) === 1;
        var isWorker = String(g.worker_name || '').indexOf('nexus-gw-') === 0;
        h += '<tr><td><strong>' + esc(g.name) + '</strong><div class="muted">' + esc(g.region || 'default') + (isWorker ? ' &middot; Worker' : '') + '</div></td>' +
          '<td><span class="mono">' + esc(g.worker_url || location.host) + '</span></td>' +
          '<td>' + esc(g.users) + '</td>' +
          '<td><span class="badge ' + cls + '">' + esc(st) + '</span>' +
          (g.last_error ? '<div class="muted" style="max-width:240px;white-space:normal">' + esc(g.last_error) + '</div>' : '') + '</td>' +
          '<td>' + (g.latency_ms != null ? esc(g.latency_ms) + ' ms' : '-') + '</td>' +
          '<td><span class="badge ' + (on ? 'green' : 'red') + '">' + (on ? 'Enabled' : 'Disabled') + '</span></td>' +
          '<td><div class="small-actions">' +
          '<button class="icon-btn" data-act="gw-check" data-id="' + g.id + '">Check</button>' +
          (isWorker ? '<button class="icon-btn" data-act="gw-redeploy" data-id="' + g.id + '">Redeploy</button>' : '') +
          '<button class="icon-btn" data-act="gw-edit" data-id="' + g.id + '">Edit</button>' +
          '<button class="icon-btn" data-act="gw-toggle" data-id="' + g.id + '">' + (on ? 'Disable' : 'Enable') + '</button>' +
          '<button class="icon-btn danger" data-act="gw-delete" data-id="' + g.id + '">Delete</button>' +
          '</div></td></tr>';
      });
      $('gwTable').innerHTML = h + '</tbody></table></div>';
    }).catch(fail('gwTable'));
  }

  function gwModal(g) {
    var edit = !!g; g = g || {};
    openModal(
      '<div class="modal-head"><strong>' + (edit ? 'Edit Gateway' : 'Create Gateway') + '</strong><button class="icon-btn" data-act="close">&times;</button></div>' +
      '<div class="modal-body"><div class="form-grid">' +
      '<input type="hidden" id="gId" value="' + esc(g.id || '') + '">' +
      '<div class="field"><label>Name</label><input id="gName" value="' + esc(g.name || '') + '" placeholder="Europe Gateway"></div>' +
      '<div class="field"><label>Region label</label><input id="gRegion" value="' + esc(g.region || '') + '" placeholder="eu"></div>' +
      '<div class="field" style="grid-column:1/-1"><label>Host (domain users connect to - leave empty for this worker)</label>' +
      '<input id="gHost" value="' + esc(g.worker_url || '') + '" placeholder="' + esc(location.host) + '"></div>' +
      '</div>' +
      (edit ? '' : '<label class="check"><input type="checkbox" id="gDeploy"> Deploy as its own Worker on workers.dev (host is filled automatically)</label>') +
      '<div class="muted" style="margin-top:12px">A custom domain must be routed to this same worker. Each gateway has its own path <span class="mono">/ws/&lt;id&gt;</span> so users can be pinned to it.</div></div>' +
      '<div class="modal-foot"><button class="btn" data-act="close">Cancel</button><button class="btn primary" data-act="gw-save">' + (edit ? 'Save' : 'Create') + '</button></div>'
    );
  }

  function saveGateway() {
    var id = val('gId'), name = val('gName').trim();
    if (!name) { toast('Gateway name is required'); return; }
    var dep = $('gDeploy') && $('gDeploy').checked;
    if (dep) toast('Deploying Worker, please wait...');
    api(id ? '/api/gateways/' + id : '/api/gateways', {
      method: id ? 'PUT' : 'POST',
      body: { name: name, region: val('gRegion').trim() || 'default', host: val('gHost').trim(), deploy: !!dep }
    }).then(function () { closeModal(); toast('Gateway saved'); loadGateways(); })
      .catch(function (e) { toast(e.message); });
  }

  function checkGateway(id) {
    var g = findBy(S.gateways, id); if (!g) return;
    var host = g.worker_url || location.host;
    var t0 = performance.now();
    toast('Checking ' + host + ' ...');
    fetch('https://' + host + '/health', { cache: 'no-store' })
      .then(function (r) { return r.json().then(function (j) { return { ok: r.ok && j && j.success === true, status: r.status }; }); })
      .then(function (res) {
        return { status: res.ok ? 'online' : 'offline', latency_ms: Math.round(performance.now() - t0), error: res.ok ? null : 'HTTP ' + res.status };
      })
      .catch(function (e) { return { status: 'offline', latency_ms: null, error: e && e.message ? e.message : 'unreachable' }; })
      .then(function (body) {
        return api('/api/gateways/' + id + '/health-result', { method: 'POST', body: body });
      })
      .then(function () { loadGateways(); })
      .catch(function (e) { toast(e.message); });
  }

  function loadLogs() {
    api('/api/logs').then(function (d) {
      var logs = d.logs || [];
      if (!logs.length) { $('logsTable').innerHTML = '<div class="empty">No log entries.</div>'; return; }
      var h = '<div class="table-wrap"><table><thead><tr><th>Time</th><th>Gateway</th><th>Event</th><th>Detail</th></tr></thead><tbody>';
      logs.forEach(function (l) {
        h += '<tr><td>' + esc(l.created_at) + '</td><td>' + esc(l.gateway_id) + '</td><td><span class="badge yellow">' + esc(l.event) + '</span></td><td class="mono" style="white-space:normal">' + esc(l.detail) + '</td></tr>';
      });
      $('logsTable').innerHTML = h + '</tbody></table></div>';
    }).catch(fail('logsTable'));
  }

  /* ---------- scanner ---------- */

  function pScanner() {
    $('view').innerHTML = hdr('Scanner', 'Find fast Cloudflare IPs (tested from your browser)',
      '<select id="scanCount" class="btn"><option value="50">50 IPs</option><option value="100" selected>100 IPs</option><option value="200">200 IPs</option></select>' +
      '<button id="scanBtn" class="btn primary" data-act="scan-run">Scan</button>' +
      '<button class="btn" data-act="scan-add">+ Add IP</button>' +
      '<button class="btn" data-act="scan-clear">Clear</button>') +
      '<div class="panel"><div class="panel-head"><div class="panel-title">Results</div><div class="muted" id="scanProgress"></div></div><div id="scanTable"><div class="empty">Loading...</div></div></div>' +
      '<div class="muted">Latency here is the TLS round-trip from your browser to each IP. The top IPs are added to new subscription links automatically. Always confirm with a real connection test in your client.</div>';
    loadScan();
  }

  function loadScan() {
    api('/api/scanner/results').then(function (d) {
      S.scan = d.results || [];
      if (!S.scan.length) { $('scanTable').innerHTML = '<div class="empty">No IPs yet. Run a scan or add one manually.</div>'; return; }
      var h = '<div class="table-wrap"><table><thead><tr><th>#</th><th>IP</th><th>Port</th><th>Status</th><th>Latency</th><th>Score</th><th>Actions</th></tr></thead><tbody>';
      S.scan.forEach(function (r, i) {
        h += '<tr><td>' + (i + 1) + '</td><td class="mono">' + esc(r.ip) + '</td><td>' + esc(r.port || 443) + '</td>' +
          '<td><span class="badge ' + (r.status === 'online' ? 'green' : 'yellow') + '">' + esc(String(r.status).toUpperCase()) + '</span></td>' +
          '<td>' + (r.latency_ms == null ? '-' : esc(r.latency_ms) + ' ms') + '</td><td><strong>' + esc(r.score || 0) + '</strong></td>' +
          '<td><div class="small-actions"><button class="icon-btn" data-act="copy" data-val="' + esc(r.ip) + '">Copy</button>' +
          '<button class="icon-btn danger" data-act="scan-del" data-id="' + r.id + '">Delete</button></div></td></tr>';
      });
      $('scanTable').innerHTML = h + '</tbody></table></div>';
    }).catch(fail('scanTable'));
  }

  function probe(ip) {
    function once() {
      return new Promise(function (resolve) {
        var t0 = performance.now();
        var ctl = new AbortController();
        var to = setTimeout(function () { ctl.abort(); }, 2500);
        function done() {
          clearTimeout(to);
          var dt = Math.round(performance.now() - t0);
          resolve(dt < 2400 ? dt : null);
        }
        fetch('https://' + ip + '/cdn-cgi/trace', { mode: 'no-cors', cache: 'no-store', signal: ctl.signal }).then(done, done);
      });
    }
    return once().then(function (a) {
      return once().then(function (b) {
        if (a == null) return b;
        if (b == null) return a;
        return Math.min(a, b);
      });
    });
  }

  function runScan() {
    if (S.scanning) return;
    S.scanning = true;
    var btn = $('scanBtn'); btn.disabled = true; btn.textContent = 'Scanning...';
    var count = Number(val('scanCount')) || 100;
    var prog = $('scanProgress');
    api('/api/scanner/candidates', { method: 'POST', body: { count: count } }).then(function (d) {
      var ips = d.candidates || [], idx = 0, done = 0, ok = [];
      function next() {
        if (idx >= ips.length) return Promise.resolve();
        var ip = ips[idx++];
        return probe(ip).then(function (ms) {
          done++;
          if (ms != null) ok.push({ ip: ip, port: 443, latency_ms: ms });
          prog.textContent = done + '/' + ips.length + ' tested, ' + ok.length + ' reachable';
          return next();
        });
      }
      var w = [];
      for (var i = 0; i < 8; i++) w.push(next());
      return Promise.all(w).then(function () {
        if (!ok.length) throw new Error('No reachable IPs found');
        return api('/api/scanner/save', { method: 'POST', body: { results: ok } });
      });
    }).then(function (r) { toast('Saved ' + r.saved + ' IPs'); })
      .catch(function (e) { toast(e.message || 'Scan failed'); })
      .then(function () {
        S.scanning = false;
        var b = $('scanBtn'); if (b) { b.disabled = false; b.textContent = 'Scan'; }
        if ($('scanTable')) loadScan();
      });
  }

  /* ---------- subscriptions ---------- */

  function pSubs() {
    $('view').innerHTML = hdr('Subscriptions', 'Public subscription URLs for your users', '') +
      '<div class="panel"><div class="panel-head"><div class="panel-title">Create Subscription</div></div><div class="pad">' +
      '<div class="row">' +
      '<div class="field" style="flex:1;min-width:160px"><label>Name</label><input id="sName" placeholder="e.g. EU Main"></div>' +
      '<div class="field" style="flex:1;min-width:200px"><label>User</label><select id="sAccount"><option value="">Loading...</option></select></div>' +
      '<div class="field" style="flex:1;min-width:200px"><label>Addresses</label><select id="sMode"><option value="auto">Auto (direct + top scanner IPs)</option><option value="direct">Direct only</option></select></div>' +
      '<button class="btn primary" style="height:42px" data-act="sub-create">Create</button></div>' +
      '<div id="sResult" style="margin-top:16px"></div></div></div>' +
      '<div class="panel"><div class="panel-head"><div class="panel-title">Subscription List</div></div><div id="subsTable"><div class="empty">Loading...</div></div></div>';
    Promise.all([api('/api/accounts'), api('/api/scanner/results')]).then(function (r) {
      var sel = $('sAccount'); if (!sel) return;
      sel.innerHTML = '<option value="">Select user...</option>';
      (r[0].accounts || []).forEach(function (a) {
        sel.innerHTML += '<option value="' + a.id + '">' + esc((a.display_name || a.username) + ' - ' + a.username) + '</option>';
      });
      var m = $('sMode');
      (r[1].results || []).forEach(function (x) {
        m.innerHTML += '<option value="' + esc(x.ip) + '">Only ' + esc(x.ip) + (x.latency_ms != null ? ' (' + esc(x.latency_ms) + ' ms)' : '') + '</option>';
      });
    }).catch(function (e) { toast(e.message); });
    loadSubs();
  }

  function subUrl(token) { return location.origin + '/sub/' + encodeURIComponent(token); }

  function loadSubs() {
    api('/api/subscriptions').then(function (d) {
      S.subs = d.subscriptions || [];
      if (!S.subs.length) { $('subsTable').innerHTML = '<div class="empty">No subscriptions configured.</div>'; return; }
      var h = '<div class="table-wrap"><table><thead><tr><th>Name</th><th>User</th><th>Mode</th><th>Status</th><th>Created</th><th>Actions</th></tr></thead><tbody>';
      S.subs.forEach(function (s) {
        var on = Number(s.enabled) === 1;
        var url = subUrl(s.token);
        h += '<tr><td><strong>' + esc(s.name || 'Unnamed') + '</strong></td>' +
          '<td>' + esc(s.display_name || s.username) + '<div class="muted">' + esc(s.username) + '</div></td>' +
          '<td>' + esc(s.scanner_ip || 'auto') + '</td>' +
          '<td><span class="badge ' + (on ? 'green' : 'red') + '">' + (on ? 'Enabled' : 'Disabled') + '</span></td>' +
          '<td>' + esc(s.created_at || '-') + '</td>' +
          '<td><div class="small-actions">' +
          '<button class="icon-btn" data-act="copy" data-val="' + esc(url) + '">Copy URL</button>' +
          '<button class="icon-btn" data-act="open" data-val="' + esc(url + '?raw=1') + '">View</button>' +
          '<button class="icon-btn" data-act="sub-toggle" data-id="' + s.id + '">' + (on ? 'Disable' : 'Enable') + '</button>' +
          '<button class="icon-btn danger" data-act="sub-delete" data-id="' + s.id + '">Delete</button>' +
          '</div></td></tr>';
      });
      $('subsTable').innerHTML = h + '</tbody></table></div>';
    }).catch(fail('subsTable'));
  }

  function createSub() {
    var name = val('sName').trim(), acc = val('sAccount');
    if (!name) { toast('Enter subscription name'); return; }
    if (!acc) { toast('Select a user'); return; }
    api('/api/subscriptions', { method: 'POST', body: { name: name, account_id: Number(acc), mode: val('sMode') } })
      .then(function (d) {
        var url = d.subscription.url;
        $('sResult').innerHTML = '<div class="card"><div class="card-label">Subscription URL</div>' +
          '<div class="row" style="margin-top:8px"><input readonly style="flex:1;min-width:0;background:#080e18;border:1px solid #273349;color:#fff;padding:10px;border-radius:9px" value="' + esc(url) + '">' +
          '<button class="btn" data-act="copy" data-val="' + esc(url) + '">Copy</button></div></div>';
        $('sName').value = '';
        loadSubs();
      }).catch(function (e) { toast(e.message); });
  }

  /* ---------- settings ---------- */

  function pSettings() {
    $('view').innerHTML = hdr('Settings', 'Nexus configuration', '') +
      '<div class="panel"><div class="panel-head"><div class="panel-title">Infrastructure</div></div><div class="pad">' +
      '<div class="card"><div class="card-label">Architecture</div><div style="margin-top:10px;line-height:1.8;color:#aab5c8">Nexus Worker (panel + API + subscriptions + VLESS/WebSocket) &rarr; D1</div></div>' +
      '<div class="card" style="margin-top:14px"><div class="card-label">Fallback proxy (optional)</div>' +
      '<div class="muted" style="margin-top:6px">Used only when a direct outbound connection fails (for example targets behind Cloudflare). Format: host or host:port, comma separated.</div>' +
      '<div class="row" style="margin-top:10px;max-width:560px"><div class="field" style="flex:1"><input id="proxyIp" placeholder="proxy.example.com"></div>' +
      '<button class="btn primary" data-act="proxy-save">Save</button></div><div id="proxyEnv" class="muted" style="margin-top:8px"></div></div>' +
      '<div class="card" style="margin-top:14px"><div class="card-label">Admin password</div>' +
      '<form data-form="password" style="margin-top:12px;display:grid;gap:10px;max-width:500px">' +
      '<div class="field"><label>Current password</label><input id="curPw" type="password" autocomplete="current-password"></div>' +
      '<div class="field"><label>New password (min 8 chars)</label><input id="newPw" type="password" autocomplete="new-password"></div>' +
      '<div class="field"><label>Confirm new password</label><input id="newPw2" type="password" autocomplete="new-password"></div>' +
      '<button id="pwBtn" class="btn primary" type="submit">Change Password</button></form></div>' +
      '<div class="card" style="margin-top:14px"><div class="card-label">Telegram Bot</div>' +
      '<div id="tgStatus" style="margin-top:8px"></div>' +
      '<div class="muted" style="margin-top:6px">Create a bot with @BotFather and paste its token. Admin IDs are numeric Telegram IDs (comma separated). If you do not know yours, activate the bot, send it /start and it will show your ID.</div>' +
      '<div style="margin-top:12px;display:grid;gap:10px;max-width:560px">' +
      '<div class="field"><label>Bot token</label><input id="tgToken" type="password" autocomplete="off" placeholder="123456:ABC..."></div>' +
      '<div class="field"><label>Admin IDs</label><input id="tgAdmins" placeholder="123456789, 987654321"></div>' +
      '<div class="muted">Webhook: <span id="tgHook" class="mono"></span></div>' +
      '<div class="actions"><button class="btn primary" data-act="tg-on">Save &amp; Activate</button>' +
      '<button class="btn" data-act="tg-save">Save only</button>' +
      '<button class="btn" data-act="tg-off">Deactivate</button></div></div></div>' +
      '<div class="card" style="margin-top:14px"><div class="card-label">Worker gateways (Cloudflare API)</div>' +
      '<div id="cfdStatus" style="margin-top:8px"></div>' +
      '<div class="muted" style="margin-top:6px">Lets the panel deploy every new gateway as its own Worker on workers.dev. Token permissions: Account Settings Read, Workers Scripts Edit, D1 Read. Account and database are detected automatically when left empty.</div>' +
      '<div style="margin-top:12px;display:grid;gap:10px;max-width:560px">' +
      '<div class="field"><label>API token</label><input id="cfdToken" type="password" autocomplete="off" placeholder="Cloudflare API token"></div>' +
      '<div class="field"><label>Account ID (optional)</label><input id="cfdAccount"></div>' +
      '<div class="field"><label>D1 database ID (optional)</label><input id="cfdDb"></div>' +
      '<div class="field"><label>Panel code URL (raw _worker.js)</label><input id="cfdSource"></div>' +
      '<div class="actions"><button class="btn primary" data-act="cfd-save">Save</button>' +
      '<button class="btn" data-act="cfd-clear">Remove token</button></div></div></div>' +
      '</div></div>';
    api('/api/settings').then(function (d) {
      $('proxyIp').value = d.settings.proxy_ip || '';
      if (d.env_proxy_ip) $('proxyEnv').textContent = 'PROXYIP env var is set and takes priority: ' + d.env_proxy_ip;
    }).catch(function () {});
    loadTg();
    loadCfd();
  }

  function changePw() {
    var a = val('curPw'), b = val('newPw'), c = val('newPw2');
    if (b !== c) { toast('New passwords do not match'); return; }
    if (b.length < 8) { toast('New password must be at least 8 characters'); return; }
    var btn = $('pwBtn'); btn.disabled = true;
    api('/api/auth/change-password', { method: 'POST', body: { current_password: a, new_password: b } })
      .then(function () { toast('Password changed'); $('curPw').value = ''; $('newPw').value = ''; $('newPw2').value = ''; })
      .catch(function (e) { toast(e.message); })
      .then(function () { btn.disabled = false; });
  }

  function loadTg() {
    api('/api/telegram').then(function (d) {
      var t = d.telegram;
      $('tgAdmins').value = t.admins || '';
      $('tgToken').placeholder = t.token_set ? ('Saved: ' + t.token_masked + ' (leave empty to keep)') : '123456:ABC...';
      $('tgHook').textContent = t.webhook_url;
      $('tgStatus').innerHTML = t.active
        ? '<span class="badge green">&#9679; Active</span> ' + (t.username ? '@' + esc(t.username) : '')
        : '<span class="badge yellow">Not active</span>';
    }).catch(function () {});
  }

  function tgSave(thenActivate) {
    api('/api/telegram', { method: 'POST', body: { token: val('tgToken').trim(), admins: val('tgAdmins').trim() } })
      .then(function () {
        $('tgToken').value = '';
        if (!thenActivate) { toast('Saved'); loadTg(); return; }
        return api('/api/telegram/activate', { method: 'POST' }).then(function () {
          toast('Bot activated'); loadTg();
        });
      })
      .catch(function (e) { toast(e.message); });
  }

  function loadCfd() {
    api('/api/cfdeploy').then(function (d) {
      var c = d.cfd;
      $('cfdAccount').value = c.account_id || '';
      $('cfdDb').value = c.db_id || '';
      $('cfdSource').value = c.source || '';
      $('cfdToken').placeholder = c.token_set ? (c.from_env ? 'Set via environment variable' : 'Saved (leave empty to keep)') : 'Cloudflare API token';
      $('cfdStatus').innerHTML = (c.token_set && c.account_id && c.db_id)
        ? '<span class="badge green">&#9679; Ready</span>'
        : '<span class="badge yellow">Not configured</span>';
    }).catch(function () {});
  }

  function cfdSave() {
    api('/api/cfdeploy', { method: 'POST', body: {
      token: val('cfdToken').trim(), account_id: val('cfdAccount').trim(),
      db_id: val('cfdDb').trim(), source: val('cfdSource').trim()
    } }).then(function () { $('cfdToken').value = ''; toast('Saved'); loadCfd(); })
      .catch(function (e) { toast(e.message); });
  }

  /* ---------- events ---------- */

  function confirmDo(msg, fn) { if (confirm(msg)) fn(); }
  function simple(method, path, okMsg, after) {
    api(path, { method: method }).then(function () { if (okMsg) toast(okMsg); after(); })
      .catch(function (e) { toast(e.message); });
  }

  var ACTIONS = {
    nav: function (id) { go(id); },
    close: function () { closeModal(); },
    logout: function () { api('/api/auth/logout', { method: 'POST' }).then(showLogin, showLogin); },
    copy: function (id, el) { copyText(el.getAttribute('data-val')); },
    open: function (id, el) { window.open(el.getAttribute('data-val'), '_blank'); },

    'user-new': function () { userModal(null); },
    'user-edit': function (id) { var u = findBy(S.users, id); if (u) userModal(u); },
    'user-save': saveUser,
    'uuid-gen': function () { $('fUuid').value = crypto.randomUUID(); },
    'user-config': showConfig,
    'user-toggle': function (id) { simple('PATCH', '/api/accounts/' + id, '', pUsers); },
    'user-reset': function (id) { confirmDo('Reset traffic for this user?', function () { simple('POST', '/api/accounts/' + id + '/reset', 'Traffic reset', pUsers); }); },
    'user-delete': function (id) { confirmDo('Delete this user and their subscriptions?', function () { simple('DELETE', '/api/accounts/' + id, 'User deleted', pUsers); }); },

    'gw-new': function () { gwModal(null); },
    'gw-edit': function (id) { var g = findBy(S.gateways, id); if (g) gwModal(g); },
    'gw-save': saveGateway,
    'gw-check': checkGateway,
    'gw-toggle': function (id) { simple('PATCH', '/api/gateways/' + id, '', loadGateways); },
    'gw-delete': function (id) { confirmDo('Delete this gateway? Users on it will be unassigned. A deployed Worker will be removed too.', function () { simple('DELETE', '/api/gateways/' + id, 'Gateway removed', loadGateways); }); },
    'gw-redeploy': function (id) {
      toast('Redeploying...');
      api('/api/gateways/' + id + '/redeploy', { method: 'POST' })
        .then(function () { toast('Worker updated'); })
        .catch(function (e) { toast(e.message); });
    },
    'logs-refresh': loadLogs,
    'logs-clear': function () { simple('DELETE', '/api/logs', 'Logs cleared', loadLogs); },

    'scan-run': runScan,
    'scan-add': function () {
      openModal('<div class="modal-head"><strong>Add IP manually</strong><button class="icon-btn" data-act="close">&times;</button></div>' +
        '<div class="modal-body"><div class="field"><label>IPv4 address</label><input id="mIp" placeholder="104.16.1.1"></div></div>' +
        '<div class="modal-foot"><button class="btn" data-act="close">Cancel</button><button class="btn primary" data-act="scan-add-save">Add</button></div>');
    },
    'scan-add-save': function () {
      api('/api/scanner/add', { method: 'POST', body: { ip: val('mIp').trim() } })
        .then(function () { closeModal(); toast('IP added'); loadScan(); })
        .catch(function (e) { toast(e.message); });
    },
    'scan-del': function (id) { simple('DELETE', '/api/scanner/' + id, '', loadScan); },
    'scan-clear': function () { confirmDo('Remove all scanner IPs?', function () { simple('DELETE', '/api/scanner', 'Cleared', loadScan); }); },

    'sub-create': createSub,
    'sub-toggle': function (id) { simple('PATCH', '/api/subscriptions/' + id, '', loadSubs); },
    'sub-delete': function (id) { confirmDo('Delete this subscription?', function () { simple('DELETE', '/api/subscriptions/' + id, 'Subscription deleted', loadSubs); }); },

    'proxy-save': function () {
      api('/api/settings', { method: 'POST', body: { proxy_ip: val('proxyIp').trim() } })
        .then(function () { toast('Saved'); }).catch(function (e) { toast(e.message); });
    },

    'tg-save': function () { tgSave(false); },
    'tg-on': function () { tgSave(true); },
    'tg-off': function () {
      api('/api/telegram/deactivate', { method: 'POST' })
        .then(function () { toast('Bot deactivated'); loadTg(); })
        .catch(function (e) { toast(e.message); });
    },

    'cfd-save': cfdSave,
    'cfd-clear': function () {
      api('/api/cfdeploy', { method: 'POST', body: { clear: true } })
        .then(function () { toast('Removed'); loadCfd(); })
        .catch(function (e) { toast(e.message); });
    }
  };

  document.addEventListener('click', function (e) {
    if (e.target && e.target.id === 'modalOverlay') { closeModal(); return; }
    var el = e.target.closest ? e.target.closest('[data-act]') : null;
    if (!el) return;
    var fn = ACTIONS[el.getAttribute('data-act')];
    if (fn) fn(el.getAttribute('data-id'), el);
  });

  document.addEventListener('submit', function (e) {
    var f = e.target.getAttribute && e.target.getAttribute('data-form');
    if (!f) return;
    e.preventDefault();
    if (f === 'login') doLogin();
    else if (f === 'password') changePw();
  });

  api('/api/auth/me').then(function (me) { S.me = me; showShell(); }).catch(function () { showLogin(); });
})();
</script>
</body>
</html>`;
}
