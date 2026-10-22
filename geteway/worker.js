
import { connect } from "cloudflare:sockets";

const APP_NAME = "Trendify Nexus Gateway";
const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=UTF-8",
      "Cache-Control": "no-store"
    }
  });
}

function text(body, status = 200) {
  return new Response(body, {
    status,
    headers: {
      "Content-Type": "text/plain; charset=UTF-8",
      "Cache-Control": "no-store"
    }
  });
}

function uuidFromBytes(bytes) {
  const h = Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  return [
    h.slice(0, 8),
    h.slice(8, 12),
    h.slice(12, 16),
    h.slice(16, 20),
    h.slice(20)
  ].join("-");
}

function parseVLESS(data) {
  if (data.length < 24) {
    throw new Error("Invalid VLESS header");
  }

  const version = data[0];
  const uuid = uuidFromBytes(data.slice(1, 17));
  let offset = 18 + data[17];

  if (data.length < offset + 4) {
    throw new Error("Incomplete VLESS header");
  }

  const command = data[offset++];

  if (command !== 1 && command !== 2) {
    throw new Error("Unsupported VLESS command");
  }

  const port = (data[offset] << 8) | data[offset + 1];
  offset += 2;

  const addressType = data[offset++];
  let address;

  if (addressType === 1) {
    if (data.length < offset + 4) {
      throw new Error("Invalid IPv4 address");
    }

    address = Array.from(data.slice(offset, offset + 4)).join(".");
    offset += 4;
  } else if (addressType === 2) {
    const length = data[offset++];

    if (data.length < offset + length) {
      throw new Error("Invalid domain length");
    }

    address = new TextDecoder().decode(
      data.slice(offset, offset + length)
    );

    offset += length;
  } else if (addressType === 3) {
    if (data.length < offset + 16) {
      throw new Error("Invalid IPv6 address");
    }

    const parts = [];

    for (let i = 0; i < 16; i += 2) {
      parts.push(
        ((data[offset + i] << 8) | data[offset + i + 1]).toString(16)
      );
    }

    address = parts.join(":");
    offset += 16;
  } else {
    throw new Error("Unsupported address type");
  }

  if (!address || !Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("Invalid target");
  }

  return {
    version,
    uuid,
    command,
    address,
    port,
    data: data.slice(offset)
  };
}

function withTimeout(promise, milliseconds) {
  let timer;

  return Promise.race([
    promise,
    new Promise((_, reject) => {
      timer = setTimeout(
        () => reject(new Error("Connection timeout")),
        milliseconds
      );
    })
  ]).finally(() => clearTimeout(timer));
}

async function connectTCP(host, port) {
  const socket = connect({
    hostname: host,
    port
  });

  try {
    await withTimeout(socket.opened, 10000);
    return socket;
  } catch (error) {
    try {
      socket.close();
    } catch {}

    throw error;
  }
}

function parseProxy(value, defaultPort) {
  const input = String(value || "").trim();
  const index = input.lastIndexOf(":");

  if (
    index > 0 &&
    input.indexOf(":") === index &&
    /^\d+$/.test(input.slice(index + 1))
  ) {
    return {
      host: input.slice(0, index),
      port: Number(input.slice(index + 1))
    };
  }

  return {
    host: input,
    port: defaultPort
  };
}

async function authorizeUser(env, uuid, requestedGatewayId) {
  if (!env.DB) {
    throw new Error('Missing D1 binding "DB"');
  }

  const user = await env.DB.prepare(
    `SELECT id, uuid, enabled, gateway_id,
            data_limit, data_used, expires_at
     FROM accounts
     WHERE uuid = ?
     LIMIT 1`
  )
    .bind(uuid)
    .first();

  if (!user || !UUID_RE.test(String(user.uuid || ""))) {
    throw new Error("Invalid UUID");
  }

  if (Number(user.enabled) !== 1) {
    throw new Error("Account disabled");
  }

  if (
    requestedGatewayId &&
    user.gateway_id &&
    Number(user.gateway_id) !== requestedGatewayId
  ) {
    throw new Error("Wrong gateway for account");
  }

  const gatewayId =
    requestedGatewayId || Number(user.gateway_id || 0);

  if (gatewayId) {
    const gateway = await env.DB.prepare(
      "SELECT id, enabled FROM gateways WHERE id = ? LIMIT 1"
    )
      .bind(gatewayId)
      .first();

    if (!gateway || Number(gateway.enabled) !== 1) {
      throw new Error("Gateway disabled or missing");
    }
  }

  if (user.expires_at) {
    const expiry = Date.parse(String(user.expires_at));

    if (Number.isFinite(expiry) && Date.now() >= expiry) {
      throw new Error("Account expired");
    }
  }

  const limit = Number(user.data_limit || 0);
  const used = Number(user.data_used || 0);

  if (limit > 0 && used >= limit) {
    throw new Error("Traffic limit reached");
  }

  return {
    id: Number(user.id),
    gatewayId
  };
}

async function addTraffic(env, userId, bytes) {
  if (!userId || !bytes) return;

  try {
    await env.DB.prepare(
      `UPDATE accounts
       SET data_used = data_used + ?, updated_at = unixepoch()
       WHERE id = ?`
    )
      .bind(bytes, userId)
      .run();
  } catch (error) {
    console.error("Traffic accounting error:", error.message);
  }
}

async function connectTarget(env, host, port) {
  try {
    return await connectTCP(host, port);
  } catch (directError) {
    const configured = String(env.PROXYIP || "")
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean);

    for (const value of configured) {
      const proxy = parseProxy(value, port);

      if (!proxy.host || proxy.port < 1 || proxy.port > 65535) {
        continue;
      }

      try {
        return await connectTCP(proxy.host, proxy.port);
      } catch (error) {
        console.error("Fallback connection failed:", error.message);
      }
    }

    throw directError;
  }
}

function handleVLESS(request, env, gatewayId) {
  const pair = new WebSocketPair();
  const client = pair[0];
  const server = pair[1];

  server.accept();

  let socket = null;
  let writer = null;
  let closed = false;
  let started = false;
  let responseHeaderSent = false;
  let version = 0;
  let userId = 0;
  let receivedBytes = 0;
  let udpBuffer = new Uint8Array(0);
  let chain = Promise.resolve();

  function closeConnection() {
    if (closed) return;
    closed = true;

    try {
      if (writer) writer.releaseLock();
    } catch {}

    try {
      if (socket) socket.close();
    } catch {}

    try {
      if (server.readyState === 1 || server.readyState === 2) {
        server.close(1000, "closed");
      }
    } catch {}

    if (userId && receivedBytes) {
      const amount = receivedBytes;
      receivedBytes = 0;

      try {
        request.cf;
      } catch {}

      // Traffic updates are best-effort.
      env.DB.prepare(
        `UPDATE accounts
         SET data_used = data_used + ?, updated_at = unixepoch()
         WHERE id = ?`
      )
        .bind(amount, userId)
        .run()
        .catch((error) => {
          console.error("Traffic update failed:", error.message);
        });
    }
  }

  function sendToClient(bytes) {
    if (closed || server.readyState !== 1) return;

    try {
      if (!responseHeaderSent) {
        responseHeaderSent = true;

        const output = new Uint8Array(2 + bytes.length);
        output[0] = version;
        output[1] = 0;
        output.set(bytes, 2);

        server.send(output);
      } else {
        server.send(bytes);
      }
    } catch {
      closeConnection();
    }
  }

  async function handleDNS(data) {
    const merged = new Uint8Array(udpBuffer.length + data.length);
    merged.set(udpBuffer);
    merged.set(data, udpBuffer.length);

    let offset = 0;

    while (merged.length - offset >= 2) {
      const length = (merged[offset] << 8) | merged[offset + 1];

      if (merged.length - offset - 2 < length) break;

      const query = merged.slice(offset + 2, offset + 2 + length);
      offset += 2 + length;

      const response = await fetch("https://1.1.1.1/dns-query", {
        method: "POST",
        headers: {
          "Content-Type": "application/dns-message",
          Accept: "application/dns-message"
        },
        body: query
      });

      if (!response.ok) {
        throw new Error("DNS request failed");
      }

      const answer = new Uint8Array(await response.arrayBuffer());
      const output = new Uint8Array(2 + answer.length);

      output[0] = (answer.length >> 8) & 255;
      output[1] = answer.length & 255;
      output.set(answer, 2);

      receivedBytes += query.length + answer.length;
      sendToClient(output);
    }

    udpBuffer = merged.slice(offset);
  }

  async function startTunnel(raw) {
    const packet = raw instanceof ArrayBuffer
      ? new Uint8Array(raw)
      : ArrayBuffer.isView(raw)
        ? new Uint8Array(raw.buffer, raw.byteOffset, raw.byteLength)
        : raw instanceof Blob
          ? new Uint8Array(await raw.arrayBuffer())
          : null;

    if (!packet) {
      throw new Error("Unsupported WebSocket frame");
    }

    if (!started) {
      started = true;

      const parsed = parseVLESS(packet);
      const account = await authorizeUser(
        env,
        parsed.uuid,
        gatewayId
      );

      userId = account.id;
      version = parsed.version;

      if (parsed.command === 2) {
        if (parsed.port !== 53) {
          throw new Error("UDP is only supported for DNS port 53");
        }

        sendToClient(new Uint8Array(0));

        if (parsed.data.length) {
          await handleDNS(parsed.data);
        }

        return;
      }

      socket = await connectTarget(
        env,
        parsed.address,
        parsed.port
      );

      writer = socket.writable.getWriter();

      if (parsed.data.length) {
        await writer.write(parsed.data);
        receivedBytes += parsed.data.length;
      }

      socket.readable
        .pipeTo(
          new WritableStream({
            write(chunk) {
              if (closed) return;

              receivedBytes += chunk.byteLength;
              sendToClient(new Uint8Array(chunk));
            }
          })
        )
        .catch((error) => {
          console.error("Remote stream error:", error.message);
        })
        .finally(closeConnection);

      return;
    }

    if (writer) {
      receivedBytes += packet.length;
      await writer.write(packet);
    }
  }

  server.addEventListener("message", (event) => {
    chain = chain
      .then(() => startTunnel(event.data))
      .catch((error) => {
        console.error("Gateway session error:", error.message);
        closeConnection();
      });
  });

  server.addEventListener("close", closeConnection);
  server.addEventListener("error", closeConnection);

  return new Response(null, {
    status: 101,
    webSocket: client
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type"
        }
      });
    }

    if (path === "/" || path === "/health" || path === "/api/health") {
      return json({
        success: true,
        app: APP_NAME,
        status: "online",
        timestamp: new Date().toISOString()
      });
    }

    const match = path.match(/^\/(?:ws|vless)(?:\/(\d+))?$/);

    if (match) {
      if ((request.headers.get("Upgrade") || "").toLowerCase() !== "websocket") {
        return text("WebSocket Upgrade Required", 426);
      }

      if (!env.DB) {
        return json({
          success: false,
          error: 'Missing D1 binding "DB"'
        }, 500);
      }

      const gatewayId = Number(match[1] || env.GATEWAY_ID || 0);

      return handleVLESS(request, env, gatewayId);
    }

    return json({
      success: false,
      error: "Not Found"
    }, 404);
  }
};
