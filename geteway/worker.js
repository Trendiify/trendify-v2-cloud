
import { connect } from "cloudflare:sockets";

function json(data, status) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}

function uuidFromBytes(bytes) {
  const hex = Array.from(bytes, function (b) {
    return b.toString(16).padStart(2, "0");
  }).join("");

  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20, 32)
  ].join("-");
}

function parseVless(buffer) {
  if (buffer.length < 18) return null;
  
  const version = buffer[0];
  if (version !== 0) throw new Error("Unsupported VLESS version");

  const uuid = uuidFromBytes(buffer.subarray(1, 17));
  const optionsLength = buffer[17];
  const commandIndex = 18 + optionsLength;

  if (buffer.length < commandIndex + 4) return null;

  const command = buffer[commandIndex];
  if (command !== 1) throw new Error("Only TCP is supported");

  const port = buffer.readUInt16BE
    ? buffer.readUInt16BE(commandIndex + 1)
    : (buffer[commandIndex + 1] * 256 +
       buffer[commandIndex + 2]);

  const addressType = buffer[commandIndex + 3];
  let offset = commandIndex + 4;
  let host = "";

  if (addressType === 1) {
    if (buffer.length < offset + 4) return null;
    host = Array.from(buffer.subarray(offset, offset + 4)).join(".");
    offset += 4;
  } else if (addressType === 2) {
    if (buffer.length < offset + 1) return null;
    const length = buffer[offset++];
    if (length < 1) throw new Error("Invalid domain");
    if (buffer.length < offset + length) return null;
    host = new TextDecoder().decode(
      buffer.subarray(offset, offset + length)
    );
    offset += length;
  } else if (addressType === 3) {
    if (buffer.length < offset + 16) return null;
    const parts = [];
    for (let i = 0; i < 16; i += 2) {
      parts.push(
        ((buffer[offset + i] << 8) | buffer[offset + i + 1])
          .toString(16)
      );
    }
    host = parts.join(":");
    offset += 16;
  } else {
    throw new Error("Unsupported address type");
  }

  if (!host || !port) throw new Error("Invalid destination");

  return {
    version: version,
    uuid: uuid,
    host: host,
    port: port,
    offset: offset
  };
}

async function authorize(uuid, env) {
  const base = String(env.NEXUS_API_URL || "")
    .trim()
    .replace(/\/+$/, "");

  if (!base || !env.NEXUS_GATEWAY_SECRET) {
    throw new Error("Gateway authorization is not configured");
  }

  const url = new URL(base + "/api/internal/gateway/auth");
  url.searchParams.set("uuid", uuid);
  url.searchParams.set("gateway_id", String(env.GATEWAY_ID || ""));

  const response = await fetch(url.toString(), {
    method: "GET",
    headers: {
      "X-Nexus-Gateway-Secret": env.NEXUS_GATEWAY_SECRET,
      "Accept": "application/json"
    }
  });

  if (!response.ok) {
    throw new Error("Gateway authorization API returned " + response.status);
  }

  const data = await response.json();
  if (!data || data.authorized !== true) {
    throw new Error("UUID is not authorized");
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

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

    if (path === "/" || path === "/health") {
      return json({
        success: true,
        status: "online",
        gateway: "Trendify Nexus Gateway",
        gateway_id: env.GATEWAY_ID || "",
        region: env.GATEWAY_REGION || ""
      });
    }

    if (
      path !== "/ws" &&
      !path.startsWith("/ws/") &&
      path !== "/vless"
    ) {
      return new Response("Not Found", { status: 404 });
    }

    if (
      !request.headers.get("Upgrade") ||
      request.headers.get("Upgrade").toLowerCase() !== "websocket"
    ) {
      return new Response("Expected WebSocket", {
        status: 426,
        headers: { Upgrade: "websocket" }
      });
    }

    const railwayHost = String(
      env.RAILWAY_TCP_PROXY_DOMAIN || ""
    ).trim();
    const railwayPort = Number(env.RAILWAY_TCP_PROXY_PORT || 0);
    const relaySecret = String(env.NEXUS_GATEWAY_SECRET || "");

    if (!railwayHost || !railwayPort || !relaySecret) {
      return new Response("Gateway relay configuration is incomplete", {
        status: 500
      });
    }

    const pair = new WebSocketPair();
    const client = pair[0];
    const ws = pair[1];

    ws.accept();
    ws.binaryType = "arraybuffer";

    let pending = new Uint8Array(0);
    let socket = null;
    let writer = null;
    let reader = null;
    let connected = false;
    let closed = false;
    let chain = Promise.resolve();

    function closeAll() {
      if (closed) return;
      closed = true;

      try {
        if (ws.readyState === WebSocket.OPEN) ws.close();
      } catch (_) {}

      try {
        if (reader) reader.cancel();
      } catch (_) {}

      try {
        if (writer) writer.close();
      } catch (_) {}

      try {
        if (socket) socket.close();
      } catch (_) {}
    }

    async function handleMessage(data) {
      if (closed) return;

      let incoming;
      if (data instanceof ArrayBuffer) {
        incoming = new Uint8Array(data);
      } else if (ArrayBuffer.isView(data)) {
        incoming = new Uint8Array(
          data.buffer,
          data.byteOffset,
          data.byteLength
        );
      } else if (data instanceof Blob) {
        incoming = new Uint8Array(await data.arrayBuffer());
      } else {
        throw new Error("Binary WebSocket messages are required");
      }

      if (connected) {
        await writer.write(incoming);
        return;
      }

      const combined = new Uint8Array(pending.length + incoming.length);
      combined.set(pending, 0);
      combined.set(incoming, pending.length);
      pending = combined;

      const parsed = parseVless(pending);
      if (!parsed) {
        if (pending.length > 8192) {
          throw new Error("VLESS header is too large");
        }
        return;
      }

      await authorize(parsed.uuid, env);

      const secretBytes = new TextEncoder().encode(relaySecret);
      const hostBytes = new TextEncoder().encode(parsed.host);

      if (secretBytes.length < 16 || secretBytes.length > 256) {
        throw new Error("Relay secret length must be 16-256 bytes");
      }
      if (hostBytes.length < 1 || hostBytes.length > 255) {
        throw new Error("Destination hostname is too long");
      }

      const payload = pending.subarray(parsed.offset);
      const frame = new Uint8Array(
        2 + secretBytes.length +
        2 + hostBytes.length +
        2 + payload.length
      );

      let p = 0;
      frame[p++] = (secretBytes.length >> 8) & 255;
      frame[p++] = secretBytes.length & 255;
      frame.set(secretBytes, p);
      p += secretBytes.length;

      frame[p++] = (hostBytes.length >> 8) & 255;
      frame[p++] = hostBytes.length & 255;
      frame.set(hostBytes, p);
      p += hostBytes.length;

      frame[p++] = (parsed.port >> 8) & 255;
      frame[p++] = parsed.port & 255;
      frame.set(payload, p);

      socket = connect({
        hostname: railwayHost,
        port: railwayPort
      });

      await socket.opened;
      writer = socket.writable.getWriter();
      reader = socket.readable.getReader();

      await writer.write(frame);
      connected = true;
      pending = new Uint8Array(0);

      // VLESS response: version, zero-length response options.
      ws.send(new Uint8Array([parsed.version, 0]));

      (async function relayToClient() {
        try {
          while (!closed) {
            const result = await reader.read();
            if (result.done) break;
            if (result.value && ws.readyState === WebSocket.OPEN) {
              ws.send(result.value);
            }
          }
        } catch (_) {
          closeAll();
        }
      })();
    }

    ws.addEventListener("message", function (event) {
      chain = chain
        .then(function () {
          return handleMessage(event.data);
        })
        .catch(function () {
          closeAll();
        });
    });

    ws.addEventListener("close", closeAll);
    ws.addEventListener("error", closeAll);

    return new Response(null, {
      status: 101,
      webSocket: client
    });
  }
};
