const { timingSafeEqual } = require("node:crypto");
const http = require("node:http");

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || "127.0.0.1";
const API_KEY = process.env.API_KEY || "";
const MAX_BODY_BYTES = 4096;
const UPSTREAM_TIMEOUT_MS = 10000;

function isLoopback(host) {
  return host === "localhost" || host === "::1" || host.startsWith("127.");
}

if (!Number.isInteger(PORT) || PORT < 1 || PORT > 65535) {
  throw new Error("PORT must be an integer between 1 and 65535");
}

if (!isLoopback(HOST) && !API_KEY) {
  throw new Error("Set API_KEY before exposing the API beyond localhost");
}

function sendJson(res, statusCode, data) {
  const body = JSON.stringify(data);
  res.writeHead(statusCode, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(body),
    "cache-control": "no-store",
  });
  res.end(body);
}

function isAuthorized(req) {
  if (!API_KEY) return true;

  const authorization = req.headers.authorization || "";
  const match = /^Bearer (.+)$/i.exec(authorization);
  if (!match) return false;

  const provided = Buffer.from(match[1]);
  const expected = Buffer.from(API_KEY);
  return provided.length === expected.length && timingSafeEqual(provided, expected);
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    let tooLarge = false;
    const chunks = [];

    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        tooLarge = true;
      } else {
        chunks.push(chunk);
      }
    });

    req.on("end", () => {
      if (tooLarge) {
        reject(Object.assign(new Error("Request body is too large"), { statusCode: 413 }));
        return;
      }

      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
      } catch {
        reject(Object.assign(new Error("Request body must be valid JSON"), { statusCode: 400 }));
      }
    });

    req.on("error", reject);
  });
}

function validateCredentials(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return "JSON body must be an object";
  }

  if (typeof body.ssid !== "string" || body.ssid.length === 0) {
    return "ssid must be a non-empty string";
  }
  if (Buffer.byteLength(body.ssid, "utf8") > 32) {
    return "ssid must be at most 32 bytes";
  }
  if (typeof body.password !== "string") {
    return "password must be a string (use an empty string for an open network)";
  }

  const validPassword =
    body.password.length === 0 ||
    (body.password.length >= 8 && body.password.length <= 63) ||
    /^[0-9a-fA-F]{64}$/.test(body.password);
  if (!validPassword) {
    return "password must be empty, 8-63 characters, or a 64-character hexadecimal PSK";
  }

  return null;
}

function getEsp32Url(path) {
  const baseUrl = process.env.ESP32_URL;
  if (!baseUrl) return null;

  let url;
  try {
    url = new URL(baseUrl);
  } catch {
    throw new Error("ESP32_URL must be a valid URL");
  }

  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) {
    throw new Error("ESP32_URL must use HTTP or HTTPS and must not contain credentials");
  }

  return new URL(path, url.origin);
}

async function forwardToEsp32(path, options = {}) {
  let url;
  try {
    url = getEsp32Url(path);
  } catch (error) {
    return { statusCode: 500, body: { error: error.message } };
  }
  if (!url) {
    return { statusCode: 503, body: { error: "ESP32_URL is not configured" } };
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);

  try {
    const response = await fetch(url, {
      method: options.method || "GET",
      headers: options.body ? { "content-type": "application/json" } : undefined,
      body: options.body ? JSON.stringify(options.body) : undefined,
      signal: controller.signal,
    });
    const text = await response.text();

    let body;
    try {
      body = JSON.parse(text);
    } catch {
      return {
        statusCode: 502,
        body: { error: "ESP32 returned a non-JSON response" },
      };
    }

    return { statusCode: response.status, body };
  } catch (error) {
    const message =
      error.name === "AbortError"
        ? "Timed out while contacting ESP32"
        : "Could not contact ESP32";
    return { statusCode: 502, body: { error: message } };
  } finally {
    clearTimeout(timeout);
  }
}

const server = http.createServer(async (req, res) => {
  if (!isAuthorized(req)) {
    sendJson(res, 401, { error: "Unauthorized" });
    return;
  }

  const pathname = new URL(req.url, "http://localhost").pathname;

  if (req.method === "GET" && pathname === "/api/health") {
    sendJson(res, 200, { ok: true, esp32Configured: Boolean(process.env.ESP32_URL) });
    return;
  }

  if (req.method === "GET" && pathname === "/api/wifi/status") {
    const result = await forwardToEsp32("/api/wifi/status");
    sendJson(res, result.statusCode, result.body);
    return;
  }

  if (req.method === "POST" && pathname === "/api/wifi/connect") {
    if (!/^application\/json(?:\s*;|$)/i.test(req.headers["content-type"] || "")) {
      sendJson(res, 415, { error: "Content-Type must be application/json" });
      return;
    }

    try {
      const body = await readJsonBody(req);
      const validationError = validateCredentials(body);
      if (validationError) {
        sendJson(res, 400, { error: validationError });
        return;
      }

      const result = await forwardToEsp32("/api/wifi/connect", {
        method: "POST",
        body: { ssid: body.ssid, password: body.password },
      });
      sendJson(res, result.statusCode, result.body);
    } catch (error) {
      sendJson(res, error.statusCode || 400, { error: error.message });
    }
    return;
  }

  sendJson(res, 404, { error: "Not found" });
});

server.listen(PORT, HOST, () => {
  console.log(`Wi-Fi API listening on http://${HOST}:${PORT}`);
});

server.on("error", (error) => {
  console.error("Could not start Wi-Fi API:", error.message);
  process.exitCode = 1;
});