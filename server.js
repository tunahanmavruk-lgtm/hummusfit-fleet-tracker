const express = require("express");
const path = require("path");

const app = express();
// Fixed port — must match the "target port" set in Railway's
// Settings → Networking → Generate Domain (set to 3000).
const PORT = 3000;

// ---- Config from environment variables (set these in Railway) ----
const CLIENT_ID = process.env.BOUNCIE_CLIENT_ID;
const CLIENT_SECRET = process.env.BOUNCIE_CLIENT_SECRET;
const AUTH_CODE = process.env.BOUNCIE_AUTH_CODE;
const REDIRECT_URI = process.env.BOUNCIE_REDIRECT_URI || "https://www.bouncie.dev";

let cachedToken = null;
let tokenExpiresAt = 0;

async function getAccessToken() {
  const now = Date.now();
  if (cachedToken && now < tokenExpiresAt - 30_000) {
    return cachedToken;
  }

  if (!CLIENT_ID || !CLIENT_SECRET || !AUTH_CODE) {
    throw new Error(
      "Missing BOUNCIE_CLIENT_ID, BOUNCIE_CLIENT_SECRET, or BOUNCIE_AUTH_CODE env vars"
    );
  }

  const body = JSON.stringify({
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    grant_type: "authorization_code",
    code: AUTH_CODE,
    redirect_uri: REDIRECT_URI,
  });

  const res = await fetch("https://auth.bouncie.com/oauth/token", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: body,
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Bouncie token request failed (${res.status}): ${text}`);
  }

  const data = await res.json();
  cachedToken = data.access_token;
  // Bouncie tokens are typically short-lived; default to 55 min if not specified
  const expiresInSeconds = data.expires_in || 3300;
  tokenExpiresAt = now + expiresInSeconds * 1000;
  return cachedToken;
}

async function bouncieFetch(endpoint) {
  const token = await getAccessToken();
  const res = await fetch(`https://api.bouncie.dev${endpoint}`, {
    headers: { Authorization: token },
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Bouncie API error (${res.status}): ${text}`);
  }
  return res.json();
}

// ---- API routes consumed by the frontend ----

app.get("/api/vehicles", async (req, res) => {
  try {
    const vehicles = await bouncieFetch("/vehicles");
    res.json(vehicles);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/vehicles/:imei/trips", async (req, res) => {
  try {
    const trips = await bouncieFetch(`/trips?imei=${req.params.imei}&gps-format=geojson`);
    res.json(trips);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/status", (req, res) => {
  res.json({
    configured: Boolean(CLIENT_ID && CLIENT_SECRET && AUTH_CODE),
  });
});

// ---- Static frontend ----
app.use(express.static(path.join(__dirname, "public")));

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Bouncie tracker running on port ${PORT}`);
});
