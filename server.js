const express = require("express");
const path = require("path");
const { clerkClient, clerkMiddleware, getAuth } = require("@clerk/express");

const app = express();
// This service's Railway domain is explicitly routed to target port 3000.
const PORT = 3000;

// ---- Config from environment variables (set these in Railway) ----
const CLIENT_ID = process.env.BOUNCIE_CLIENT_ID;
const CLIENT_SECRET = process.env.BOUNCIE_CLIENT_SECRET;
const AUTH_CODE = process.env.BOUNCIE_AUTH_CODE;
const REDIRECT_URI = process.env.BOUNCIE_REDIRECT_URI || "https://www.bouncie.dev";
const CLERK_PUBLISHABLE_KEY = process.env.CLERK_PUBLISHABLE_KEY;
const CLERK_SECRET_KEY = process.env.CLERK_SECRET_KEY;
const MANAGER_EMAILS = new Set(
  (process.env.FLEET_MANAGER_EMAILS || "tony@myhummusfit.com")
    .split(",")
    .map((email) => email.trim().toLowerCase())
    .filter(Boolean)
);

if (CLERK_PUBLISHABLE_KEY && CLERK_SECRET_KEY) {
  app.use(clerkMiddleware({
    publishableKey: CLERK_PUBLISHABLE_KEY,
    secretKey: CLERK_SECRET_KEY,
    authorizedParties: ["https://hummusfit-fleet-tracker-production.up.railway.app"],
  }));
}

const managerCache = new Map();

async function managerIdentity(req) {
  if (!CLERK_PUBLISHABLE_KEY || !CLERK_SECRET_KEY) return null;
  const auth = getAuth(req);
  if (!auth.isAuthenticated || !auth.userId) return null;
  const cached = managerCache.get(auth.userId);
  if (cached && cached.expiresAt > Date.now()) return cached.identity;
  const user = await clerkClient.users.getUser(auth.userId);
  const emails = user.emailAddresses.map((entry) => entry.emailAddress.toLowerCase());
  const email = emails.find((value) => MANAGER_EMAILS.has(value));
  if (!email) return null;
  const identity = { userId: auth.userId, email, name: user.fullName || user.firstName || email.split("@")[0] };
  managerCache.set(auth.userId, { identity, expiresAt: Date.now() + 5 * 60_000 });
  return identity;
}

function requireManager(options = {}) {
  return async (req, res, next) => {
    if (!CLERK_PUBLISHABLE_KEY || !CLERK_SECRET_KEY) {
      return res.status(503).send(options.html ? "Fleet manager authentication is being configured." : { error: "Fleet manager authentication is not configured" });
    }
    try {
      const identity = await managerIdentity(req);
      if (!identity) {
        if (options.html) return res.redirect(`/sign-in?redirect_url=${encodeURIComponent(req.originalUrl || "/")}`);
        return res.status(401).json({ error: "Manager authentication required" });
      }
      req.managerIdentity = identity;
      next();
    } catch (error) {
      console.error("Fleet manager authorization failed", error);
      return res.status(401).send(options.html ? "Unable to verify this manager session." : { error: "Unable to verify manager session" });
    }
  };
}

let cachedToken = null;
let cachedRefreshToken = null;
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

  const body = JSON.stringify(cachedRefreshToken ? {
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    grant_type: "refresh_token",
    refresh_token: cachedRefreshToken,
  } : {
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
  cachedRefreshToken = data.refresh_token || cachedRefreshToken;
  // Bouncie tokens are typically short-lived; default to 55 min if not specified
  const expiresInSeconds = data.expires_in || 3300;
  tokenExpiresAt = now + expiresInSeconds * 1000;
  return cachedToken;
}

async function bouncieFetch(endpoint) {
  const token = await getAccessToken();
  const res = await fetch(`https://api.bouncie.dev/v1${endpoint}`, {
    headers: { Authorization: token },
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Bouncie API error (${res.status}): ${text}`);
  }
  return res.json();
}

// ---- API routes consumed by the frontend ----

function clerkFrontendApi() {
  try {
    const encoded = CLERK_PUBLISHABLE_KEY.split("_").slice(2).join("_").replace(/-/g, "+").replace(/_/g, "/");
    return Buffer.from(encoded, "base64").toString("utf8").replace(/\$$/, "");
  } catch {
    return "";
  }
}

app.get("/sign-in", (req, res) => {
  if (!CLERK_PUBLISHABLE_KEY) return res.status(503).send("Fleet manager sign-in is being configured.");
  const frontendApi = clerkFrontendApi();
  const redirect = typeof req.query.redirect_url === "string" && req.query.redirect_url.startsWith("/") ? req.query.redirect_url : "/";
  res.type("html").send(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Fleet Manager Sign In</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f7f6f3;font-family:Arial,sans-serif}.shell{display:grid;justify-items:center;gap:20px;padding:28px}.brand{font-weight:900;letter-spacing:.16em;color:#117c6b}.note{max-width:390px;text-align:center;color:#666;font-size:13px;line-height:1.5}</style><script defer crossorigin="anonymous" src="https://${frontendApi}/npm/@clerk/ui@1/dist/ui.browser.js"></script><script defer crossorigin="anonymous" data-clerk-publishable-key="${CLERK_PUBLISHABLE_KEY}" src="https://${frontendApi}/npm/@clerk/clerk-js@6/dist/clerk.browser.js"></script></head><body><main class="shell"><div class="brand">HUMMUS FIT · FLEET MANAGER</div><div id="sign-in"></div><p class="note">Only approved managers can view the full fleet, vehicle health, and trip history.</p></main><script>window.addEventListener('load',async function(){await Clerk.load({ui:{ClerkUI:window.__internal_ClerkUICtor}});if(Clerk.isSignedIn){location.replace(${JSON.stringify(redirect)});return;}Clerk.mountSignIn(document.getElementById('sign-in'),{fallbackRedirectUrl:${JSON.stringify(redirect)}});});</script></body></html>`);
});

app.get("/api/session", requireManager(), (req, res) => {
  res.json({ name: req.managerIdentity.name, email: req.managerIdentity.email });
});

app.get("/api/vehicles", requireManager(), async (req, res) => {
  try {
    const vehicles = await bouncieFetch("/vehicles");
    res.json(vehicles);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Scoped lookup for the store-facing "track my delivery" page — returns
// ONLY the one requested vehicle, never the rest of the fleet. This is a
// real server-side filter, not just something the frontend hides: a
// store employee's tracking link should never be able to see where every
// other van in the fleet is, even by poking at the network tab.
app.get("/api/vehicle/:imei", async (req, res) => {
  try {
    const vehicles = await bouncieFetch("/vehicles");
    const v = vehicles.find((veh) => veh.imei === req.params.imei);
    if (!v) return res.status(404).json({ error: "No vehicle with that IMEI." });
    res.json({
      nickName: v.nickName || null,
      imei: v.imei,
      speed: (v.stats && v.stats.speed) || 0,
      isRunning: !!(v.stats && v.stats.isRunning),
      lat: (v.stats && v.stats.location && v.stats.location.lat) || null,
      lon: (v.stats && v.stats.location && v.stats.location.lon) || null,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/vehicles/:imei/trips", requireManager(), async (req, res) => {
  try {
    const trips = await bouncieFetch(`/trips?imei=${req.params.imei}&gps-format=geojson`);
    const limit = Math.min(50, Math.max(1, Number(req.query.limit) || 20));
    res.json(trips.sort((a, b) => String(b.startTime || "").localeCompare(String(a.startTime || ""))).slice(0, limit));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/status", (req, res) => {
  res.json({
    configured: Boolean(CLIENT_ID && CLIENT_SECRET && AUTH_CODE),
    managerAuthentication: Boolean(CLERK_PUBLISHABLE_KEY && CLERK_SECRET_KEY),
  });
});

// ---- Static frontend ----
app.get(["/", "/index.html"], requireManager({ html: true }), (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.use(express.static(path.join(__dirname, "public"), { index: false }));

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Bouncie tracker running on port ${PORT}`);
});
