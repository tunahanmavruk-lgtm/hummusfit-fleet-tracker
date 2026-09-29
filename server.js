const express = require("express");
const path = require("path");
const crypto = require("crypto");
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
const STORE_TRACKING_SECRET = process.env.STORE_TRACKING_SECRET || "";
const FLEET_SERVICE_SECRET = process.env.FLEET_SERVICE_SECRET || "";
const ROUTE_BOARD_URL = process.env.ROUTE_BOARD_URL || "https://hummusfit-route-board-production.up.railway.app";
const SUPER_ADMIN_EMAIL = "tony@myhummusfit.com";
const MANAGER_EMAILS = new Set(
  [SUPER_ADMIN_EMAIL, ...(process.env.FLEET_MANAGER_EMAILS || "hummusfit@gmail.com").split(",")]
    .map((email) => email.trim().toLowerCase())
    .filter(Boolean)
);

if (CLERK_PUBLISHABLE_KEY && CLERK_SECRET_KEY) {
  app.use(clerkMiddleware({
    publishableKey: CLERK_PUBLISHABLE_KEY,
    secretKey: CLERK_SECRET_KEY,
    authorizedParties: [
      "https://fleet.myhummusfit.com",
      "https://hummusfit-fleet-tracker-production.up.railway.app",
    ],
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

function serviceRequestAuthorized(req) {
  if (!FLEET_SERVICE_SECRET) return false;
  const authorization = String(req.get("authorization") || "");
  const supplied = authorization.startsWith("Bearer ") ? authorization.slice(7) : "";
  if (!supplied) return false;
  const expectedBuffer = Buffer.from(FLEET_SERVICE_SECRET, "utf8");
  const suppliedBuffer = Buffer.from(supplied, "utf8");
  return expectedBuffer.length === suppliedBuffer.length && crypto.timingSafeEqual(expectedBuffer, suppliedBuffer);
}

function requireManagerOrService(req, res, next) {
  if (serviceRequestAuthorized(req)) {
    req.fleetServiceRequest = true;
    return next();
  }
  return requireManager()(req, res, next);
}

function verifyTrackingToken(token) {
  if (!STORE_TRACKING_SECRET || typeof token !== "string") return null;
  const separator = token.lastIndexOf(".");
  if (separator < 1) return null;
  const payloadPart = token.slice(0, separator);
  const supplied = Buffer.from(token.slice(separator + 1), "base64url");
  const expected = crypto.createHmac("sha256", STORE_TRACKING_SECRET).update(payloadPart).digest();
  if (expected.length !== supplied.length || !crypto.timingSafeEqual(expected, supplied)) return null;
  try {
    const payload = JSON.parse(Buffer.from(payloadPart, "base64url").toString("utf8"));
    const isStoreToken = payload.scope === "store.vehicle.track" && payload.store;
    const isRouteToken = payload.scope === "route.vehicle.track" && payload.routeId;
    if (payload.v !== 1 || (!isStoreToken && !isRouteToken) || !payload.imei) return null;
    if (!Number.isFinite(payload.exp) || payload.exp <= Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch {
    return null;
  }
}

async function activeScopedTracking(req, res, next) {
  const access = String(req.query.access || "");
  const payload = verifyTrackingToken(access);
  if (!payload) return res.status(403).json({ error: "This delivery tracking link is invalid or expired." });
  try {
    if (payload.scope === "store.vehicle.track") {
      const etaResponse = await fetch(`${ROUTE_BOARD_URL}/api/store-eta/${encodeURIComponent(payload.store)}`);
      const eta = etaResponse.ok ? await etaResponse.json() : null;
      if (!eta || !eta.started || !eta.trackingAvailable || eta.vanImei !== payload.imei) {
        return res.status(410).json({ error: "This delivery has ended. Live tracking is no longer available." });
      }
    } else {
      const routeResponse = await fetch(`${ROUTE_BOARD_URL}/api/route-vehicle/${encodeURIComponent(payload.routeId)}`);
      const route = routeResponse.ok ? await routeResponse.json() : null;
      if (!route || !route.assigned || route.vanImei !== payload.imei) {
        return res.status(410).json({ error: "This route assignment has ended. Live tracking is no longer available." });
      }
    }
    req.vehicleTracking = payload;
    next();
  } catch {
    return res.status(503).json({ error: "Delivery status could not be verified." });
  }
}

let cachedToken = null;
let tokenExpiresAt = 0;
let tokenRequestPromise = null;

async function requestAccessToken() {
  const res = await fetch("https://auth.bouncie.com/oauth/token", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      grant_type: "authorization_code",
      code: AUTH_CODE,
      redirect_uri: REDIRECT_URI,
    }),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Bouncie token request failed (${res.status}): ${text}`);
  }

  const data = await res.json();
  if (!data.access_token) throw new Error("Bouncie token response did not include an access token");
  cachedToken = data.access_token;
  const expiresInSeconds = data.expires_in || 3300;
  tokenExpiresAt = Date.now() + expiresInSeconds * 1000;
  return cachedToken;
}

async function getAccessToken(forceRefresh = false) {
  const now = Date.now();
  if (!forceRefresh && cachedToken && now < tokenExpiresAt - 30_000) {
    return cachedToken;
  }

  if (!CLIENT_ID || !CLIENT_SECRET || !AUTH_CODE) {
    throw new Error(
      "Missing BOUNCIE_CLIENT_ID, BOUNCIE_CLIENT_SECRET, or BOUNCIE_AUTH_CODE env vars"
    );
  }

  if (forceRefresh) {
    cachedToken = null;
    tokenExpiresAt = 0;
  }
  // Bouncie rotates refresh tokens. Keeping one only in process memory lets
  // concurrent callers or another service invalidate it and strands every
  // customer map until a redeploy. Bouncie's authorization code remains valid
  // until the account issues a replacement, so use that stable grant and make
  // token creation single-flight.
  if (!tokenRequestPromise) {
    tokenRequestPromise = requestAccessToken().finally(() => {
      tokenRequestPromise = null;
    });
  }
  return tokenRequestPromise;
}

async function bouncieFetch(endpoint, canRetry = true) {
  const token = await getAccessToken();
  const res = await fetch(`https://api.bouncie.dev/v1${endpoint}`, {
    headers: { Authorization: token },
  });
  if (canRetry && (res.status === 401 || res.status === 403)) {
    await getAccessToken(true);
    return bouncieFetch(endpoint, false);
  }
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Bouncie API error (${res.status}): ${text}`);
  }
  return res.json();
}

let vehiclesCache = { fetchedAt: 0, vehicles: [] };
const VEHICLES_CACHE_MS = 10_000;

async function getVehicles() {
  if (Date.now() - vehiclesCache.fetchedAt < VEHICLES_CACHE_MS) return vehiclesCache.vehicles;
  const vehicles = await bouncieFetch("/vehicles");
  vehiclesCache = { fetchedAt: Date.now(), vehicles };
  return vehicles;
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

app.get("/api/vehicles", requireManagerOrService, async (req, res) => {
  try {
    const vehicles = await getVehicles();
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
app.get("/api/vehicle/:imei", requireManager(), async (req, res) => {
  try {
    const vehicles = await getVehicles();
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

app.get("/api/store-vehicle", activeScopedTracking, async (req, res) => {
  try {
    const vehicles = await getVehicles();
    const v = vehicles.find((vehicle) => vehicle.imei === req.vehicleTracking.imei);
    if (!v) return res.status(404).json({ error: "The assigned delivery vehicle is unavailable." });
    res.set("Cache-Control", "private, no-store");
    res.json({
      nickName: v.nickName || "Your delivery van",
      speed: (v.stats && v.stats.speed) || 0,
      isRunning: !!(v.stats && v.stats.isRunning),
      lat: (v.stats && v.stats.location && v.stats.location.lat) || null,
      lon: (v.stats && v.stats.location && v.stats.location.lon) || null,
    });
  } catch (error) {
    console.error(error);
    res.status(503).json({
      error: "Live GPS is reconnecting. Your ETA remains available and this map will retry automatically.",
      retryable: true,
    });
  }
});

app.get("/api/vehicles/:imei/trips", requireManagerOrService, async (req, res) => {
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
app.get("/track.html", (req, res) => {
  if (!verifyTrackingToken(String(req.query.access || ""))) {
    return res.status(403).type("html").send("<!doctype html><meta name=viewport content='width=device-width'><title>Tracking link unavailable</title><style>body{font-family:Arial,sans-serif;background:#edf5f2;color:#173b38;display:grid;place-items:center;min-height:100vh;margin:0}.card{max-width:420px;margin:24px;padding:32px;border-radius:18px;background:white;text-align:center}p{line-height:1.6;color:#667b78}</style><main class=card><h1>Tracking link unavailable</h1><p>Please return to your store’s receiving page and use its current tracking button.</p></main>");
  }
  res.set("Cache-Control", "private, no-store");
  res.set("Referrer-Policy", "no-referrer");
  res.sendFile(path.join(__dirname, "public", "track.html"));
});
app.use(express.static(path.join(__dirname, "public"), { index: false }));

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Bouncie tracker running on port ${PORT}`);
});
