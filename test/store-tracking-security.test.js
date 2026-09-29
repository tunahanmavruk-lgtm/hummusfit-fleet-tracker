const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const root = path.resolve(__dirname, "..");
const read = (file) => fs.readFileSync(path.join(root, file), "utf8");

test("protects the complete fleet and scopes store tracking to a signed active delivery", () => {
  const server = read("server.js");
  assert.match(server, /app\.get\("\/api\/vehicles", requireManagerOrService/);
  assert.match(server, /app\.get\("\/api\/vehicle\/:imei", requireManager\(\)/);
  assert.match(server, /app\.get\("\/api\/store-vehicle", activeScopedTracking/);
  assert.match(server, /scope === "store\.vehicle\.track"/);
  assert.match(server, /scope === "route\.vehicle\.track"/);
  assert.match(server, /api\/route-vehicle/);
  assert.match(server, /eta\.vanImei !== payload\.imei/);
  assert.match(server, /eta\.trackingAvailable/);
  assert.match(server, /Cache-Control", "private, no-store/);
});

test("allows the HF Logistics server to read fleet data without exposing it publicly", () => {
  const server = read("server.js");
  assert.match(server, /FLEET_SERVICE_SECRET/);
  assert.match(server, /timingSafeEqual/);
  assert.match(server, /app\.get\("\/api\/vehicles\/:imei\/trips", requireManagerOrService/);
});

test("keeps Bouncie authentication single-flight and avoids invalid in-memory refresh tokens", () => {
  const server = read("server.js");
  assert.match(server, /tokenRequestPromise/);
  assert.match(server, /grant_type: "authorization_code"/);
  assert.match(server, /getAccessToken\(true\)/);
  assert.doesNotMatch(server, /cachedRefreshToken/);
  assert.doesNotMatch(server, /grant_type: "refresh_token"/);
  assert.match(server, /VEHICLES_CACHE_MS = 10_000/);
});

test("tells store customers that GPS recovery is automatic without exposing authorization details", () => {
  const server = read("server.js");
  assert.match(server, /Live GPS is reconnecting/);
  assert.match(server, /retryable: true/);
  assert.doesNotMatch(server, /res\.status\(503\)\.json\(\{ error: error\.message/);
});

test("store tracking page no longer accepts raw vehicle or route identifiers", () => {
  const html = read("public/track.html");
  assert.match(html, /params\.get\('access'\)/);
  assert.match(html, /\/api\/store-vehicle\?access=/);
  assert.doesNotMatch(html, /params\.get\('imei'\)/);
  assert.doesNotMatch(html, /routeBoardUrl/);
  assert.doesNotMatch(html, /\/api\/vehicle\//);
});

test("authorizes both Hummus Fit owner identities by default", () => {
  const server = read("server.js");
  assert.match(server, /SUPER_ADMIN_EMAIL = "tony@myhummusfit\.com"/);
  assert.match(server, /\[SUPER_ADMIN_EMAIL, \.\.\.\(process\.env\.FLEET_MANAGER_EMAILS/);
  assert.match(server, /hummusfit@gmail\.com/);
});
