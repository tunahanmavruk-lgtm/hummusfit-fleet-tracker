const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const root = path.resolve(__dirname, "..");
const read = (file) => fs.readFileSync(path.join(root, file), "utf8");

test("protects the complete fleet and scopes store tracking to a signed active delivery", () => {
  const server = read("server.js");
  assert.match(server, /app\.get\("\/api\/vehicles", requireManager\(\)/);
  assert.match(server, /app\.get\("\/api\/vehicle\/:imei", requireManager\(\)/);
  assert.match(server, /app\.get\("\/api\/store-vehicle", activeStoreTracking/);
  assert.match(server, /scope !== "store\.vehicle\.track"/);
  assert.match(server, /eta\.vanImei !== payload\.imei/);
  assert.match(server, /eta\.delivered/);
  assert.match(server, /Cache-Control", "private, no-store/);
});

test("store tracking page no longer accepts raw vehicle or route identifiers", () => {
  const html = read("public/track.html");
  assert.match(html, /params\.get\('access'\)/);
  assert.match(html, /\/api\/store-vehicle\?access=/);
  assert.doesNotMatch(html, /params\.get\('imei'\)/);
  assert.doesNotMatch(html, /routeBoardUrl/);
  assert.doesNotMatch(html, /\/api\/vehicle\//);
});
