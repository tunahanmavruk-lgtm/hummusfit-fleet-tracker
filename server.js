const express = require("express");
const path = require("path");

const app = express();

// Fixed port — must match the "target port" set in Railway's
// Settings → Networking → Generate Domain (set to 3000).
const PORT = 3000;

app.use(express.static(path.join(__dirname)));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Ops Hub running on port ${PORT}`);
});
