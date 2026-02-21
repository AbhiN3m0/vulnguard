const { exec } = require("child_process");

app.get("/run", (req, res) => {
  const a = req.body.input;
  const safe = sanitize(a);  // Sanitizer
  exec(safe);                // Should NOT trigger
});
