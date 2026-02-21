const { exec } = require("child_process");

function run(x) {
  exec(x);
}

app.get("/run", (req, res) => {
  const input = req.body.input;
  run(input);
});
