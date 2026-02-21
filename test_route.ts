import express from "express";
const app = express();

app.get("/admin", (req, res) => {
  res.send("admin panel");
});
