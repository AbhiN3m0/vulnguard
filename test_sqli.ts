const id = req.body.id;
db.query("SELECT * FROM users WHERE id=" + id);
