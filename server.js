const express = require("express");

require("dotenv").config();

const app = express();
const PORT = process.env.AUTH_SERVICE_PORT || 5001;

app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
  res.send("Auth service running!");
});

app.listen(PORT, () => {
  console.log(`Auth service running on port ${PORT}`);
});
