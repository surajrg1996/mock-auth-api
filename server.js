const express = require("express");
const jwt = require("jsonwebtoken");
const basicAuth = require("basic-auth");
const cors = require("cors");
const bodyParser = require("body-parser");

const {
  CompactEncrypt,
  compactDecrypt,
  generateSecret
} = require("jose");

const app = express();

app.use(cors());
app.use(bodyParser.json());

const PORT = process.env.PORT || 3000;

const JWT_SECRET = "MY_SUPER_SECRET";

const users = [
  {
    username: "admin",
    password: "Admin@123",
    role: "ADMIN"
  },
  {
    username: "tester",
    password: "Test@123",
    role: "TESTER"
  }
];


// ========================================
// BASIC AUTH LOGIN
// ========================================

app.post("/basic/login", (req, res) => {

  const credentials = basicAuth(req);

  if (!credentials) {
    return res.status(401).json({
      message: "Authorization header missing"
    });
  }

  const user = users.find(
    u =>
      u.username === credentials.name &&
      u.password === credentials.pass
  );

  if (!user) {
    return res.status(401).json({
      message: "Invalid username/password"
    });
  }

  return res.json({
    status: "success",
    message: "Basic Auth Login Successful",
    user: {
      username: user.username,
      role: user.role
    }
  });

});


// ========================================
// OAUTH TOKEN API
// ========================================

app.post("/oauth/token", (req, res) => {

  const {
    client_id,
    client_secret,
    username,
    password,
    grant_type
  } = req.body;

  if (
    client_id !== "mock_client" ||
    client_secret !== "mock_secret"
  ) {
    return res.status(401).json({
      error: "Invalid client"
    });
  }

  if (grant_type !== "password") {
    return res.status(400).json({
      error: "Unsupported grant_type"
    });
  }

  const user = users.find(
    u =>
      u.username === username &&
      u.password === password
  );

  if (!user) {
    return res.status(401).json({
      error: "Invalid credentials"
    });
  }

  const accessToken = jwt.sign(
    {
      username: user.username,
      role: user.role
    },
    JWT_SECRET,
    {
      expiresIn: "1h"
    }
  );

  return res.json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: 3600
  });

});


// ========================================
// OAUTH PROTECTED API
// ========================================

app.get("/oauth/profile", (req, res) => {

  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({
      error: "Token missing"
    });
  }

  const token = authHeader.split(" ")[1];

  try {

    const decoded = jwt.verify(token, JWT_SECRET);

    return res.json({
      message: "Protected Data",
      user: decoded
    });

  } catch (err) {

    return res.status(401).json({
      error: "Invalid or expired token"
    });

  }

});


// ========================================
// JWE LOGIN
// ========================================

let secretKey;

(async () => {

  secretKey = await generateSecret("A256GCM");

})();

app.post("/jwe/login", async (req, res) => {

  const { username, password } = req.body;

  const user = users.find(
    u =>
      u.username === username &&
      u.password === password
  );

  if (!user) {
    return res.status(401).json({
      error: "Invalid credentials"
    });
  }

  const payload = JSON.stringify({
    username: user.username,
    role: user.role,
    time: Date.now()
  });

  const jwe = await new CompactEncrypt(
    new TextEncoder().encode(payload)
  )
    .setProtectedHeader({
      alg: "dir",
      enc: "A256GCM"
    })
    .encrypt(secretKey);

  return res.json({
    encrypted_token: jwe
  });

});


// ========================================
// JWE PROTECTED API
// ========================================

app.get("/jwe/profile", async (req, res) => {

  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({
      error: "Token missing"
    });
  }

  try {

    const token = authHeader.split(" ")[1];

    const { plaintext } = await compactDecrypt(
      token,
      secretKey
    );

    const decoded = JSON.parse(
      new TextDecoder().decode(plaintext)
    );

    return res.json({
      message: "JWE Protected API Success",
      user: decoded
    });

  } catch (err) {

    return res.status(401).json({
      error: "Invalid encrypted token"
    });

  }

});


// ========================================
// HEALTH API
// ========================================

app.get("/health", (req, res) => {

  return res.json({
    status: "UP"
  });

});


// ========================================
// START SERVER
// ========================================

app.listen(PORT, () => {

  console.log(`Server running on port ${PORT}`);

});
