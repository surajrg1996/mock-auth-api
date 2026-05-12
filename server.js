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
// HEALTH
// ========================================

app.get("/health", (req, res) => {

  return res.json({
    status: "UP"
  });

});


// ========================================
// OAUTH TOKEN API
// ========================================

app.post("/oauth/token", (req, res) => {

  let client_id;
  let client_secret;

  // ======================================
  // BASIC AUTH METHOD
  // ======================================

  const credentials = basicAuth(req);

  if (credentials) {

    client_id = credentials.name;
    client_secret = credentials.pass;

  } else {

    // ======================================
    // BODY AUTH METHOD
    // ======================================

    client_id = req.body.client_id;
    client_secret = req.body.client_secret;

  }

  const {
    username,
    password,
    grant_type,
    audience,
    scope
  } = req.body;

  // ======================================
  // CLIENT VALIDATION
  // ======================================

  if (
    client_id !== "mock_client" ||
    client_secret !== "mock_secret"
  ) {

    return res.status(401).json({
      error: "invalid_client",
      error_description:
        "Invalid client credentials"
    });

  }

  // ======================================
  // PASSWORD GRANT
  // ======================================

  if (grant_type === "password") {

    const user = users.find(
      u =>
        u.username === username &&
        u.password === password
    );

    if (!user) {

      return res.status(401).json({
        error: "invalid_grant",
        error_description:
          "Invalid username/password"
      });

    }

    const accessToken = jwt.sign(
      {
        username: user.username,
        role: user.role,
        audience: audience || "default-api",
        scope: scope || "read write"
      },
      JWT_SECRET,
      {
        expiresIn: "1h"
      }
    );

    return res.json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: 3600,
      scope: scope || "read write"
    });

  }

  // ======================================
  // CLIENT CREDENTIALS GRANT
  // ======================================

  if (
    grant_type === "client_credentials"
  ) {

    const accessToken = jwt.sign(
      {
        client_id: client_id,
        role: "SYSTEM",
        audience: audience || "system-api",
        scope: scope || "system"
      },
      JWT_SECRET,
      {
        expiresIn: "1h"
      }
    );

    return res.json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: 3600,
      scope: scope || "system"
    });

  }

  return res.status(400).json({
    error: "unsupported_grant_type"
  });

});


// ========================================
// OAUTH PROFILE API
// ========================================

app.post("/oauth/profile", (req, res) => {

  const authHeader =
    req.headers.authorization;

  if (!authHeader) {

    return res.status(401).json({
      error: "Token missing"
    });

  }

  const token = authHeader.split(" ")[1];

  try {

    const decoded = jwt.verify(
      token,
      JWT_SECRET
    );

    return res.json({
      message:
        "OAuth Protected API Success",
      user: decoded,
      headers: {
        authorization: authHeader
      }
    });

  } catch (err) {

    return res.status(401).json({
      error:
        "Invalid or expired token"
    });

  }

});


// ========================================
// START SERVER
// ========================================

app.listen(PORT, () => {

  console.log(
    `Server running on port ${PORT}`
  );

});
