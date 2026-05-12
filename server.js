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

// ========================================
// MOCK USERS
// ========================================

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
// HEALTH API
// ========================================

app.get("/health", (req, res) => {

  return res.json({
    status: "UP"
  });

});

// ========================================
// BASIC AUTH LOGIN
// ========================================

app.post("/basic/login", (req, res) => {

  const credentials = basicAuth(req);

  if (!credentials) {

    return res.status(401).json({
      error: "Authorization header missing"
    });

  }

  const {
    name,
    pass
  } = credentials;

  const user = users.find(
    u =>
      u.username === name &&
      u.password === pass
  );

  if (!user) {

    return res.status(401).json({
      error: "Invalid username/password"
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

  let client_id;
  let client_secret;

  // ======================================
  // BASIC AUTH CLIENT AUTH METHOD
  // ======================================

  const credentials = basicAuth(req);

  if (credentials) {

    client_id = credentials.name;
    client_secret = credentials.pass;

  } else {

    // ======================================
    // BODY CLIENT AUTH METHOD
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
        scope: scope || "read write",
        auth_type: "password"
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
      audience: audience || "default-api",
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
        scope: scope || "system",
        auth_type: "client_credentials"
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
      audience: audience || "system-api",
      scope: scope || "system"
    });

  }

  return res.status(400).json({
    error: "unsupported_grant_type"
  });

});

// ========================================
// OAUTH PROTECTED API
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
// JWE SETUP
// ========================================

let secretKey;

(async () => {

  secretKey =
    await generateSecret("A256GCM");

})();

// ========================================
// JWE LOGIN
// ========================================

app.post("/jwe/login", async (req, res) => {

  const {
    username,
    password
  } = req.body;

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
    secure: true,
    time: Date.now()
  });

  const jwe =
    await new CompactEncrypt(
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

  const authHeader =
    req.headers.authorization;

  if (!authHeader) {

    return res.status(401).json({
      error: "Token missing"
    });

  }

  try {

    const token =
      authHeader.split(" ")[1];

    const { plaintext } =
      await compactDecrypt(
        token,
        secretKey
      );

    const decoded = JSON.parse(
      new TextDecoder().decode(
        plaintext
      )
    );

    return res.json({
      message:
        "JWE Protected API Success",
      user: decoded
    });

  } catch (err) {

    return res.status(401).json({
      error:
        "Invalid encrypted token"
    });

  }

});

// ========================================
// LOGOUT MOCK API
// ========================================

app.post("/logout", (req, res) => {

  return res.json({
    status: "success",
    message: "Logout successful"
  });

});

// ========================================
// VALIDATE TOKEN API
// ========================================

app.post("/validate-token", (req, res) => {

  const authHeader =
    req.headers.authorization;

  if (!authHeader) {

    return res.status(401).json({
      error: "Token missing"
    });

  }

  try {

    const token =
      authHeader.split(" ")[1];

    const decoded = jwt.verify(
      token,
      JWT_SECRET
    );

    return res.json({
      valid: true,
      decoded
    });

  } catch {

    return res.status(401).json({
      valid: false,
      error: "Invalid token"
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
