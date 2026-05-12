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

// ========================================
// MIDDLEWARE
// ========================================

app.use(cors());

// JSON SUPPORT
app.use(bodyParser.json());

// FORM URL ENCODED SUPPORT
app.use(
  bodyParser.urlencoded({
    extended: true
  })
);

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
// COMMON PAYLOAD PROCESSOR
// ========================================

function processPayload(payload) {

  return {

    status: "SUCCESS",

    message:
      "Payload processed successfully",

    extracted_details: {

      tenant:
        payload?.header_details?.tenant,

      order_number:
        payload?.order_details
          ?.order_number,

      service_level:
        payload?.order_details
          ?.service_level,

      sender_name:
        payload?.contact_details
          ?.SenderName,

      city:
        payload?.shipment_details
          ?.address1,

      modified_by:
        payload?.user_details
          ?.modified_by,

      part_number:
        payload?.part_details?.[0]
          ?.part_number,

      quantity:
        payload?.part_details?.[0]
          ?.quantity,

      flow_types:
        payload?.header_details
          ?.flow_types

    },

    order_status:
      payload?.order_details
        ?.service_level ===
      "Source Flow Test"
        ? "FLOW_TEST_TRIGGERED"
        : "ORDER_CREATED",

    received_at:
      new Date().toISOString()

  };

}

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

  const credentials =
    basicAuth(req);

  if (!credentials) {

    return res.status(401).json({
      error:
        "Authorization header missing"
    });

  }

  const user = users.find(
    u =>
      u.username ===
        credentials.name &&
      u.password ===
        credentials.pass
  );

  if (!user) {

    return res.status(401).json({
      error:
        "Invalid username/password"
    });

  }

  return res.json({
    status: "success",
    message:
      "Basic Auth Login Successful",
    user: {
      username: user.username,
      role: user.role
    }
  });

});

// ========================================
// BASIC AUTH PROCESS ORDER
// ========================================

app.post(
  "/basic/process-order",
  (req, res) => {

    const credentials =
      basicAuth(req);

    if (!credentials) {

      return res.status(401).json({
        error:
          "Authorization header missing"
      });

    }

    const user = users.find(
      u =>
        u.username ===
          credentials.name &&
        u.password ===
          credentials.pass
    );

    if (!user) {

      return res.status(401).json({
        error:
          "Invalid username/password"
      });

    }

    const response =
      processPayload(req.body);

    return res.json({
      auth_type: "BASIC_AUTH",
      authenticated_user:
        user.username,
      response
    });

  }
);

// ========================================
// OAUTH TOKEN API
// ========================================

app.post("/oauth/token", (req, res) => {

  const {
    client_id,
    client_secret,
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
        audience:
          audience || "default-api",
        scope:
          scope || "read write",
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
      audience:
        audience || "default-api",
      scope:
        scope || "read write"
    });

  }

  // ======================================
  // CLIENT CREDENTIALS GRANT
  // ======================================

  if (
    grant_type ===
    "client_credentials"
  ) {

    const accessToken = jwt.sign(
      {
        client_id: client_id,
        role: "SYSTEM",
        audience:
          audience || "system-api",
        scope:
          scope || "system",
        auth_type:
          "client_credentials"
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
      audience:
        audience || "system-api",
      scope:
        scope || "system"
    });

  }

  return res.status(400).json({
    error:
      "unsupported_grant_type"
  });

});

// ========================================
// OAUTH PROFILE
// ========================================

app.post(
  "/oauth/profile",
  (req, res) => {

    const authHeader =
      req.headers.authorization;

    if (!authHeader) {

      return res.status(401).json({
        error:
          "Token missing"
      });

    }

    try {

      const token =
        authHeader.split(" ")[1];

      const decoded =
        jwt.verify(
          token,
          JWT_SECRET
        );

      return res.json({
        message:
          "OAuth Protected API Success",

        user: decoded
      });

    } catch {

      return res.status(401).json({
        error:
          "Invalid or expired token"
      });

    }

  }
);

// ========================================
// OAUTH PROCESS ORDER
// ========================================

app.post(
  "/oauth/process-order",
  (req, res) => {

    const authHeader =
      req.headers.authorization;

    if (!authHeader) {

      return res.status(401).json({
        error:
          "Token missing"
      });

    }

    try {

      const token =
        authHeader.split(" ")[1];

      const decoded =
        jwt.verify(
          token,
          JWT_SECRET
        );

      const response =
        processPayload(req.body);

      return res.json({
        auth_type: "OAUTH",
        authenticated_user:
          decoded,
        response
      });

    } catch {

      return res.status(401).json({
        error:
          "Invalid or expired token"
      });

    }

  }
);

// ========================================
// JWE SETUP
// ========================================

let secretKey;

(async () => {

  secretKey =
    await generateSecret(
      "A256GCM"
    );

})();

// ========================================
// JWE LOGIN
// ========================================

app.post(
  "/jwe/login",
  async (req, res) => {

    const {
      username,
      password
    } = req.body;

    const user = users.find(
      u =>
        u.username ===
          username &&
        u.password ===
          password
    );

    if (!user) {

      return res.status(401).json({
        error:
          "Invalid credentials"
      });

    }

    const payload =
      JSON.stringify({
        username:
          user.username,

        role: user.role,

        secure: true,

        time: Date.now()
      });

    const jwe =
      await new CompactEncrypt(
        new TextEncoder().encode(
          payload
        )
      )
        .setProtectedHeader({
          alg: "dir",
          enc: "A256GCM"
        })
        .encrypt(secretKey);

    return res.json({
      encrypted_token: jwe
    });

  }
);

// ========================================
// JWE PROFILE
// ========================================

app.get(
  "/jwe/profile",
  async (req, res) => {

    const authHeader =
      req.headers.authorization;

    if (!authHeader) {

      return res.status(401).json({
        error:
          "Token missing"
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

      const decoded =
        JSON.parse(
          new TextDecoder().decode(
            plaintext
          )
        );

      return res.json({
        message:
          "JWE Protected API Success",

        user: decoded
      });

    } catch {

      return res.status(401).json({
        error:
          "Invalid encrypted token"
      });

    }

  }
);

// ========================================
// START SERVER
// ========================================

app.listen(PORT, () => {

  console.log(
    `Server running on port ${PORT}`
  );

});
