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

app.use(bodyParser.json());

app.use(
  bodyParser.urlencoded({
    extended: true
  })
);

// ========================================
// GLOBAL REQUEST/RESPONSE LOGGER
// ========================================

app.use((req, res, next) => {

  const startTime = Date.now();

  console.log("\n========================================");
  console.log("Incoming Request");
  console.log("========================================");
  console.log("Time       :", new Date().toISOString());
  console.log("Method     :", req.method);
  console.log("Endpoint   :", req.originalUrl);
  console.log("IP Address :", req.ip);

  console.log("\nHeaders:");
  console.log(JSON.stringify(req.headers, null, 2));

  console.log("\nQuery Params:");
  console.log(JSON.stringify(req.query, null, 2));

  console.log("\nRequest Body:");
  console.log(JSON.stringify(req.body, null, 2));

  const originalJson = res.json;
  const originalSend = res.send;

  res.json = function (body) {

    console.log("\nResponse Status :", res.statusCode);
    console.log("Response Body:");
    console.log(JSON.stringify(body, null, 2));
    console.log("Execution Time :", Date.now() - startTime, "ms");
    console.log("========================================\n");

    return originalJson.call(this, body);

  };

  res.send = function (body) {

    console.log("\nResponse Status :", res.statusCode);
    console.log("Response Body:");
    console.log(body);
    console.log("Execution Time :", Date.now() - startTime, "ms");
    console.log("========================================\n");

    return originalSend.call(this, body);

  };

  next();

});

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
  },
  {
    username: "Suraj",
    password: "Test@qa",
    role: "USER"
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
// BASIC AUTH PROFILE API
// ========================================

app.post("/basic/profile", (req, res) => {

  console.log("========== BASIC PROFILE API ==========");

  const credentials = basicAuth(req);

  if (!credentials) {

    console.log("Authorization header missing");

    return res.status(401).json({
      error: "Authorization header missing"
    });

  }

  const user = users.find(
    u =>
      u.username === credentials.name &&
      u.password === credentials.pass
  );

  if (!user) {

    console.log("Invalid username/password");

    return res.status(401).json({
      error: "Invalid username/password"
    });

  }

  console.log("Authenticated User:", user.username);
  console.log("Request Body:");
  console.log(JSON.stringify(req.body, null, 2));

  const response = {
    status: "SUCCESS",
    message: "Basic Authentication Successful",
    authenticated_user: {
      username: user.username,
      role: user.role
    },
    request_payload: req.body,
    timestamp: new Date().toISOString()
  };

  console.log("Response:");
  console.log(JSON.stringify(response, null, 2));
  console.log("======================================");

  return res.json(response);

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

  // PASSWORD GRANT

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

  // CLIENT CREDENTIALS GRANT

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

    const username =
      req.body.username;

    const password =
      req.body.password;

    if (!username || !password) {

      return res.status(400).json({
        error:
          "username and password required"
      });

    }

    const user = users.find(
      u =>
        u.username === username &&
        u.password === password
    );

    if (!user) {

      return res.status(401).json({
        error:
          "Invalid username/password"
      });

    }

    const payload =
      JSON.stringify({
        username:
          user.username,

        role:
          user.role,

        secure: true,

        auth_type: "JWE",

        time:
          Date.now()
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
      authToken: jwe
    });

  }
);

// ========================================
// JWE PROFILE
// ========================================

app.post(
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
// JWE PROCESS ORDER
// ========================================

app.post(
  "/jwe/process-order",
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

      const response =
        processPayload(req.body);

      return res.json({
        auth_type: "JWE",
        authenticated_user:
          decoded,
        response
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
// GRAPH API TOKEN
// ========================================

app.post("/graph/token", (req, res) => {

  const {
    client_id,
    client_secret,
    username,
    password
  } = req.body;

  if (
    client_id !== "mock_client" ||
    client_secret !== "mock_secret"
  ) {

    return res.status(401).json({
      error: "invalid_client"
    });

  }

  const user = users.find(
    u =>
      u.username === username &&
      u.password === password
  );

  if (!user) {

    return res.status(401).json({
      error: "invalid_user"
    });

  }

  const token = jwt.sign(
    {
      username: user.username,
      role: user.role,
      api_type: "GRAPH_API"
    },
    JWT_SECRET,
    {
      expiresIn: "1h"
    }
  );

  return res.json({
    access_token: token,
    token_type: "Bearer",
    expires_in: 3600
  });

});

// ========================================
// GRAPH API ME
// ========================================

app.get("/graph/v1.0/me", (req, res) => {

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

    const decoded =
      jwt.verify(
        token,
        JWT_SECRET
      );

    return res.json({
      id: "USR001",
      displayName:
        decoded.username,
      givenName:
        decoded.username,
      mail:
        `${decoded.username}@mock.com`,
      jobTitle:
        decoded.role,
      officeLocation:
        "Pune",
      preferredLanguage:
        "en-US"
    });

  } catch {

    return res.status(401).json({
      error: "Invalid token"
    });

  }

});

// ========================================
// GRAPH API USERS
// ========================================

app.get("/graph/v1.0/users", (req, res) => {

  return res.json({
    value: [
      {
        id: "USR001",
        displayName: "admin",
        mail: "admin@mock.com",
        role: "ADMIN"
      },
      {
        id: "USR002",
        displayName: "tester",
        mail: "tester@mock.com",
        role: "TESTER"
      }
    ]
  });

});

// ========================================
// GRAPH API GROUPS
// ========================================

app.get("/graph/v1.0/groups", (req, res) => {

  return res.json({
    value: [
      {
        id: "GRP001",
        displayName: "Admins"
      },
      {
        id: "GRP002",
        displayName: "Testers"
      }
    ]
  });

});

// ========================================
// GRAPH SEND MAIL
// ========================================

app.post(
  "/graph/v1.0/sendMail",
  (req, res) => {

    return res.json({
      status: "SUCCESS",
      message:
        "Mail sent successfully",
      request_body: req.body
    });

  }
);

// ========================================
// GRAPH PROCESS ORDER
// ========================================

app.post(
  "/graph/v1.0/process-order",
  (req, res) => {

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

      const decoded =
        jwt.verify(
          token,
          JWT_SECRET
        );

      const response =
        processPayload(req.body);

      return res.json({
        api_type: "GRAPH_API",
        authenticated_user:
          decoded.username,
        response
      });

    } catch {

      return res.status(401).json({
        error: "Invalid token"
      });

    }

  }
);

// ========================================
// VALIDATE TOKEN
// ========================================

app.post(
  "/validate-token",
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
        valid: true,
        decoded
      });

    } catch {

      return res.status(401).json({
        valid: false,
        error:
          "Invalid token"
      });

    }

  }
);

// ========================================
// INVALID JSON / XML RESPONSE API
// ========================================

app.post(
  "/mock/invalid-payload",
  (req, res) => {

    const type = req.query.type || "json";

    if (type === "json") {

      res.set(
        "Content-Type",
        "application/json"
      );

      // Invalid JSON
      return res.send(
        '{"status":"SUCCESS","message":"Invalid JSON Response"'
      );

    }

    if (type === "xml") {

      res.set(
        "Content-Type",
        "application/xml"
      );

      // Invalid XML
      return res.send(`
        <response>
          <status>SUCCESS</status>
          <message>Invalid XML Response</message>
      `);

    }

    return res.status(400).send(
      "Supported types: json, xml"
    );

  }
);

// ========================================
// BAD REQUEST (400) API
// ========================================

app.post("/mock/bad-request", (req, res) => {

  return res.status(400).json({
    status: "FAILED",
    error_code: "BAD_REQUEST",
    message: "Invalid request payload",
    timestamp: new Date().toISOString()
  });

});

// ========================================
// HTTP 301 JSON RESPONSE API
// ========================================

app.post("/mock/301", (req, res) => {

  return res.status(301).json({
    status: "MOVED_PERMANENTLY",
    message: "Resource has moved permanently",
    redirect_url: "/health"
  });

});

// ========================================
// ECHO CONDITION MAPPING API
// ========================================

app.post("/mock/condition-mapping", (req, res) => {
  return res.json({
    IF_ELSE_01: req.body?.IF_ELSE_01,
    IF_ELSEIF_ELSE_02: req.body?.IF_ELSEIF_ELSE_02,
    IF_ELSEIF_ELSE_03: req.body?.IF_ELSEIF_ELSE_03,
    Boolean_Condition: req.body?.Boolean_Condition,
    test_conditionr: req.body?.test_condition
  });
});

// ========================================
// PUBLIC PROFILE API (NO AUTH)
// ========================================

app.post("/public/profile", (req, res) => {

  console.log("========== PUBLIC PROFILE ==========");
  console.log("Endpoint Hit: /public/profile");
  console.log("Request Body:");
  console.log(JSON.stringify(req.body, null, 2));

  const response = {
    status: "SUCCESS",
    message: "Public API accessed successfully",
    user: {
      username: "admin",
      role: "ADMIN",
      auth_type: "NONE"
    },
    received_payload: req.body,
    timestamp: new Date().toISOString()
  };

  console.log("Response:");
  console.log(JSON.stringify(response, null, 2));
  console.log("====================================");

  return res.status(200).json(response);

});

// ========================================
// LOGOUT UPDATED METHOD
// ========================================

app.post("/logout", (req, res) => {

  return res.json({
    status: "success",
    message:
      "Logout successful"
  });

});

// ========================================
// START SERVER
// ========================================

app.listen(PORT, () => {

  console.log(
    `Server running on port ${PORT}`
  );

});
