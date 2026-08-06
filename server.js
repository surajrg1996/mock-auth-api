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
// MOCK DSL API (BASIC AUTH)
// ========================================

app.post("/mock/dsl", (req, res) => {
  // ----------------------------------------
  // BASIC AUTHENTICATION
  // ----------------------------------------

  const credentials = basicAuth(req);

  if (!credentials) {
    return res.status(401).json({
      Result: {
        Success: "Trigger initiation failed",
        Error: "Authorization header missing"
      }
    });
  }

  const user = users.find(
    user =>
      user.username === credentials.name &&
      user.password === credentials.pass
  );

  if (!user) {
    return res.status(401).json({
      Result: {
        Success: "Trigger initiation failed",
        Error: "Invalid username/password"
      }
    });
  }

  try {
    // ----------------------------------------
    // PARSE REQUEST BODY
    // ----------------------------------------

    let incomingPayload = req.body;

    /*
     * Handles a request sent as an escaped JSON string:
     *
     * "{\"message\":{\"order_number\":\"123\"}}"
     */
    if (typeof incomingPayload === "string") {
      try {
        incomingPayload = JSON.parse(incomingPayload);
      } catch {
        return res.status(400).json({
          Result: {
            Success: "Trigger initiation failed",
            Error: "Request body is not valid JSON"
          }
        });
      }
    }

    if (
      !incomingPayload ||
      typeof incomingPayload !== "object"
    ) {
      return res.status(400).json({
        Result: {
          Success: "Trigger initiation failed",
          Error: "Request body must be a JSON object"
        }
      });
    }

    /*
     * Lynx sends business fields inside "message".
     * This also supports flat request bodies.
     */
    const lynxMessage =
      incomingPayload.message || incomingPayload;

    // ----------------------------------------
    // HELPER FUNCTIONS
    // ----------------------------------------

    function extractDate(value) {
      /*
       * Handles MongoDB Extended JSON:
       *
       * {
       *   "$date": "2026-08-06T15:23:02.728Z"
       * }
       */
      if (
        value &&
        typeof value === "object" &&
        value.$date
      ) {
        return value.$date;
      }

      return value;
    }

    function extractObjectId(value) {
      /*
       * Handles MongoDB Extended JSON:
       *
       * {
       *   "$oid": "6a74a6dadd9ad1f816eb9415"
       * }
       */
      if (
        value &&
        typeof value === "object" &&
        value.$oid
      ) {
        return value.$oid;
      }

      return value || null;
    }

    function convertToBoolean(value) {
      if (typeof value === "boolean") {
        return value;
      }

      return ["true", "1", "yes", "y"].includes(
        String(value).toLowerCase()
      );
    }

    function createObjectId() {
      return (
        Date.now().toString(16) +
        Math.random()
          .toString(16)
          .substring(2)
      )
        .substring(0, 24)
        .padEnd(24, "0");
    }

    function formatDate(date) {
      return date
        .toISOString()
        .replace("T", " ")
        .replace("Z", "+00:00");
    }

    // ----------------------------------------
    // NORMALIZE LYNX REQUEST FIELDS
    // ----------------------------------------

    const dsl_flag =
      lynxMessage.dsl_flag;

    const order_number =
      lynxMessage.order_number;

    const delivery_country =
      lynxMessage.delivery_country ||
      lynxMessage.country;

    const delivery_postal_code =
      lynxMessage.delivery_postal_code ||
      lynxMessage.postal;

    const line_number =
      lynxMessage.line_number;

    const order_qty =
      lynxMessage.order_qty ||
      lynxMessage.quantity;

    const actual_time = extractDate(
      lynxMessage.actual_time
    );

    const flow_type =
      lynxMessage.flow_type;

    const order_type =
      lynxMessage.order_type ||
      lynxMessage.avnet_order_type;

    const current_state =
      lynxMessage.current_state;

    const priority =
      lynxMessage.priority;

    const part_number =
      lynxMessage.part_number;

    const tenant =
      lynxMessage.tenant;

    /*
     * delivery_state is not present in the sample
     * Lynx message, so use N/A when it is missing.
     */
    const delivery_state =
      lynxMessage.delivery_state ||
      lynxMessage.state ||
      "N/A";

    const delivery_city =
      lynxMessage.delivery_city ||
      lynxMessage.city;

    const autoprocess = convertToBoolean(
      incomingPayload.autoprocess ??
      lynxMessage.autoprocess ??
      false
    );

    const prioritize = convertToBoolean(
      incomingPayload.prioritize ??
      lynxMessage.prioritize ??
      false
    );

    const rstx_message_id = extractObjectId(
      incomingPayload.rstx_message_id
    );

    const rstx_timestamp = extractDate(
      incomingPayload.rstx_timestamp
    );

    const rstx_messtype =
      incomingPayload.rstx_messtype || null;

    // ----------------------------------------
    // VALIDATE REQUIRED FIELDS
    // ----------------------------------------

    const requiredFields = {
      dsl_flag,
      order_number,
      delivery_country,
      delivery_postal_code,
      line_number,
      order_qty,
      actual_time,
      flow_type,
      order_type,
      current_state,
      priority,
      part_number,
      tenant,
      delivery_city
    };

    const missingFields = Object.entries(
      requiredFields
    )
      .filter(
        ([, value]) =>
          value === undefined ||
          value === null ||
          value === ""
      )
      .map(([field]) => field);

    if (missingFields.length > 0) {
      return res.status(400).json({
        Result: {
          Success: "Trigger initiation failed",
          Error:
            `Missing required fields: ${missingFields.join(", ")}`
        }
      });
    }

    const requestedQuantity = Number(order_qty);

    if (
      !Number.isInteger(requestedQuantity) ||
      requestedQuantity <= 0
    ) {
      return res.status(400).json({
        Result: {
          Success: "Trigger initiation failed",
          Error:
            "quantity must be a positive integer"
        }
      });
    }

    // ----------------------------------------
    // DUMMY INVENTORY
    // ----------------------------------------

    const dummyInventory = [
      {
        returnedPartNumber: "X0625",
        onHandInventory: 5,
        substituteFlag: "Y",
        chain: "Alternate",
        materialDescription:
          "TOWER ASSY,CONTROLLER, ROHS,1.4.0",
        materialType: "Interchangeable"
      },
      {
        returnedPartNumber: "X0660",
        onHandInventory: 2,
        substituteFlag: "Y",
        chain: "Alternate",
        materialDescription:
          "TOWER ASSY, CONTROLLER,ROHS",
        materialType: "Interchangeable"
      },
      {
        returnedPartNumber: "X0805",
        onHandInventory: 5,
        substituteFlag: "Y",
        chain: "Alternate",
        materialDescription:
          "TOWER ASSY, SLAVE,ROHS,1.4.2",
        materialType: "Interchangeable"
      },
      {
        /*
         * Master part comes from the Lynx request.
         */
        returnedPartNumber:
          String(part_number),

        onHandInventory: 3,
        substituteFlag: "N",
        chain: "Master",
        materialDescription:
          "Requested master material",
        materialType: "Not Replaced"
      }
    ];

    /*
     * If dsl_flag is explicitly N, return only the
     * requested master part.
     *
     * For values such as "LynX Order Creation",
     * return master and alternate parts.
     */
    const includeSubstitutes =
      String(dsl_flag).toUpperCase() !== "N";

    const inventory = includeSubstitutes
      ? dummyInventory
      : dummyInventory.filter(
          item => item.chain === "Master"
        );

    // ----------------------------------------
    // QUANTITY AVAILABILITY
    // ----------------------------------------

    const totalChainOnHand = inventory.reduce(
      (total, item) =>
        total + item.onHandInventory,
      0
    );

    const stockAvailable =
      totalChainOnHand >= requestedQuantity;

    const failureReason = stockAvailable
      ? null
      : `Requested quantity ${requestedQuantity} exceeds available quantity ${totalChainOnHand}`;

    // ----------------------------------------
    // CREATE DSL RESPONSE LINE ITEMS
    // ----------------------------------------

    const dslResponseLineItem = inventory.map(
      item => ({
        orderLineItemId:
          String(line_number),

        requestedPartNumber:
          String(part_number),

        sourceInventoryLocation: "ONT",

        availability: stockAvailable
          ? String(order_type)
          : "UNAVAILABLE",

        substituteFlag:
          item.substituteFlag,

        failureReason,

        returnedPartNumber:
          item.returnedPartNumber,

        locationStatus: "OPEN",
        distanceMiles: "703",
        travelTime: "13.85",

        onHandInventory:
          String(item.onHandInventory),

        masterMaterial:
          String(part_number),

        region: "GBX-DC",
        replenishmentMin: "13",
        replenishmentMax: "14",

        totalChainOnHand:
          String(totalChainOnHand),

        echelon: stockAvailable
          ? "Next Day Downgrade - US DC"
          : "Inventory Unavailable",

        meetsGoal: stockAvailable
          ? "Y"
          : "N",

        chain: item.chain,

        materialDescription:
          item.materialDescription,

        materialType:
          item.materialType,

        siteCountry:
          String(delivery_country),

        siteState:
          String(delivery_state),

        sitePostalCode:
          String(delivery_postal_code),

        preferredSource: "Y",

        siteLocation:
          String(delivery_city),

        distanceKilometers: "1130"
      })
    );

    // ----------------------------------------
    // TRIGGER VALUES
    // ----------------------------------------

    const generatedAt =
      formatDate(new Date());

    const triggerId =
      createObjectId();

    // ----------------------------------------
    // FINAL RESPONSE
    // ----------------------------------------

    const response = {
      Result: {
        Success:
          "Trigger/s initiated successfully",

        DSLResponse: {
          "@xmlns:ns2":
            "https://mock-auth-api.onrender.com/mock/dsl",

          dslResponseHeader: {
            orderHeaderId:
              String(order_number)
          },

          dslResponseLineItemList: {
            dslResponseLineItem
          }
        },

        triggers: [
          {
            generated_at: generatedAt,
            processed: false,

            message_id:
              rstx_message_id,

            trigger: {
              order_number:
                String(order_number),

              line_number:
                Number(line_number),

              actual_time:
                String(actual_time),

              stock_available:
                stockAvailable,

              requested_quantity:
                requestedQuantity,

              total_available_quantity:
                totalChainOnHand,

              part_number:
                String(part_number),

              flow_type:
                String(flow_type),

              order_type:
                String(order_type),

              current_state:
                String(current_state),

              priority:
                String(priority),

              tenant:
                String(tenant),

              autoprocess,
              prioritize
            },

            rstx_timestamp:
              rstx_timestamp || null,

            rstx_messtype:
              rstx_messtype,

            _id: triggerId
          }
        ]
      }
    };

    // ----------------------------------------
    // LOG REQUEST AND RESPONSE
    // ----------------------------------------

    console.log("========== MOCK DSL ==========");
    console.log(
      "Authenticated User:",
      user.username
    );
    console.log("Incoming payload:");
    console.log(
      JSON.stringify(incomingPayload, null, 2)
    );
    console.log(
      "Requested Quantity:",
      requestedQuantity
    );
    console.log(
      "Available Quantity:",
      totalChainOnHand
    );
    console.log(
      "Stock Available:",
      stockAvailable
    );
    console.log("DSL response:");
    console.log(
      JSON.stringify(response, null, 2)
    );
    console.log("==============================");

    return res.status(200).json(response);
  } catch (error) {
    console.error(
      "Mock DSL processing error:",
      error
    );

    return res.status(500).json({
      Result: {
        Success: "Trigger initiation failed",
        Error: error.message
      }
    });
  }
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
