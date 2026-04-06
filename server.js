require("dotenv").config();

const express = require("express");
const admin = require("firebase-admin");
const path = require("path");
const crypto = require("crypto");

const app = express();
const port = Number(process.env.PORT) || 3000;

const PINATA_JWT = process.env.PINATA_JWT;
const PINATA_GROUP_NAME = process.env.PINATA_GROUP_NAME || "My Uploads";
const DEFAULT_GATEWAY = "gateway.pinata.cloud";
const FIREBASE_PROJECT_ID = process.env.FIREBASE_PROJECT_ID || "";
const FIREBASE_CLIENT_EMAIL = process.env.FIREBASE_CLIENT_EMAIL || "";
const FIREBASE_PRIVATE_KEY = process.env.FIREBASE_PRIVATE_KEY || "";
const ADMIN_ACCESS_KEY = process.env.ADMIN_ACCESS_KEY || "";
const ADMIN_COOKIE_NAME = "dexstorage_admin";
const PINATA_SIGNED_UPLOAD_EXPIRY_SECONDS = 15 * 60;
const MAX_DIRECT_UPLOAD_SIZE = 1024 * 1024 * 1024;

let cachedGroupId = null;
let cachedGatewayHost = process.env.PINATA_GATEWAY_HOST || "";
let firestore = null;

app.use(
  express.static(path.join(__dirname, "public"), {
    index: false,
  })
);
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false }));

function getHeaders(extra = {}) {
  if (!PINATA_JWT) {
    throw new Error("PINATA_JWT is missing. Add it to your environment variables.");
  }

  return {
    Authorization: `Bearer ${PINATA_JWT}`,
    ...extra,
  };
}

function getFirestore() {
  if (!FIREBASE_PROJECT_ID || !FIREBASE_CLIENT_EMAIL || !FIREBASE_PRIVATE_KEY) {
    throw new Error(
      "Firebase credentials are missing. Add FIREBASE_PROJECT_ID, FIREBASE_CLIENT_EMAIL, and FIREBASE_PRIVATE_KEY."
    );
  }

  if (!admin.apps.length) {
    admin.initializeApp({
      credential: admin.credential.cert({
        projectId: FIREBASE_PROJECT_ID,
        clientEmail: FIREBASE_CLIENT_EMAIL,
        privateKey: FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n"),
      }),
    });
  }

  if (!firestore) {
    firestore = admin.firestore();
  }

  return firestore;
}

function parseCookies(req) {
  const raw = req.headers.cookie || "";

  return raw.split(";").reduce((acc, item) => {
    const [key, ...rest] = item.trim().split("=");
    if (!key) {
      return acc;
    }

    acc[key] = decodeURIComponent(rest.join("=") || "");
    return acc;
  }, {});
}

function getAdminCookieValue() {
  return encodeURIComponent(ADMIN_ACCESS_KEY);
}

function isAdminAuthenticated(req) {
  if (!ADMIN_ACCESS_KEY) {
    return false;
  }

  const cookies = parseCookies(req);
  return cookies[ADMIN_COOKIE_NAME] === ADMIN_ACCESS_KEY;
}

function requireAdmin(req, res, next) {
  if (!ADMIN_ACCESS_KEY) {
    return res.status(500).send("ADMIN_ACCESS_KEY is missing. Add it to your environment variables.");
  }

  if (!isAdminAuthenticated(req)) {
    return res.redirect("/admin");
  }

  return next();
}

function renderAccessGate({ code = "", errorMessage = "" } = {}) {
  const safeCode = escapeHtml(code);
  const safeError = escapeHtml(errorMessage);

  return `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Protected File Access</title>
    <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link
      href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;700&display=swap"
      rel="stylesheet"
    />
    <style>
      body {
        margin: 0;
        font-family: "Space Grotesk", sans-serif;
        background:
          radial-gradient(circle at top left, rgba(0, 0, 0, 0.05), transparent 30%),
          linear-gradient(135deg, #ffffff, #f4f4f4);
        color: #000;
      }
      .wrap {
        width: min(560px, calc(100% - 24px));
        margin: 0 auto;
        padding: 32px 0;
      }
      h1 {
        margin: 0 0 16px;
        font-size: clamp(1.6rem, 4vw, 2.4rem);
      }
      .card {
        padding: 18px;
        border: 1px solid rgba(0, 0, 0, 0.12);
        background: rgba(255, 255, 255, 0.96);
        box-shadow: 0 24px 60px rgba(0, 0, 0, 0.08);
      }
      label {
        display: grid;
        gap: 8px;
      }
      input {
        min-height: 46px;
        padding: 0 12px;
        border: 1px solid rgba(0, 0, 0, 0.12);
        font: inherit;
      }
      button {
        margin-top: 12px;
        min-height: 42px;
        padding: 0 14px;
        border: 0;
        background: #000;
        color: #fff;
        font: inherit;
        cursor: pointer;
      }
      p {
        color: #666;
      }
      .error {
        margin: 0 0 12px;
        color: #b42318;
      }
    </style>
  </head>
  <body>
    <main class="wrap">
      <h1>Protected File Access</h1>
      <div class="card">
        ${safeError ? `<p class="error">${safeError}</p>` : ""}
        <form method="post" action="/access/${safeCode}">
          <label>
            <span>Access key</span>
            <input type="password" name="key" placeholder="Enter access key" required />
          </label>
          <button type="submit">Open File</button>
        </form>
        <p>This shared page is protected. Enter the access key to continue.</p>
      </div>
    </main>
  </body>
</html>`;
}

async function readJson(response) {
  const text = await response.text();

  try {
    return text ? JSON.parse(text) : {};
  } catch (error) {
    return { message: text || "Invalid JSON response from Pinata." };
  }
}

async function pinataRequest(url, options = {}) {
  const response = await fetch(url, options);
  const data = await readJson(response);

  if (!response.ok) {
    const message =
      data.error?.reason ||
      data.error?.details ||
      data.message ||
      "Pinata request failed.";

    throw new Error(message);
  }

  return data;
}

async function getGatewayHost() {
  if (cachedGatewayHost) {
    return cachedGatewayHost;
  }

  try {
    const data = await pinataRequest("https://api.pinata.cloud/v3/gateways", {
      method: "GET",
      headers: getHeaders(),
    });

    const firstGateway = data.data?.rows?.[0];
    const customDomain = firstGateway?.custom_domains?.[0]?.domain;

    if (customDomain) {
      cachedGatewayHost = customDomain;
      return cachedGatewayHost;
    }

    if (firstGateway?.domain) {
      cachedGatewayHost = `${firstGateway.domain}.mypinata.cloud`;
      return cachedGatewayHost;
    }
  } catch (error) {
    console.warn("Gateway discovery failed, using fallback gateway.", error.message);
  }

  cachedGatewayHost = DEFAULT_GATEWAY;
  return cachedGatewayHost;
}

async function getOrCreateGroupId() {
  if (cachedGroupId) {
    return cachedGroupId;
  }

  const lookup = await pinataRequest(
    `https://api.pinata.cloud/v3/groups/public?name=${encodeURIComponent(PINATA_GROUP_NAME)}&limit=10`,
    {
      method: "GET",
      headers: getHeaders(),
    }
  );

  const existingGroup = lookup.data?.groups?.find(
    (group) => group.name.toLowerCase() === PINATA_GROUP_NAME.toLowerCase()
  );

  if (existingGroup) {
    cachedGroupId = existingGroup.id;
    return cachedGroupId;
  }

  const created = await pinataRequest("https://api.pinata.cloud/v3/groups/public", {
    method: "POST",
    headers: getHeaders({
      "Content-Type": "application/json",
    }),
    body: JSON.stringify({
      name: PINATA_GROUP_NAME,
      is_public: true,
    }),
  });

  cachedGroupId = created.data?.id;
  return cachedGroupId;
}

function buildBaseUrl(req) {
  return `${req.protocol}://${req.get("host")}`;
}

function buildShortLink(req, shortCode) {
  return `${buildBaseUrl(req)}/s/${shortCode}`;
}

function isImageName(fileName = "") {
  return /\.(png|jpe?g|gif|webp|bmp|svg|avif)$/i.test(fileName);
}

function isTextLikeFile(fileName = "", contentType = "") {
  if (contentType.startsWith("text/")) {
    return true;
  }

  return /\.(txt|md|json|ya?ml|xml|csv|scv|log|js|ts|jsx|tsx|css|html|py|java|c|cpp|sh)$/i.test(fileName);
}

function isCsvFile(fileName = "", contentType = "") {
  return contentType.includes("text/csv") || /\.(csv|scv)$/i.test(fileName);
}

function isPlainTextFile(fileName = "", contentType = "") {
  if (isCsvFile(fileName, contentType)) {
    return false;
  }

  if (contentType.startsWith("text/")) {
    return true;
  }

  return /\.(txt|md|log)$/i.test(fileName);
}

function isAllowedUpload(fileName = "", contentType = "") {
  return isCsvFile(fileName, contentType) || isPlainTextFile(fileName, contentType);
}

function parseCsv(text) {
  const rows = [];
  let row = [];
  let value = "";
  let inQuotes = false;

  for (let i = 0; i < text.length; i += 1) {
    const char = text[i];
    const next = text[i + 1];

    if (char === '"') {
      if (inQuotes && next === '"') {
        value += '"';
        i += 1;
      } else {
        inQuotes = !inQuotes;
      }
      continue;
    }

    if (char === "," && !inQuotes) {
      row.push(value);
      value = "";
      continue;
    }

    if ((char === "\n" || char === "\r") && !inQuotes) {
      if (char === "\r" && next === "\n") {
        i += 1;
      }

      row.push(value);
      rows.push(row);
      row = [];
      value = "";
      continue;
    }

    value += char;
  }

  if (value.length || row.length) {
    row.push(value);
    rows.push(row);
  }

  return rows.filter((currentRow) => currentRow.length && currentRow.some((cell) => cell !== ""));
}

function escapeHtml(value = "") {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function buildGatewayLinks(host, rootCid, storedPath, displayName) {
  const encodedName = encodeURIComponent(displayName);
  const baseUrl = `https://${host}/ipfs/${rootCid}`;

  return {
    page: `${baseUrl}?filename=${encodedName}`,
    image: `${baseUrl}?filename=${encodedName}`,
    download: `${baseUrl}?download=true&filename=${encodedName}`,
  };
}

async function uploadBufferToPinata({ buffer, contentType, originalName }) {
  const gatewayHost = await getGatewayHost();
  const formData = new FormData();
  const blob = new Blob([buffer], { type: contentType || "application/octet-stream" });
  const storedName = createStoredName(originalName);

  formData.append("network", "public");
  formData.append("name", storedName);
  formData.append("keyvalues", JSON.stringify({ source: "file-upload-app" }));
  formData.append("file", blob, originalName);

  const uploadResult = await pinataRequest("https://uploads.pinata.cloud/v3/files", {
    method: "POST",
    headers: getHeaders(),
    body: formData,
  });

  const file = uploadResult.data;
  const links = buildGatewayLinks(gatewayHost, file.cid, storedName, originalName);

  return {
    success: true,
    file: {
      id: file.id,
      cid: file.cid,
      name: originalName,
      storedName,
      storedPath: storedName,
      size: file.size,
      type: contentType,
      groupId: file.group_id || null,
      createdAt: file.created_at,
    },
    links,
  };
}

function createStoredName(originalName) {
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  return `${timestamp}-${originalName}`;
}

function extractSignedUploadId(signedUrl = "") {
  try {
    const parsed = new URL(signedUrl);
    const parts = parsed.pathname.split("/").filter(Boolean);
    return parts[parts.length - 1] || null;
  } catch (error) {
    return null;
  }
}

async function createSignedUploadUrl({ originalName, contentType, size }) {
  const storedName = createStoredName(originalName);
  const date = Math.floor(Date.now() / 1000);

  const response = await pinataRequest("https://uploads.pinata.cloud/v3/files/sign", {
    method: "POST",
    headers: getHeaders({
      "Content-Type": "application/json",
    }),
    body: JSON.stringify({
      date,
      expires: PINATA_SIGNED_UPLOAD_EXPIRY_SECONDS,
      network: "public",
      max_file_size: Math.max(size || 0, MAX_DIRECT_UPLOAD_SIZE),
      allow_mime_types: [contentType || "text/*"],
      keyvalues: {
        source: "file-upload-app",
      },
      filename: storedName,
    }),
  });

  return {
    signedUrl: response.data,
    fileId: extractSignedUploadId(response.data),
    storedName,
  };
}

async function getPinataFileById(fileId) {
  return pinataRequest(`https://api.pinata.cloud/v3/files/public/${fileId}`, {
    method: "GET",
    headers: getHeaders(),
  });
}

async function waitForPinataFile(fileId) {
  for (let attempt = 0; attempt < 8; attempt += 1) {
    const response = await getPinataFileById(fileId);
    const file = response.data;

    if (file?.cid) {
      return file;
    }

    await new Promise((resolve) => setTimeout(resolve, 500 * (attempt + 1)));
  }

  throw new Error("Pinata upload finished but file metadata is not ready yet. Please try again.");
}
function createLinkPayload(req, gatewayHost, rootCid, storedPath, displayName, shortCode) {
  const short = buildShortLink(req, shortCode);

  return {
    ...buildGatewayLinks(gatewayHost, rootCid, storedPath, displayName),
    page: short,
    short,
  };
}

function createShortCode() {
  return crypto.randomBytes(4).toString("base64url").toLowerCase();
}

async function createShortRecord({ cid, path: storedPath, name, type }) {
  const db = getFirestore();

  for (let attempt = 0; attempt < 5; attempt += 1) {
    const code = createShortCode();
    const ref = db.collection("short_links").doc(code);
    const existing = await ref.get();

    if (existing.exists) {
      continue;
    }

    await ref.set({
        cid,
        path: storedPath,
        name,
        type,
        createdAt: new Date().toISOString(),
      });

    return code;
  }

  throw new Error("Could not create a unique short URL.");
}

async function readShortRecord(code) {
  const db = getFirestore();
  const doc = await db.collection("short_links").doc(code).get();

  if (!doc.exists) {
    return null;
  }

  return doc.data();
}

async function updateShortRecord(code, updates) {
  const existing = await readShortRecord(code);

  if (!existing) {
    throw new Error("Short link not found.");
  }

  const nextValue = {
    ...existing,
    ...updates,
    updatedAt: new Date().toISOString(),
  };

  const db = getFirestore();
  await db.collection("short_links").doc(code).set(nextValue);
  return nextValue;
}

async function listShortRecords() {
  const db = getFirestore();
  const snapshot = await db.collection("short_links").orderBy("createdAt", "desc").get();

  return snapshot.docs.map((doc) => ({
    code: doc.id,
    ...doc.data(),
  }));
}

app.get("/api/health", async (_req, res) => {
  const gatewayHost = await getGatewayHost();

  res.json({
    ok: true,
    groupName: PINATA_GROUP_NAME,
    gatewayHost,
  });
});

app.get("/admin", (req, res) => {
  if (!ADMIN_ACCESS_KEY) {
    return res
      .status(500)
      .type("html")
      .send(`<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>decentrazile storage</title>
  </head>
  <body style="font-family: Arial, sans-serif; padding: 24px;">
    <p>ADMIN_ACCESS_KEY is missing.</p>
  </body>
</html>`);
  }

  if (isAdminAuthenticated(req)) {
    return res.redirect("/admin/files");
  }

  return res
    .status(200)
    .type("html")
    .send(`<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>decentrazile storage</title>
    <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link
      href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;700&display=swap"
      rel="stylesheet"
    />
    <style>
      body {
        margin: 0;
        font-family: "Space Grotesk", sans-serif;
        background:
          radial-gradient(circle at top left, rgba(0, 0, 0, 0.05), transparent 30%),
          linear-gradient(135deg, #ffffff, #f4f4f4);
        color: #000;
      }
      .wrap {
        width: min(560px, calc(100% - 24px));
        margin: 0 auto;
        padding: 32px 0;
      }
      h1 {
        margin: 0 0 16px;
        font-size: clamp(1.6rem, 4vw, 2.4rem);
      }
      .card {
        padding: 18px;
        border: 1px solid rgba(0, 0, 0, 0.12);
        background: rgba(255, 255, 255, 0.96);
        box-shadow: 0 24px 60px rgba(0, 0, 0, 0.08);
      }
      label {
        display: grid;
        gap: 8px;
      }
      input {
        min-height: 46px;
        padding: 0 12px;
        border: 1px solid rgba(0, 0, 0, 0.12);
        font: inherit;
      }
      button {
        margin-top: 12px;
        min-height: 42px;
        padding: 0 14px;
        border: 0;
        background: #000;
        color: #fff;
        font: inherit;
        cursor: pointer;
      }
      p {
        color: #666;
      }
    </style>
  </head>
  <body>
    <main class="wrap">
      <h1>decentrazile storage</h1>
      <div class="card">
        <form method="post" action="/admin/login">
          <label>
            <span>Admin access key</span>
            <input type="password" name="key" placeholder="Enter your admin key" required />
          </label>
          <button type="submit">Open Admin</button>
        </form>
        <p>Only you can access this page with the correct key.</p>
      </div>
    </main>
  </body>
</html>`);
});

app.get("/", (req, res) => {
  return res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.post("/admin/login", (req, res) => {
  if (!ADMIN_ACCESS_KEY) {
    return res.status(500).send("ADMIN_ACCESS_KEY is missing. Add it to your environment variables.");
  }

  if ((req.body?.key || "") !== ADMIN_ACCESS_KEY) {
    return res.redirect("/admin");
  }

  res.setHeader(
    "Set-Cookie",
    `${ADMIN_COOKIE_NAME}=${getAdminCookieValue()}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000`
  );

  return res.redirect("/admin/files");
});

app.post("/admin/logout", (_req, res) => {
  res.setHeader(
    "Set-Cookie",
    `${ADMIN_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`
  );

  return res.redirect("/admin");
});

app.get("/access/:code", (req, res) => {
  return res.redirect(`/s/${req.params.code}`);
});

app.post("/access/:code", (req, res) => {
  return res.redirect(`/s/${req.params.code}`);
});

app.get("/admin/files", requireAdmin, async (req, res) => {
  try {
    const records = await listShortRecords();
    const rows = records
      .map((record) => {
        const fileName = escapeHtml(record.name || "-");
        const shortCode = escapeHtml(record.code || "-");
        const cid = escapeHtml(record.cid || "-");
        const type = escapeHtml(record.type || "-");
        const createdAt = escapeHtml(record.createdAt || "-");
        const shortLink = escapeHtml(buildShortLink(req, record.code));

        return `<tr>
          <td><a href="/s/${shortCode}" target="_blank" rel="noreferrer">${shortCode}</a></td>
          <td>${fileName}</td>
          <td>${type}</td>
          <td class="cid">${cid}</td>
          <td>${createdAt}</td>
          <td><a href="${shortLink}" target="_blank" rel="noreferrer">Open</a></td>
        </tr>`;
      })
      .join("");

    return res
      .status(200)
      .type("html")
      .send(`<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>decentrazile storage</title>
    <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link
      href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;700&display=swap"
      rel="stylesheet"
    />
    <style>
      body {
        margin: 0;
        font-family: "Space Grotesk", sans-serif;
        background:
          radial-gradient(circle at top left, rgba(0, 0, 0, 0.05), transparent 30%),
          linear-gradient(135deg, #ffffff, #f4f4f4);
        color: #000;
      }
      .wrap {
        width: min(1480px, calc(100% - 20px));
        margin: 0 auto;
        padding: 18px 0 24px;
      }
      .topbar {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 12px;
        margin-bottom: 12px;
      }
      .brand {
        color: #000;
        text-decoration: none;
      }
      .title {
        margin: 0;
        font-size: clamp(1.2rem, 2.8vw, 2rem);
      }
      .logout {
        min-height: 36px;
        padding: 0 12px;
        border: 0;
        background: #000;
        color: #fff;
        font: inherit;
        cursor: pointer;
      }
      .panel {
        padding: 10px;
        border: 1px solid rgba(0, 0, 0, 0.12);
        background: rgba(255, 255, 255, 0.96);
        box-shadow: 0 24px 60px rgba(0, 0, 0, 0.08);
      }
      .table-wrap {
        overflow: auto;
        border: 1px solid rgba(0, 0, 0, 0.12);
        background: #fff;
      }
      table {
        width: 100%;
        min-width: 980px;
        border-collapse: collapse;
      }
      th, td {
        padding: 10px 12px;
        border-bottom: 1px solid rgba(0, 0, 0, 0.12);
        border-right: 1px solid rgba(0, 0, 0, 0.12);
        text-align: left;
        vertical-align: top;
        font-size: 0.92rem;
      }
      th {
        position: sticky;
        top: 0;
        background: #f7f7f7;
      }
      tr:nth-child(even) td {
        background: rgba(0, 0, 0, 0.015);
      }
      .cid {
        font-family: Consolas, Monaco, monospace;
        font-size: 0.84rem;
      }
      a {
        color: #000;
      }
      @media (max-width: 720px) {
        .wrap {
          width: calc(100% - 12px);
          padding: 8px 0 16px;
        }
        th, td {
          padding: 8px 10px;
          font-size: 0.84rem;
        }
      }
    </style>
  </head>
  <body>
    <main class="wrap">
      <div class="topbar">
        <a class="brand" href="/"><h1 class="title">decentrazile storage</h1></a>
        <form method="post" action="/admin/logout">
          <button class="logout" type="submit">Logout</button>
        </form>
      </div>
      <section class="panel">
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Short Code</th>
                <th>File Name</th>
                <th>Type</th>
                <th>CID</th>
                <th>Created</th>
                <th>Open</th>
              </tr>
            </thead>
            <tbody>
              ${rows || `<tr><td colspan="6">No files found.</td></tr>`}
            </tbody>
          </table>
        </div>
      </section>
    </main>
  </body>
</html>`);
  } catch (error) {
    return res.status(500).send(error.message || "Could not load admin files.");
  }
});

app.post("/api/links", async (req, res) => {
  const cid = req.body?.cid;
  const storedPath = req.body?.path;
  const originalName = req.body?.name;
  const shortCode = req.body?.shortCode;

  if (!cid || !storedPath || !originalName || !shortCode) {
    return res.status(400).json({
      error: "CID, stored path, file name, and short code are required.",
    });
  }

  try {
    const gatewayHost = await getGatewayHost();
    await updateShortRecord(shortCode, { cid, path: storedPath, name: originalName });

    return res.json({
      links: createLinkPayload(req, gatewayHost, cid, storedPath, originalName, shortCode),
    });
  } catch (error) {
    return res.status(500).json({
      error: error.message || "Could not generate links.",
    });
  }
});

async function handleShortLink(req, res) {
  try {
    const record = await readShortRecord(req.params.code);

    if (!record?.cid) {
      return res.status(404).send("Short link not found.");
    }

    const gatewayHost = await getGatewayHost();
    const fileName = record.name || "image";
    const storedPath = record.path || fileName;
    const links = buildGatewayLinks(gatewayHost, record.cid, storedPath, fileName);
    const escapedName = escapeHtml(fileName);

    if (isTextLikeFile(fileName, record.type || "")) {
      let fileContent = "Could not load file preview.";

      try {
        const textResponse = await fetch(links.image);
        if (textResponse.ok) {
          fileContent = await textResponse.text();
        }
      } catch (fetchError) {
        fileContent = "Could not load file preview.";
      }

      const escapedContent = escapeHtml(fileContent);

      if (isCsvFile(fileName, record.type || "")) {
        const csvRows = parseCsv(fileContent);
        const headerRow = csvRows[0] || [];
        const bodyRows = csvRows.slice(1);
        const tableHead = headerRow
          .map((cell) => `<th>${escapeHtml(cell)}</th>`)
          .join("");
        const tableBody = bodyRows
          .map(
            (currentRow) =>
              `<tr>${currentRow.map((cell) => `<td>${escapeHtml(cell)}</td>`).join("")}</tr>`
          )
          .join("");

        return res
          .status(200)
          .type("html")
          .send(`<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>decentrazile storage</title>
    <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link
      href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;700&display=swap"
      rel="stylesheet"
    />
    <style>
      :root {
        color-scheme: light;
        --text: #000000;
        --muted: #666666;
        --line: rgba(0, 0, 0, 0.12);
        --soft: #f7f7f7;
      }
      * { box-sizing: border-box; }
      body {
        margin: 0;
        font-family: "Space Grotesk", sans-serif;
        background:
          radial-gradient(circle at top left, rgba(0, 0, 0, 0.05), transparent 30%),
          linear-gradient(135deg, #ffffff, #f4f4f4);
        color: var(--text);
      }
      .wrap {
        width: min(1440px, calc(100% - 20px));
        margin: 0 auto;
        padding: 16px 0 24px;
      }
      .topbar {
        display: flex;
        align-items: center;
        margin-bottom: 10px;
      }
      .brand {
        color: var(--text);
        text-decoration: none;
      }
      .name {
        margin: 0;
        font-size: clamp(1.2rem, 2.8vw, 2rem);
        line-height: 1;
      }
      .panel {
        margin-top: 14px;
        padding: 12px;
        border: 1px solid var(--line);
        background: rgba(255, 255, 255, 0.96);
        box-shadow: 0 24px 60px rgba(0, 0, 0, 0.08);
      }
      .csv-wrap {
        overflow: auto;
        border: 1px solid var(--line);
        background: #ffffff;
      }
      table {
        width: 100%;
        border-collapse: collapse;
        min-width: 760px;
      }
      th, td {
        padding: 6px 10px;
        border-bottom: 1px solid var(--line);
        border-right: 1px solid var(--line);
        text-align: left;
        vertical-align: top;
        font-size: 1rem;
        white-space: nowrap;
        line-height: 1.35;
      }
      th {
        position: sticky;
        top: 0;
        background: var(--soft);
        font-weight: 700;
      }
      tr:nth-child(even) td {
        background: rgba(0, 0, 0, 0.015);
      }
      .actions {
        display: flex;
        flex-wrap: wrap;
        gap: 6px;
        margin-top: 10px;
      }
      .btn {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        min-height: 34px;
        padding: 0 10px;
        color: #ffffff;
        background: #000000;
        text-decoration: none;
        font-size: 0.84rem;
      }
      .btn.secondary {
        background: #ffffff;
        color: #000000;
        border: 1px solid var(--line);
      }
      @media (max-width: 720px) {
        .wrap {
          width: calc(100% - 12px);
          padding: 8px 0 16px;
        }
        .panel {
          padding: 8px;
        }
        th, td {
          padding: 5px 8px;
          font-size: 0.76rem;
        }
        .btn {
          min-height: 32px;
          padding: 0 9px;
          font-size: 0.8rem;
        }
      }
    </style>
  </head>
  <body>
    <main class="wrap">
      <div class="topbar">
        <a class="brand" href="/"><h1 class="name">decentrazile storage</h1></a>
      </div>
      <section class="panel">
        <div class="csv-wrap">
          <table>
            <thead>
              <tr>${tableHead}</tr>
            </thead>
            <tbody>
              ${tableBody}
            </tbody>
          </table>
        </div>
        <div class="actions">
          <a class="btn" href="${links.image}" target="_blank" rel="noreferrer">Open Direct File</a>
          <a class="btn secondary" href="${links.download}" target="_blank" rel="noreferrer">Download</a>
        </div>
      </section>
    </main>
  </body>
</html>`);
      }

      return res
        .status(200)
        .type("html")
        .send(`<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>decentrazile storage</title>
    <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link
      href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;700&display=swap"
      rel="stylesheet"
    />
    <style>
      :root {
        color-scheme: light;
        --text: #000000;
        --muted: #666666;
        --line: rgba(0, 0, 0, 0.12);
      }
      * { box-sizing: border-box; }
      body {
        margin: 0;
        font-family: "Space Grotesk", sans-serif;
        background:
          radial-gradient(circle at top left, rgba(0, 0, 0, 0.05), transparent 30%),
          linear-gradient(135deg, #ffffff, #f4f4f4);
        color: var(--text);
      }
      .wrap {
        width: min(1320px, calc(100% - 20px));
        margin: 0 auto;
        padding: 16px 0 24px;
      }
      .topbar {
        display: flex;
        align-items: center;
        margin-bottom: 10px;
      }
      .brand {
        color: var(--text);
        text-decoration: none;
      }
      .name {
        margin: 0;
        font-size: clamp(1.2rem, 2.8vw, 2rem);
        line-height: 1;
      }
      .panel {
        margin-top: 14px;
        padding: 12px;
        border: 1px solid var(--line);
        background: rgba(255, 255, 255, 0.96);
        box-shadow: 0 24px 60px rgba(0, 0, 0, 0.08);
        position: relative;
      }
      .copy-top {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        min-height: 34px;
        padding: 0 10px;
        color: #ffffff;
        background: #000000;
        border: 0;
        cursor: pointer;
        font: inherit;
        font-size: 0.84rem;
        position: absolute;
        top: 12px;
        right: 12px;
      }
      .content {
        margin: 0;
        padding: 16px;
        padding-top: 54px;
        overflow: auto;
        white-space: pre-wrap;
        word-break: break-word;
        background: #ffffff;
        border: 1px solid var(--line);
        font: 0.96rem/1.55 Consolas, Monaco, monospace;
      }
      .actions {
        display: flex;
        flex-wrap: wrap;
        gap: 6px;
        margin-top: 10px;
      }
      .btn {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        min-height: 34px;
        padding: 0 10px;
        color: #ffffff;
        background: #000000;
        text-decoration: none;
        font-size: 0.84rem;
      }
      .btn.secondary {
        background: #ffffff;
        color: #000000;
        border: 1px solid var(--line);
      }
      @media (max-width: 720px) {
        .wrap {
          width: calc(100% - 12px);
          padding: 8px 0 16px;
        }
        .panel {
          padding: 8px;
        }
        .copy-top {
          top: 8px;
          right: 8px;
          min-height: 32px;
          padding: 0 9px;
          font-size: 0.8rem;
        }
        .content {
          padding: 12px;
          padding-top: 48px;
          font-size: 0.86rem;
        }
        .btn {
          min-height: 32px;
          padding: 0 9px;
          font-size: 0.8rem;
        }
        .copy-top {
          min-height: 32px;
          padding: 0 9px;
          font-size: 0.8rem;
        }
      }
    </style>
  </head>
  <body>
    <main class="wrap">
      <div class="topbar">
        <a class="brand" href="/"><h1 class="name">Ranjeet decentrazile storage</h1></a>
      </div>
      <section class="panel">
        <button class="copy-top" id="copyTextButton" type="button">Copy</button>
        <pre class="content" id="textContent">${escapedContent}</pre>
        <div class="actions">
          <a class="btn" href="${links.image}" target="_blank" rel="noreferrer">Open Direct File</a>
          <a class="btn secondary" href="${links.download}" target="_blank" rel="noreferrer">Download</a>
        </div>
      </section>
    </main>
    <script>
      const copyButton = document.getElementById("copyTextButton");
      const textContent = document.getElementById("textContent");

      copyButton.addEventListener("click", async () => {
        try {
          await navigator.clipboard.writeText(textContent.textContent || "");
          copyButton.textContent = "Copied";
          setTimeout(() => {
            copyButton.textContent = "Copy";
          }, 1200);
        } catch (error) {
          copyButton.textContent = "Failed";
          setTimeout(() => {
            copyButton.textContent = "Copy";
          }, 1200);
        }
      });
    </script>
  </body>
</html>`);
    }

    if (!isImageName(fileName) && !(record.type || "").startsWith("image/")) {
      return res.redirect(links.image);
    }

    return res
      .status(200)
      .type("html")
      .send(`<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>decentrazile storage</title>
    <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link
      href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;700&display=swap"
      rel="stylesheet"
    />
    <style>
      :root {
        color-scheme: light;
        --bg: #ffffff;
        --text: #000000;
        --muted: #666666;
        --line: rgba(0, 0, 0, 0.12);
      }
      * { box-sizing: border-box; }
      body {
        margin: 0;
        font-family: "Space Grotesk", sans-serif;
        background:
          radial-gradient(circle at top left, rgba(0, 0, 0, 0.05), transparent 30%),
          linear-gradient(135deg, #ffffff, #f2f2f2);
        color: var(--text);
      }
      .wrap {
        width: min(1320px, calc(100% - 20px));
        margin: 0 auto;
        padding: 16px 0 24px;
      }
      .topbar {
        display: flex;
        align-items: center;
        margin-bottom: 10px;
      }
      .brand {
        color: var(--text);
        text-decoration: none;
      }
      .name {
        margin: 0;
        font-size: clamp(1.2rem, 2.8vw, 2rem);
        word-break: break-word;
        line-height: 1;
      }
      .panel {
        margin-top: 14px;
        padding: 10px;
        border: 1px solid var(--line);
        border-radius: 0;
        background: rgba(255, 255, 255, 0.95);
        box-shadow: 0 24px 60px rgba(0, 0, 0, 0.08);
      }
      .preview {
        display: block;
        width: 100%;
        max-height: 80vh;
        object-fit: contain;
        border-radius: 0;
        background: #ffffff;
      }
      .actions {
        display: flex;
        flex-wrap: wrap;
        gap: 6px;
        margin-top: 10px;
      }
      .btn {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        min-height: 34px;
        padding: 0 10px;
        color: #ffffff;
        background: #000000;
        text-decoration: none;
        font-size: 0.84rem;
      }
      .btn.secondary {
        background: #ffffff;
        color: #000000;
        border: 1px solid var(--line);
      }
      @media (max-width: 720px) {
        .wrap {
          width: calc(100% - 12px);
          padding: 8px 0 16px;
        }
        .panel {
          padding: 6px;
        }
        .preview {
          max-height: 68vh;
        }
        .actions {
          gap: 6px;
          margin-top: 8px;
        }
        .btn {
          min-height: 32px;
          padding: 0 9px;
          font-size: 0.8rem;
        }
      }
    </style>
  </head>
  <body>
    <main class="wrap">
      <div class="topbar">
        <a class="brand" href="/"><h1 class="name">Ranjeet decentrazile storage</h1></a>
      </div>
      <section class="panel">
        <img class="preview" src="${links.image}" alt="${escapedName}" />
        <div class="actions">
          <a class="btn" href="${links.image}" target="_blank" rel="noreferrer">Open Direct File</a>
          <a class="btn secondary" href="${links.download}" target="_blank" rel="noreferrer">Download</a>
        </div>
      </section>
    </main>
  </body>
</html>`);
  } catch (error) {
    return res.status(500).send(error.message || "Short link failed.");
  }
}

app.get("/s/:code", handleShortLink);

app.post("/api/upload-url", async (req, res) => {
  const originalName = req.body?.name;
  const contentType = req.body?.type || "application/octet-stream";
  const size = Number(req.body?.size || 0);

  if (!originalName) {
    return res.status(400).json({
      error: "Please select a file first.",
    });
  }

  if (!isAllowedUpload(originalName, contentType)) {
    return res.status(400).json({
      error: "Only CSV and text files are allowed.",
    });
  }

  try {
    const payload = await createSignedUploadUrl({
      originalName,
      contentType,
      size,
    });

    return res.json(payload);
  } catch (error) {
    console.error("Could not create signed upload URL:", error);
    return res.status(500).json({
      error: error.message || "Could not create upload URL.",
    });
  }
});

app.post("/api/complete-upload", async (req, res) => {
  const fileId = req.body?.fileId;
  const originalName = req.body?.name;
  const storedPath = req.body?.storedPath;
  const contentType = req.body?.type || "";
  const uploadedFileFromClient = req.body?.uploadedFile;

  if (!fileId || !originalName || !storedPath) {
    return res.status(400).json({
      error: "fileId, file name, and stored path are required.",
    });
  }

  if (!isAllowedUpload(originalName, contentType)) {
    return res.status(400).json({
      error: "Only CSV and text files are allowed.",
    });
  }

  try {
    const uploadedFile =
      uploadedFileFromClient?.cid && uploadedFileFromClient?.id
        ? uploadedFileFromClient
        : await waitForPinataFile(fileId);
    const gatewayHost = await getGatewayHost();
    const shortCode = await createShortRecord({
      cid: uploadedFile.cid,
      path: storedPath,
      name: originalName,
      type: uploadedFile.mime_type || contentType,
    });
    const payload = {
      success: true,
      file: {
        id: uploadedFile.id || fileId,
        cid: uploadedFile.cid,
        name: originalName,
        storedPath,
        size: uploadedFile.size,
        type: uploadedFile.mime_type || contentType,
        groupId: uploadedFile.group_id,
        createdAt: uploadedFile.created_at,
        shortCode,
      },
    };

    payload.links = createLinkPayload(
      req,
      gatewayHost,
      uploadedFile.cid,
      storedPath,
      originalName,
      shortCode
    );

    return res.json(payload);
  } catch (error) {
    console.error("Completing upload failed:", error);
    return res.status(500).json({
      error: error.message || "Upload failed.",
    });
  }
});

app.post("/api/upload-from-url", async (req, res) => {
  return res.status(400).json({
    error: "Upload by URL is disabled. Only CSV and text files can be uploaded from your device.",
  });
});

if (!process.env.VERCEL) {
  app.listen(port, () => {
    console.log(`File upload app running at http://localhost:${port}`);
  });
}

module.exports = app;
