// server.js
const express = require("express");
const axios = require("axios");
const { CookieJar } = require("tough-cookie");
const crypto = require("crypto");

const app = express();
app.use(express.json());

// ==========================================
// 0. CLIENT DENGAN COOKIE (mirip requests.Session())
// ==========================================

function createClient() {
  // client biasa aja
  const client = axios.create({
    timeout: 20000,
    // baseURL: "https://xxxx", // kalau mau
  });
  return client;
}
// ==========================================
// RANDOM HELPERS
// ==========================================

function randomHex(len = 16) {
  return crypto.randomBytes(len).toString("hex");
}

function randomAndroidModel() {
  const models = [
    "Pixel 6",
    "Pixel 7",
    "Pixel 8",
    "Pixel 6a",
    "Galaxy S21",
    "Galaxy S22",
    "Galaxy S23",
    "Redmi Note 11",
    "Redmi Note 12",
    "ONEPLUS A6003",
    "CPH2411",
  ];
  return models[Math.floor(Math.random() * models.length)];
}

function randomChromeVersion() {
  const major = 85 + Math.floor(Math.random() * 15); // 85–99
  const build = Math.floor(1000 + Math.random() * 8000);
  return `${major}.0.${build}.120`;
}

function buildUserAgent() {
  return (
    `Mozilla/5.0 (Linux; Android 12; ${randomAndroidModel()} Build/SP1A.210812.015; wv) ` +
    `AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/${randomChromeVersion()} Mobile Safari/537.36`
  );
}

// ==========================================
// 1. KUNCI RSA & KONSTAN
// ==========================================

const RSA_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2poXMstZ8NCWE7915MXz
DWC5/t+oB2waGfskPqSZwLqxd4ZBR0H1cb1tAZRZcV7P+LmOd6SYNxhnELaWuKTD
+D3xkz8Tt1L5j/ynGqVt1MDbiQIEzXQKUkNDSH6T0A+Xzo/67/8QOQXlVJfW06re
sbaeNvibfx6Qc78j96bCIPlxPrtieilVTBHUFOXjirxK/ki/mO8P2smRbpt73fsQ
WdGmTGMfYGvfPApGyxbxLkL/qrBjU25XpM8a0MBqzFWUAchHmqSBJ6Mbfam1SSgf
3b2U28s67nOW+JiOrhd6iVLcsLFxXA54HX+Zbej3AbOB6jKaEmp/bz1amneE1NYX
wwIDAQAB
-----END PUBLIC KEY-----`;

const RSA_PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCK0Tl1pd7bjTRU93bWoHW1hLCD
j2+9bg1MgY8j5C7xXaw6bJfToXhWbH1fXNbnFFVqxyYNErcuOUwJZxyDgcxUXM4yWnRseb2GF97G
OicAQ2keDzVYmwky4lrSRwvcXutJRLPUCRQNfc6upfk2G5TKh6/CcP4TV1eXTF7+vdEw2SHxAOIT
KbSfcaZXr/hVs6a1aRHsBF+7RG99ebwZIP6/AgIyqX9RbDVN6ixi1v2G3/bwAULHLSqGdSaqij/c
a17fbFGITaeCeEaZ6d/P4ZuOK+PEPdbPQt6SbY4lZaYwRvdrpH73kigPITgDzIDONFybJ1m7wRKl
q1wxWHwbimptAgMBAAECggEAPz3cYJXFtt5YphDrahJGLgEabYVOUc2ub1li/eX54OpdCWzpqneY
nD7myyg/m5zu4SuDUVdibsOZuXrpSZw7m3+ATP5apgS8bDe5vTNHC16qqBAjrI9NHIp09/F4HNh9
dq6/Am10XkUfgP+KTrU4DyDL2NijV+pltD8N1B5kDE1igokVcsavhnu2INoMRXYE78Wq6urNECuF
Ww9hldv81M9m2w56t1CQOUukpo4mfmLjZRe2s+kwtcBVefGHP8Cj0OeH2dGltjl2YSQMRBFUCVoix
YpOrcjIHoqzWri8IfUZ2tW+nUvHl5IZ9RVxefnFaLGnxiXd2sk6Sn4aD/l9YQKBgQDVv3HaOZxHRq
lNSPrNGqplGhE066HnDsq6MlPukiovxE43CRBmpTnk9zDCqrDh9t2HbJuao7nSq5WlBERWgwqXU/q
DpH43W7Y/lJfHkDv6A2m0viJa0a9x8+CJpNnCDu1ATo4/IQKwoXYice6JKnUyXgkGKn+HipiN6tO0
EtWHlQKBgQCmQfklKFtXtm/FZ6NIMs+d+EyvaE5xNLKGYQxmiCR10WGYd8ZV+K0Q6qXHS+a32TirW
B9F3TqPOklTytMrfPZB3BCXj4weEldb8W716G8FYf7LLhaT+MdpF7KDcruObwoQAvKV3N4eX6tUEM
mdrx9hpCmmIU5EeXUkhGdmwk7BeQKBgAIXMkThJV8pGMTRvuo8pYgBnkN3PoklAuSZU2rU8Sawc9d
j9k4atZtAs7BjvQEoyffmHwt/KHUgCoGnrgdulq7uOlgJRtbBxeGPUYC5L2z9lY4YAfwDawThTsPp
4dtdDAMCAbAqYX1axu4FUUD0MltAwjPWPJMVzvIsZs+vE3mVAoGAJPja3OaCmZjadj2709xoyypic
0dw2j/ry3JdfZec9A5h87P/CTNJ2U81GoLIhe3qakAohDLUSPGfSOD74NnjMXYswmeLs0xE3Q9tq4
XK2pmWPby8DJ/wSHCapByplN0gkbr2E1mQk5SW1xT8oPJGukH1eRpC+3s/D6XaEMH5HZECgYEAigo
X5l39LDsCgeaUcI4S9grkaas/WsKv37eqo3oD9Qk6VFiMM5L5Zig6aXJxuAPLVjb38caJRPmPmOXL
T2kEP1E1h6OJOhEhETwVIUtcBzsK25ju9LqL89bC+W0uS7BPvk6Tcws/tXHCkQCTgb9jVXceZ2ox+
6axvlW/5WgHt5Q=
-----END PRIVATE KEY-----`;

// DEVICE_CODE & USER_AGENT sekarang random per start server
const DEVICE_CODE = randomHex(8); // 8 bytes = 16 hex chars
const APP_VER = "2.0.3";
const BASE_URL = "https://appsecapi.netshort.com";
const DEFAULT_AD_UNLOCK_CONFIG_ID = "1993944126552477698";
const USER_AGENT = buildUserAgent();

// ==========================================
// 2. UTIL ENCRYPT / DECRYPT
// ==========================================

function genAesKey(length = 32) {
  const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
  const bytes = crypto.randomBytes(length);
  let result = "";
  for (let i = 0; i < length; i++) {
    result += alphabet[bytes[i] % alphabet.length];
  }
  return result;
}

function encryptRequestPayload(jsonDataOrString) {
  const payloadStr =
    typeof jsonDataOrString === "string"
      ? jsonDataOrString
      : JSON.stringify(jsonDataOrString);

  const aesKeyStr = genAesKey(32);
  const aesKeyBytes = Buffer.from(aesKeyStr, "utf8");

  const cipher = crypto.createCipheriv("aes-256-ecb", aesKeyBytes, null);
  cipher.setAutoPadding(true);
  const encryptedBody = Buffer.concat([
    cipher.update(Buffer.from(payloadStr, "utf8")),
    cipher.final(),
  ]);
  const bodyB64 = encryptedBody.toString("base64");

  const aesKeyB64 = Buffer.from(aesKeyBytes).toString("base64");
  const encryptedKeyBuf = crypto.publicEncrypt(
    {
      key: RSA_PUBLIC_KEY,
      padding: crypto.constants.RSA_PKCS1_PADDING,
    },
    Buffer.from(aesKeyB64, "utf8")
  );
  const headerKeyB64 = encryptedKeyBuf.toString("base64");

  return { bodyB64, headerKeyB64 };
}

function decryptResponsePayload(headerEncryptKey, bodyText) {
  try {
    const encKeyBytes = Buffer.from(headerEncryptKey, "base64");

    const rsaDecrypted = crypto.privateDecrypt(
      {
        key: RSA_PRIVATE_KEY,
        padding: crypto.constants.RSA_PKCS1_PADDING,
      },
      encKeyBytes
    );

    const aesKey = Buffer.from(rsaDecrypted.toString("utf8"), "base64");

    const bodyBytes = Buffer.from(bodyText, "base64");
    const decipher = crypto.createDecipheriv("aes-256-ecb", aesKey, null);
    decipher.setAutoPadding(true);
    const decryptedRaw = Buffer.concat([
      decipher.update(bodyBytes),
      decipher.final(),
    ]);

    return JSON.parse(decryptedRaw.toString("utf8"));
  } catch (e) {
    return { error: e.message, raw_body: bodyText };
  }
}

// ==========================================
// 3. LOGIN → TOKEN
// ==========================================

async function doLogin(client) {
  const url = `${BASE_URL}/prod-app-api/auth/login`;

  const params = {
    os: "Android",
    appVer: APP_VER,
    identity: 0,
    model: "sdk_gphone64_x86_64",
    deviceCode: DEVICE_CODE,
    source: "visitor",
    osVer: "12",
  };

  const { bodyB64, headerKeyB64 } = encryptRequestPayload(params);
  const ts = Date.now().toString();

  const headers = {
    Host: "appsecapi.netshort.com",
    Canary: "v2",
    Os: "1",
    "User-Agent": USER_AGENT,
    Start_type: "cold",
    Version: APP_VER,
    Network: "wifi,cold,true",
    "Device-Code": DEVICE_CODE,
    "Encrypt-Key": headerKeyB64,
    Push_switch: "true",
    Timestamp: ts,
    "Content-Language": "en_US",
    "Content-Type": "application/json",
    "Accept-Encoding": "gzip",
    Connection: "Keep-Alive",
  };

  const resp = await client.post(url, bodyB64, { headers });
  const encKey = resp.headers["encrypt-key"];

  if (!encKey) throw new Error("Login: encrypt-key header tidak ada");

  const rawBody =
    typeof resp.data === "string" ? resp.data.trim() : String(resp.data).trim();
  const result = decryptResponsePayload(encKey, rawBody);

  if (result.error) throw new Error("Login decrypt gagal: " + result.error);

  const token = result.data.token;
  const userId = result.data.loginUser.userId;

  return { token, userId, raw: result };
}

// ==========================================
// 4. DETAIL_INFO/V2 → LIST EPISODE
// ==========================================

async function getShortplayDetail(client, token, shortPlayId) {
  const url = BASE_URL + "/prod-app-api/video/shortPlay/base/detail_info/V2";

  const requestData = { shortPlayId };

  const { bodyB64, headerKeyB64 } = encryptRequestPayload(requestData);
  const ts = Date.now().toString();

  const headers = {
    Host: "appsecapi.netshort.com",
    Canary: "v2",
    Os: "1",
    "User-Agent": USER_AGENT,
    Start_type: "cold",
    Version: APP_VER,
    Network: "wifi,cold,true",
    "Device-Code": DEVICE_CODE,
    "Encrypt-Key": headerKeyB64,
    Push_switch: "true",
    Timestamp: ts,
    "Content-Language": "en_US",
    "Content-Type": "application/json",
    "Accept-Encoding": "gzip",
    Connection: "Keep-Alive",
    Authorization: `Bearer ${token}`,
  };

  const resp = await client.post(url, bodyB64, { headers });

  const serverKey = resp.headers["encrypt-key"];
  if (!serverKey)
    throw new Error("detail_info/V2: encrypt-key header tidak ada");

  const body =
    typeof resp.data === "string" ? resp.data.trim() : String(resp.data).trim();
  const result = decryptResponsePayload(serverKey, body);

  const episodesRaw = (result.data && result.data.shortPlayEpisodeInfos) || [];

  const episodes = episodesRaw.map((ep) => ({
    episodeNo: ep.episodeNo,
    episodeId: ep.episodeId,
    isLock: ep.isLock,
    hasPlayVoucher: !!ep.playVoucher,
  }));

  return { meta: result.data, episodes, raw: result };
}

// ==========================================
// 4.5. HOME TAB → /video/shortPlay/tab/load_group_tabId
// (port dari main() Python kamu)
// ==========================================

async function getHomeTabGroup(client, token, tabId, offset = 0, limit = 1) {
  const url = BASE_URL + "/prod-app-api/video/shortPlay/tab/load_group_tabId";

  // tabId besar → kirim sebagai string di JSON manual biar ga overflow
  const tabIdStr = String(tabId);
  const off = Number(offset) || 0;
  const lim = Number(limit) || 1;

  const payloadStr =
    `{"tabId":${tabIdStr},` + `"offset":${off},` + `"limit":${lim}}`;

  const { bodyB64, headerKeyB64 } = encryptRequestPayload(payloadStr);
  const ts = Date.now().toString();

  const headers = {
    Host: "appsecapi.netshort.com",
    Canary: "v2",
    Os: "1",
    Version: APP_VER,
    "Encrypt-Key": headerKeyB64,
    "Device-Code": DEVICE_CODE,
    "Content-Type": "application/json",
    "Content-Language": "id_ID",
    "User-Agent": USER_AGENT,
    Authorization: `Bearer ${token}`,
  };

  const resp = await client.post(url, bodyB64, { headers });

  const serverKey = resp.headers["encrypt-key"];
  if (!serverKey)
    throw new Error("getHomeTabGroup: encrypt-key header tidak ada");

  const body =
    typeof resp.data === "string" ? resp.data.trim() : String(resp.data).trim();
  const result = decryptResponsePayload(serverKey, body);

  return result; // full JSON hasil dekripsi
}

// ==========================================
// 5. EPISODE DETAIL
// ==========================================

async function getEpisodeDetail(
  client,
  token,
  shortPlayId,
  episodeNo,
  episodeId,
  playClarity = "540p"
) {
  const url =
    BASE_URL + "/prod-app-api/video/shortPlay/base/episode/detail_info";

  const payloadData = {
    codec: "h264",
    episodeType: 1,
    shortPlayId,
    episodeNo,
    episodeId,
    playClarity,
  };

  const { bodyB64, headerKeyB64 } = encryptRequestPayload(payloadData);
  const ts = Date.now().toString();

  const headers = {
    Host: "appsecapi.netshort.com",
    Canary: "v2",
    Os: "1",
    Start_type: "hot",
    Version: APP_VER,
    Network: "wifi,hot,true",
    "Device-Code": DEVICE_CODE,
    Push_switch: "true",
    "Content-Language": "en_US",
    "Content-Type": "application/json",
    "User-Agent": USER_AGENT,
    "Encrypt-Key": headerKeyB64,
    Authorization: `Bearer ${token}`,
    Timestamp: ts,
  };

  const resp = await client.post(url, bodyB64, { headers });

  const serverKey = resp.headers["encrypt-key"];
  if (!serverKey) throw new Error("episode detail: encrypt-key tidak ada");

  const body =
    typeof resp.data === "string" ? resp.data.trim() : String(resp.data).trim();
  const result = decryptResponsePayload(serverKey, body);

  const data = result.data || {};

  let possibleVideo = null;

  if (Array.isArray(data.episodeList) && data.episodeList.length > 0) {
    const first = data.episodeList[0];
    possibleVideo =
      first.playVoucher || first.videoUrl || first.playUrl || null;
  } else {
    possibleVideo = data.playVoucher || data.videoUrl || data.playUrl || null;
  }

  return { data, possibleVideo };
}

// ==========================================
// 6. UNLOCK AD EPISODE (manual JSON string, biar BigInt aman)
// ==========================================

async function unlockAdEpisode(
  client,
  token,
  shortPlayId,
  episodeNo,
  episodeId,
  adUnlockConfigId,
  adUnlockEpsType = 1
) {
  const url =
    BASE_URL + "/prod-app-api/user/shortPlay/userBase/unlock_ad_episode";

  const shortPlayIdStr = String(shortPlayId);
  const episodeIdStr = String(episodeId);
  const configIdStr = String(adUnlockConfigId);

  const payloadStr =
    `{"shortPlayEpisodeNo":${episodeNo},` +
    `"shortPlayId":${shortPlayIdStr},` +
    `"adUnlockEpsType":${adUnlockEpsType},` +
    `"adUnlockConfigId":${configIdStr},` +
    `"shortPlayEpisodeId":${episodeIdStr}}`;

  const { bodyB64, headerKeyB64 } = encryptRequestPayload(payloadStr);
  const ts = Date.now().toString();

  const headers = {
    Host: "appsecapi.netshort.com",
    Canary: "v2",
    Os: "1",
    "User-Agent": USER_AGENT,
    Start_type: "cold",
    Version: APP_VER,
    Network: "wifi,cold,true",
    Authorization: `Bearer ${token}`,
    "Device-Code": DEVICE_CODE,
    "Encrypt-Key": headerKeyB64,
    Push_switch: "true",
    Timestamp: ts,
    "Content-Language": "en_US",
    "Content-Type": "application/json",
    "Accept-Encoding": "gzip, deflate, br",
    Connection: "keep-alive",
  };

  const resp = await client.post(url, bodyB64, { headers });

  const serverKey = resp.headers["encrypt-key"];
  if (!serverKey) throw new Error("unlock_ad_episode: encrypt-key tidak ada");

  const body =
    typeof resp.data === "string" ? resp.data.trim() : String(resp.data).trim();
  const result = decryptResponsePayload(serverKey, body);

  return result;
}

// ==========================================
// 7. ROUTES
// ==========================================

// test login (opsional)
app.post("/api/login", async (req, res) => {
  const client = createClient();
  try {
    const { token, userId } = await doLogin(client);
    res.json({ token, userId });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

/**
 * GET /api/get-home?tabId=1965372594714603522&offset=0&limit=1
 *
 * Port dari main() Python:
 * - login dulu
 * - hit /video/shortPlay/tab/load_group_tabId
 */
app.get("/api/get-home", async (req, res) => {
  const { tabId, offset = "0", limit = "1" } = req.query;

  if (!tabId) {
    return res.status(400).json({ error: "tabId wajib diisi" });
  }

  const client = createClient();

  try {
    const { token } = await doLogin(client);
    const result = await getHomeTabGroup(client, token, tabId, offset, limit);

    return res.json({
      ok: true,
      request: {
        tabId: String(tabId),
        offset: Number(offset) || 0,
        limit: Number(limit) || 1,
      },
      data: result, // full JSON hasil decrypt
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message || "get-home error" });
  }
});

/**
 * GET /api/getepisode/:shortPlayId
 *
 * -> ambil daftar episode (sekali doang, lebih berat)
 */
app.get("/api/getepisode/:shortPlayId", async (req, res) => {
  const shortPlayId = req.params.shortPlayId;

  if (!shortPlayId) {
    return res.status(400).json({ error: "shortPlayId wajib diisi" });
  }

  const client = createClient();

  try {
    const { token } = await doLogin(client);
    const detail = await getShortplayDetail(client, token, shortPlayId);

    return res.json({
      ok: true,
      shortPlayId,
      title: detail.meta?.shortPlayName || null,
      cover: detail.meta?.shortPlayCover || null,
      episodeCount: detail.episodes.length,
      episodes: detail.episodes, // berisi episodeNo + episodeId
      raw: detail.meta,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/getepisode/:shortPlayId/:episodeId
 *
 * Contoh:
 *   /api/getepisode/1928285625898315778/1934502729310863362?episodeNo=6&playClarity=540p
 *
 * Flow:
 *   1) login
 *   2) unlock_ad_episode
 *   3) getEpisodeDetail (setelah unlock)
 */
app.get("/api/getepisode/:shortPlayId/:episodeId", async (req, res) => {
  const shortPlayId = req.params.shortPlayId;
  const episodeId = req.params.episodeId;

  const episodeNoParam = req.query.episodeNo;
  const playClarity = req.query.playClarity || "540p";
  const adUnlockConfigId = req.query.adUnlockConfigId;

  if (!shortPlayId || !episodeId) {
    return res.status(400).json({
      error:
        "shortPlayId dan episodeId wajib diisi, contoh: /api/getepisode/1928.../1934...",
    });
  }

  if (!episodeNoParam) {
    return res.status(400).json({
      error:
        "episodeNo wajib dikirim via query, contoh: ?episodeNo=6 (ambil dari detail_info/V2 di frontend)",
    });
  }

  const epNo = Number(episodeNoParam);
  if (Number.isNaN(epNo)) {
    return res.status(400).json({
      error: "episodeNo harus berupa angka, contoh: ?episodeNo=6",
    });
  }

  const configId =
    adUnlockConfigId != null
      ? String(adUnlockConfigId)
      : DEFAULT_AD_UNLOCK_CONFIG_ID;

  const client = createClient();

  try {
    // 1) LOGIN
    const { token } = await doLogin(client);

    // 3) UNLOCK via AD
    const unlockResult = await unlockAdEpisode(
      client,
      token,
      shortPlayId,
      epNo,
      episodeId,
      configId,
      1
    );
    const done2 = await getEpisodeDetail(
      client,
      token,
      shortPlayId,
      epNo,
      episodeId,
      playClarity
    );

    const videoUrl =
      done2.data?.episodeList?.[0]?.playVoucher || done2.possibleVideo || null;

    return res.json({
      ok: true,
      shortPlayId,
      episodeNo: epNo,
      episodeId,
      playClarity,
      configId,
      videoUrl,
      unlockResult,
      done2,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message || "episode error" });
  }
});

// ==========================================
// 8. START SERVER
// ==========================================

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("API running on http://localhost:" + PORT);
});
