// server.js
const express = require("express");
const axios = require("axios");
// const { wrapper } = require("axios-cookiejar-support");
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

const DEVICE_CODE = "231778b807f8b283";
const APP_VER = "2.0.3";
const BASE_URL = "https://appsecapi.netshort.com";
const DEFAULT_AD_UNLOCK_CONFIG_ID = "1993944126552477698"; // string biar gak di-rounding

// ==========================================
// 2. UTIL ENCRYPT / DECRYPT
// ==========================================

function genAesKey(length = 32) {
  const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
  let result = "";
  for (let i = 0; i < length; i++) {
    result += alphabet[Math.floor(Math.random() * alphabet.length)];
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
    "User-Agent":
      "Mozilla/5.0 (Linux; Android 12; sdk_gphone64_x86_64 Build/SE1A.220826.008; wv) " +
      "AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/91.0.4472.114 Mobile Safari/537.36",
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

  const requestData = { shortPlayId }; // boleh string, server nerima

  const { bodyB64, headerKeyB64 } = encryptRequestPayload(requestData);
  const ts = Date.now().toString();

  const headers = {
    Host: "appsecapi.netshort.com",
    Canary: "v2",
    Os: "1",
    "User-Agent":
      "Mozilla/5.0 (Linux; Android 12; sdk_gphone64_x86_64 Build/SE1A.220826.008; wv) " +
      "AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/91.0.4472.114 Mobile Safari/537.36",
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
    "User-Agent":
      "Mozilla/5.0 (Linux; Android 12; wv) " +
      "AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/91.0.4472.114 Mobile Safari/537.36",
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
  const possibleVideo =
    data.playVoucher || data.videoUrl || data.playUrl || null;

  return { result, possibleVideo };
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
    "User-Agent":
      "Mozilla/5.0 (Linux; Android 12; sdk_gphone64_x86_64 Build/SE1A.220826.008; wv) " +
      "AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/91.0.4472.114 " +
      "Mobile Safari/537.36",
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
 * GET /api/getepisode/:shortPlayId/:episodeNo
 *
 * Contoh:
 *  /api/getepisode/1928285625898315778/30
 *
 * Flow:
 *  1) login
 *  2) detail_info/V2 -> ambil list episode
 *  3) cari episode dengan episodeNo = param
 *  4) unlock ad
 *  5) get_episode lagi
 *  6) return videoUrl
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

app.get("/api/getepisode/:shortPlayId/:episodeNo", async (req, res) => {
  const shortPlayId = req.params.shortPlayId;
  const episodeNoParam = req.params.episodeNo;
  const playClarity = req.query.playClarity || "540p";
  const adUnlockConfigId = req.query.adUnlockConfigId;

  const epNo = Number(episodeNoParam);
  if (!shortPlayId || Number.isNaN(epNo)) {
    return res.status(400).json({
      error:
        "shortPlayId dan episodeNo wajib diisi, contoh: /api/getepisode/1928.../30",
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

    // 2) DETAIL_INFO/V2 -> AMBIL LIST EPISODE
    const detail = await getShortplayDetail(client, token, shortPlayId);
    const episodes = detail.episodes || [];

    const targetEp = episodes.find((ep) => ep.episodeNo === epNo);
    if (!targetEp) {
      return res.status(404).json({
        error: "episodeNo tidak ditemukan di shortPlay ini",
        availableEpisodes: episodes.map((e) => e.episodeNo),
      });
    }

    const episodeId = targetEp.episodeId;

    // 3) GET EPISODE (before unlock)
    const before = await getEpisodeDetail(
      client,
      token,
      shortPlayId,
      epNo,
      episodeId,
      playClarity
    );

    // 4) UNLOCK
    const unlockResult = await unlockAdEpisode(
      client,
      token,
      shortPlayId,
      epNo,
      episodeId,
      configId,
      1
    );

    // 5) GET EPISODE (after unlock)
    const after = await getEpisodeDetail(
      client,
      token,
      shortPlayId,
      epNo,
      episodeId,
      playClarity
    );

    const videoUrl = after?.possibleVideo || before?.possibleVideo || null;

    return res.json({
      ok: true,
      shortPlayId,
      episodeNo: epNo,
      episodeId,
      playClarity,
      configId,
      videoUrl,
      unlockResult,
      debug: {
        episodesCount: episodes.length,
        availableEpisodes: episodes.map((e) => e.episodeNo),
        before,
        after,
      },
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
