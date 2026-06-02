const http = require("http");
const https = require("https");
const tls = require("tls");
const dns = require("dns").promises;
const net = require("net");

function send(res, status, body) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.status(status).json(body);
}

function isPrivateAddress(address) {
  if (net.isIP(address) === 4) {
    const parts = address.split(".").map(Number);
    return parts[0] === 10 ||
      parts[0] === 127 ||
      (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
      (parts[0] === 192 && parts[1] === 168) ||
      (parts[0] === 169 && parts[1] === 254) ||
      parts[0] === 0;
  }
  if (net.isIP(address) === 6) {
    const lower = address.toLowerCase();
    return lower === "::1" || lower.startsWith("fc") || lower.startsWith("fd") || lower.startsWith("fe80");
  }
  return true;
}

async function resolvePublicHost(hostname) {
  const records = await dns.lookup(hostname, { all: true });
  if (!records.length || records.some((r) => isPrivateAddress(r.address))) {
    throw new Error("PRIVATE_HOST");
  }
}

function requestOnce(target, method) {
  return new Promise((resolve, reject) => {
    const client = target.protocol === "https:" ? https : http;
    const req = client.request(target, {
      method,
      timeout: 8000,
      headers: {
        "User-Agent": "security-url-checker/1.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
      }
    }, (response) => {
      response.resume();
      response.on("end", () => {
        resolve({
          statusCode: response.statusCode || 0,
          headers: response.headers,
          location: response.headers.location || null
        });
      });
    });
    req.on("timeout", () => req.destroy(new Error("TIMEOUT")));
    req.on("error", reject);
    req.end();
  });
}

async function fetchWithRedirects(startUrl) {
  let current = new URL(startUrl);
  const redirects = [];
  for (let index = 0; index < 5; index += 1) {
    let result;
    try {
      result = await requestOnce(current, "HEAD");
    } catch (error) {
      result = await requestOnce(current, "GET");
    }
    if ([301, 302, 303, 307, 308].includes(result.statusCode) && result.location) {
      const next = new URL(result.location, current);
      redirects.push({ from: current.href, to: next.href, statusCode: result.statusCode });
      current = next;
      await resolvePublicHost(current.hostname);
      continue;
    }
    return { finalUrl: current.href, redirects, ...result };
  }
  throw new Error("TOO_MANY_REDIRECTS");
}

function getCertificate(hostname) {
  return new Promise((resolve) => {
    const socket = tls.connect({
      host: hostname,
      port: 443,
      servername: hostname,
      timeout: 8000,
      rejectUnauthorized: false
    }, () => {
      const cert = socket.getPeerCertificate();
      const authorized = socket.authorized;
      const authorizationError = socket.authorizationError || null;
      socket.end();
      resolve({ authorized, authorizationError, validTo: cert.valid_to || null });
    });
    socket.on("error", () => resolve({ authorized: false, authorizationError: "연결 실패", validTo: null }));
    socket.on("timeout", () => { socket.destroy(); resolve({ authorized: false, authorizationError: "타임아웃", validTo: null }); });
  });
}

// ── Google Safe Browsing ──
async function checkGoogleSafeBrowsing(url) {
  const apiKey = process.env.GOOGLE_SAFE_BROWSING_KEY;
  if (!apiKey) return null;

  const body = JSON.stringify({
    client: { clientId: "url-security-checker", clientVersion: "2.0" },
    threatInfo: {
      threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: [{ url }]
    }
  });

  return new Promise((resolve) => {
    const req = https.request({
      hostname: "safebrowsing.googleapis.com",
      path: `/v4/threatMatches:find?key=${apiKey}`,
      method: "POST",
      headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) },
      timeout: 8000
    }, (res) => {
      let data = "";
      res.on("data", (chunk) => { data += chunk; });
      res.on("end", () => {
        try {
          const parsed = JSON.parse(data);
          resolve(parsed.matches || []);
        } catch { resolve(null); }
      });
    });
    req.on("error", () => resolve(null));
    req.on("timeout", () => { req.destroy(); resolve(null); });
    req.write(body);
    req.end();
  });
}

// ── VirusTotal ──
async function checkVirusTotal(url) {
  const apiKey = process.env.VIRUSTOTAL_KEY;
  if (!apiKey) return null;

  const encoded = Buffer.from(url).toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");

  return new Promise((resolve) => {
    const req = https.request({
      hostname: "www.virustotal.com",
      path: `/api/v3/urls/${encoded}`,
      method: "GET",
      headers: { "x-apikey": apiKey },
      timeout: 10000
    }, (res) => {
      let data = "";
      res.on("data", (chunk) => { data += chunk; });
      res.on("end", () => {
        try {
          const parsed = JSON.parse(data);
          const stats = parsed?.data?.attributes?.last_analysis_stats;
          if (!stats) { resolve(null); return; }
          resolve(stats);
        } catch { resolve(null); }
      });
    });
    req.on("error", () => resolve(null));
    req.on("timeout", () => { req.destroy(); resolve(null); });
    req.end();
  });
}

function scoreChecks(checks) {
  let score = 100;
  checks.forEach((c) => { if (c.level === "bad") score -= 20; else if (c.level === "mid") score -= 8; });
  return Math.max(0, score);
}

function gradeFromScore(score) {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 55) return "C";
  return "D";
}

const FIX_GUIDES = {
  "HTTPS 미사용": {
    steps: [
      "호스팅 서비스(Vercel, Netlify 등)는 무료 SSL을 자동 제공합니다.",
      "Let's Encrypt(letsencrypt.org)에서 무료 SSL 인증서를 발급받을 수 있습니다.",
      "서버에서 http:// 접속 시 https://로 자동 리다이렉트 설정을 추가하세요."
    ],
    link: "https://letsencrypt.org/getting-started/"
  },
  "SSL 인증서 오류": {
    steps: [
      "인증서가 만료됐거나 도메인이 일치하지 않는 경우입니다.",
      "호스팅 관리 패널에서 SSL 인증서를 갱신하거나 재발급하세요.",
      "Let's Encrypt를 사용 중이라면 certbot renew 명령으로 갱신할 수 있습니다."
    ],
    link: "https://certbot.eff.org/"
  },
  "인증서 만료 임박": {
    steps: [
      "인증서가 30일 이내에 만료됩니다. 지금 바로 갱신하세요.",
      "Let's Encrypt: certbot renew 명령 실행",
      "Vercel/Netlify 등 자동 갱신 서비스는 대시보드에서 확인하세요."
    ],
    link: "https://certbot.eff.org/"
  },
  "HSTS 헤더 없음": {
    steps: [
      "HSTS는 브라우저가 항상 HTTPS로만 접속하도록 강제합니다.",
      "서버 응답 헤더에 추가: Strict-Transport-Security: max-age=31536000; includeSubDomains",
      "Nginx: add_header Strict-Transport-Security \"max-age=31536000\";",
      "Express.js: helmet() 미들웨어를 사용하면 자동 설정됩니다."
    ],
    link: "https://developer.mozilla.org/ko/docs/Web/HTTP/Headers/Strict-Transport-Security"
  },
  "X-Frame-Options 헤더 없음": {
    steps: [
      "X-Frame-Options는 클릭재킹(Clickjacking) 공격을 방지합니다.",
      "서버 응답 헤더에 추가: X-Frame-Options: DENY 또는 SAMEORIGIN",
      "Nginx: add_header X-Frame-Options \"SAMEORIGIN\";",
      "Express.js: helmet() 미들웨어를 사용하면 자동 설정됩니다."
    ],
    link: "https://developer.mozilla.org/ko/docs/Web/HTTP/Headers/X-Frame-Options"
  },
  "X-Content-Type-Options 헤더 없음": {
    steps: [
      "MIME 타입 스니핑 공격을 방지하는 헤더입니다.",
      "서버 응답 헤더에 추가: X-Content-Type-Options: nosniff",
      "Nginx: add_header X-Content-Type-Options \"nosniff\";",
      "Express.js: helmet() 미들웨어를 사용하면 자동 설정됩니다."
    ],
    link: "https://developer.mozilla.org/ko/docs/Web/HTTP/Headers/X-Content-Type-Options"
  },
  "CSP 헤더 없음": {
    steps: [
      "CSP(Content Security Policy)는 XSS 공격을 방지합니다.",
      "기본 예시: Content-Security-Policy: default-src 'self'",
      "Nginx: add_header Content-Security-Policy \"default-src 'self'\";",
      "CSP 정책은 사이트 구조에 따라 달라지므로 아래 가이드를 참고하세요."
    ],
    link: "https://developer.mozilla.org/ko/docs/Web/HTTP/CSP"
  },
  "리다이렉트 발생": {
    steps: [
      "리다이렉트 자체가 위험하진 않지만 여러 번 발생하면 속도가 느려집니다.",
      "최종 URL을 직접 사용하거나, 불필요한 중간 리다이렉트를 제거하세요.",
      "www → non-www 리다이렉트는 1회만 발생하도록 설정하세요."
    ],
    link: null
  },
  "응답 오류": {
    steps: [
      "4xx: 주소가 잘못되었거나 접근 권한이 없는 경우입니다.",
      "5xx: 서버 내부 오류입니다. 서버 로그를 확인하세요.",
      "사이트 관리자라면 서버 설정 및 로그를 점검하세요."
    ],
    link: "https://developer.mozilla.org/ko/docs/Web/HTTP/Status"
  }
};

module.exports = async function handler(req, res) {
  if (req.method === "OPTIONS") {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
    return res.status(204).end();
  }

  if (req.method !== "POST") return send(res, 405, { error: "POST만 허용됩니다." });

  const { url: rawUrl } = req.body || {};
  if (!rawUrl) return send(res, 400, { error: "url 필드가 없습니다." });

  let target;
  try { target = new URL(rawUrl); }
  catch { return send(res, 400, { error: "URL 형식이 올바르지 않습니다." }); }

  try { await resolvePublicHost(target.hostname); }
  catch { return send(res, 400, { error: "내부 IP 또는 확인할 수 없는 호스트입니다." }); }

  const checks = [];

  function addCheck(title, message, level) {
    const guide = FIX_GUIDES[title] || null;
    checks.push({ title, message, level, fix: (level === "bad" || level === "mid") && guide ? guide : null });
  }

  // ── 1. Google Safe Browsing ──
  const [gsbMatches, vtStats] = await Promise.all([
    checkGoogleSafeBrowsing(target.href),
    checkVirusTotal(target.href)
  ]);

  if (gsbMatches === null) {
    checks.push({ title: "Google Safe Browsing", message: "API 키 미설정 또는 오류로 검사를 건너뜁니다.", level: "mid", fix: null });
  } else if (gsbMatches.length > 0) {
    const types = [...new Set(gsbMatches.map(m => m.threatType))].join(", ");
    checks.push({
      title: "⚠️ Google: 위험 사이트 감지",
      message: `Google Safe Browsing에서 위협이 감지됐습니다: ${types}. 즉시 접속을 중단하세요!`,
      level: "bad",
      fix: {
        steps: [
          "이 사이트는 Google이 악성/피싱 사이트로 분류했습니다.",
          "절대 개인정보나 결제 정보를 입력하지 마세요.",
          "이미 접속했다면 비밀번호를 즉시 변경하고 백신 검사를 실행하세요."
        ],
        link: "https://safebrowsing.google.com/safebrowsing/report_badware/"
      }
    });
  } else {
    checks.push({ title: "Google Safe Browsing 통과", message: "Google 위협 데이터베이스에 등록된 악성 사이트가 아닙니다.", level: "good", fix: null });
  }

  // ── 2. VirusTotal ──
  if (vtStats === null) {
    checks.push({ title: "VirusTotal", message: "API 키 미설정 또는 분석 데이터 없음으로 검사를 건너뜁니다.", level: "mid", fix: null });
  } else {
    const malicious = vtStats.malicious || 0;
    const suspicious = vtStats.suspicious || 0;
    const total = Object.values(vtStats).reduce((a, b) => a + b, 0);

    if (malicious > 0) {
      checks.push({
        title: `⚠️ VirusTotal: ${malicious}개 엔진 위협 감지`,
        message: `${total}개 보안 엔진 중 ${malicious}개가 악성, ${suspicious}개가 의심스럽다고 판정했습니다.`,
        level: "bad",
        fix: {
          steps: [
            "여러 보안 엔진이 이 사이트를 위험하다고 판단했습니다.",
            "절대 파일을 다운로드하거나 개인정보를 입력하지 마세요.",
            "이미 파일을 받았다면 즉시 삭제하고 백신 전체 검사를 실행하세요.",
            "virustotal.com에서 직접 상세 결과를 확인할 수 있습니다."
          ],
          link: `https://www.virustotal.com/gui/url/${Buffer.from(target.href).toString("base64").replace(/=/g,"")}`
        }
      });
    } else if (suspicious > 0) {
      checks.push({
        title: `VirusTotal: ${suspicious}개 엔진 의심`,
        message: `${total}개 보안 엔진 중 ${suspicious}개가 의심스럽다고 판정했습니다. 주의가 필요합니다.`,
        level: "mid",
        fix: {
          steps: [
            "일부 보안 엔진이 이 사이트를 의심스럽다고 판단했습니다.",
            "개인정보 입력이나 파일 다운로드는 피하세요.",
            "virustotal.com에서 상세 결과를 확인해보세요."
          ],
          link: `https://www.virustotal.com/gui/url/${Buffer.from(target.href).toString("base64").replace(/=/g,"")}`
        }
      });
    } else {
      checks.push({
        title: "VirusTotal 통과",
        message: `${total}개 보안 엔진 모두 위협 없음으로 판정했습니다.`,
        level: "good",
        fix: null
      });
    }
  }

  // ── 3. HTTPS ──
  if (target.protocol === "https:") {
    checks.push({ title: "HTTPS 사용", message: "암호화된 HTTPS 주소입니다.", level: "good", fix: null });
  } else {
    addCheck("HTTPS 미사용", "http:// 주소는 개인정보가 노출될 수 있습니다.", "bad");
  }

  // ── 4. 접속 및 리다이렉트 ──
  let fetchResult;
  try {
    fetchResult = await fetchWithRedirects(target.href);
  } catch (err) {
    return send(res, 200, {
      requestedUrl: rawUrl, finalUrl: rawUrl, score: 0, grade: "D",
      checks: [{ title: "접속 실패", message: err.message || "사이트에 연결할 수 없습니다.", level: "bad", fix: null }]
    });
  }

  if (fetchResult.redirects.length > 0) {
    addCheck("리다이렉트 발생", `${fetchResult.redirects.length}회 리다이렉트됐습니다. 최종: ${fetchResult.finalUrl}`, "mid");
  } else {
    checks.push({ title: "리다이렉트 없음", message: "직접 연결됩니다.", level: "good", fix: null });
  }

  const status = fetchResult.statusCode;
  if (status >= 200 && status < 300) {
    checks.push({ title: "응답 정상", message: `HTTP ${status} 정상 응답입니다.`, level: "good", fix: null });
  } else if (status >= 400) {
    addCheck("응답 오류", `HTTP ${status} 오류 응답입니다.`, "bad");
  }

  // ── 5. SSL ──
  if (target.protocol === "https:") {
    const cert = await getCertificate(target.hostname);
    if (cert.authorized) {
      const expiry = cert.validTo ? new Date(cert.validTo) : null;
      const daysLeft = expiry ? Math.floor((expiry - Date.now()) / 86400000) : null;
      if (daysLeft !== null && daysLeft < 30) {
        addCheck("인증서 만료 임박", `${daysLeft}일 후 만료됩니다.`, "mid");
      } else {
        checks.push({ title: "SSL 인증서 유효", message: `신뢰할 수 있는 인증서입니다. (만료: ${cert.validTo})`, level: "good", fix: null });
      }
    } else {
      addCheck("SSL 인증서 오류", cert.authorizationError || "인증서를 신뢰할 수 없습니다.", "bad");
    }
  }

  // ── 6. 보안 헤더 ──
  const headers = fetchResult.headers || {};
  const secHeaders = [
    { key: "strict-transport-security", title: "HSTS" },
    { key: "x-frame-options", title: "X-Frame-Options" },
    { key: "x-content-type-options", title: "X-Content-Type-Options" },
    { key: "content-security-policy", title: "CSP" }
  ];
  secHeaders.forEach(({ key, title }) => {
    if (headers[key]) {
      checks.push({ title: `${title} 헤더 있음`, message: `보안 헤더가 설정되어 있습니다.`, level: "good", fix: null });
    } else {
      addCheck(`${title} 헤더 없음`, `${title} 헤더가 없습니다. 보안이 취약할 수 있습니다.`, "mid");
    }
  });

  const score = scoreChecks(checks);
  const grade = gradeFromScore(score);

  return send(res, 200, { requestedUrl: rawUrl, finalUrl: fetchResult.finalUrl, score, grade, checks });
};
