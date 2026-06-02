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
  if (!records.length || records.some((record) => isPrivateAddress(record.address))) {
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
      resolve({
        authorized,
