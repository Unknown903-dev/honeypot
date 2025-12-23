/**
Features:
    - Cloudflare-aware client IP extraction
    - Structured JSON logging for every request
    - Soft-flagging based on rate and suspicious path hits
    - hard-block for extreme floods
    - Explicit "soft_flag" and "hard_block" event logs
    - Local-only admin endpoint to check IP state
*/

const express = require("express");
const crypto = require("crypto");
const app = express();
app.set("trust proxy", true);


const POLICY = {
    windowMs: 60_000,
    // flag if >= 60 req/min from one IP
    maxReqPerWindow: 60,
    // hard block if >= 10 req/min
    hardBlockReqPerWindow: 10,
    // flag if >= 3 suspicious path hits in the window
    suspiciousHitsToFlag: 3,
    // delay range for flagged clients (ms)
    tarpitDelayMs: [1500, 7000],
    suspiciousPaths: [
        "/wp-login.php",
        "/xmlrpc.php",
        "/phpmyadmin",
        "/admin",
        "/cgi-bin",
        "/.git",
        "/server-status",
    ],
};

//gets ip through cloudflare
function getClientIp(req) {
    const cfIp = req.headers["cf-connecting-ip"];
    if (typeof cfIp === "string" && cfIp.trim()) {
        return cfIp.trim();
    }
    const xff = req.headers["x-forwarded-for"];
    if (typeof xff === "string" && xff.trim()) {
        return xff.split(",")[0].trim();
    }

    return req.socket && req.socket.remoteAddress
        ? req.socket.remoteAddress
        : "";
}

//this what causes the website to slow down for flagged ip
function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

function logEvent(event, data) {
    console.log(
        JSON.stringify({
            ts: new Date().toISOString(),
            event,
            ...data,
        })
    );
}

function isSuspiciousPath(pathname) {
    return POLICY.suspiciousPaths.some(
        (p) => pathname === p || pathname.startsWith(p + "/")
    );
}

const ipState = new Map();
const deny = new Set();

//tracks ip status per minute
function getOrInitState(ip) {
    const now = Date.now();
    let s = ipState.get(ip);
    //time expired or new ip refresh status
    if (!s || now - s.windowStart > POLICY.windowMs) {
        s = {
            windowStart: now,
            count: 0,
            suspiciousCount: 0,
            flaggedUntil: 0,
            lastSeen: now,
        };
        ipState.set(ip, s);
    }

    s.lastSeen = now;
    return s;
}

//logging
function requestLogger(req, res, next) {
    const start = process.hrtime.bigint();
    const requestId = crypto.randomUUID();
    req.requestId = requestId;

    res.on("finish", () => {
        const durationMs = Number(process.hrtime.bigint() - start) / 1e6;
        const ip = getClientIp(req);
        const s = ip ? ipState.get(ip) : null;

        const log = {
            ts: new Date().toISOString(),
            requestId,
            ip,
            // flag ip status
            flagged: s ? Date.now() < s.flaggedUntil : false,
            method: req.method,
            path: req.originalUrl || req.url,
            status: res.statusCode,
            durationMs: Math.round(durationMs * 1000) / 1000,
            //web application
            ua: req.headers["user-agent"] || "",
            referer: req.headers["referer"] || "",
            //unique cloudflare identifier
            cfRay: req.headers["cf-ray"] || "",
            //cloudflare country code
            country: req.headers["cf-ipcountry"] || "",
        };
        console.log(JSON.stringify(log));
    });
    next();
}
app.use(requestLogger);

// banning 
async function banLogic(req, res, next) {
    const ip = getClientIp(req) || "unknown";
    const path = (req.originalUrl || req.url || "").split("?")[0];

    // hard block ip if in deny set
    if (deny.has(ip)) {
        return res.status(403).send("Forbidden");
    }

    const s = getOrInitState(ip);
    s.count += 1;

    if (isSuspiciousPath(path)) {
        s.suspiciousCount += 1;
    }

    // adds ip to deny set if to many requestss
    if (s.count >= POLICY.hardBlockReqPerWindow) {
        if (!deny.has(ip)) {
            deny.add(ip);
            logEvent("hard_block", {
                ip,
                reason: `rate >= ${POLICY.hardBlockReqPerWindow}/min`,
                count: s.count,
                suspiciousCount: s.suspiciousCount,
            });
        }
        return res.status(403).send("Forbidden");
    }

    const shouldFlag = s.count >= POLICY.maxReqPerWindow || s.suspiciousCount >= POLICY.suspiciousHitsToFlag;
    // flag ip if not flagged and refresh timer if abuse continue
    if (shouldFlag) {
        const wasFlagged = Date.now() < s.flaggedUntil;
        s.flaggedUntil = Math.max(s.flaggedUntil, Date.now() + POLICY.windowMs);

        //log only if not flagged
        if (!wasFlagged) {
            logEvent("soft_flag", {
                ip,
                reason:
                    s.count >= POLICY.maxReqPerWindow
                        ? "rate_limit"
                        : "suspicious_paths",
                count: s.count,
                suspiciousCount: s.suspiciousCount,
                flaggedUntil: new Date(s.flaggedUntil).toISOString(),
            });
        }
    }

    if (Date.now() < s.flaggedUntil) {
        const [minD, maxD] = POLICY.tarpitDelayMs;
        const delay = Math.floor(minD + Math.random() * (maxD - minD));
        await sleep(delay);

        //change behavior for some paths to make it believable
        if (path === "/wp-login.php") {
            return res.status(200).send("username: admin password: admin");

        } else if (path === "/xmlrpc.php") {
            return res.status(200).send("XML-RPC server accepts POST requests only.");

        } else if (path === "/admin") {
            return res.status(401).send("Unauthorized");

        }

        return res.status(404).send("Not Found");
    }

    next();
}

app.use(banLogic);
app.get("/", (req, res) => res.status(200).send("OK"));
app.get("/admin", (req, res) => res.status(401).send("Unauthorized"));
app.get("/wp-login.php", (req, res) => res.status(404).send("Not Found"));
app.use((req, res) => res.status(404).send("Not Found"));

//local admin endpoint to check ip status
app.get("/__status/ip/:ip", (req, res) => {
    const caller = getClientIp(req);

    if (caller !== "127.0.0.1" && caller !== "::1") {
        return res.status(403).send("Forbidden");
    }

    const ip = req.params.ip;
    const s = ipState.get(ip);

    //if nothing return nothing else return the status
    if (!s) {
        return res.json({
            ip,
            flagged: false,
            hardBlocked: deny.has(ip),
            message: "no record",
        });
    }

    return res.json({
        ip,
        flagged: Date.now() < s.flaggedUntil,
        hardBlocked: deny.has(ip),
        flaggedUntil: s.flaggedUntil
            ? new Date(s.flaggedUntil).toISOString()
            : null,
        count: s.count,
        suspiciousCount: s.suspiciousCount,
        windowStart: new Date(s.windowStart).toISOString(),
    });
});

//every 60 sec remove ip if idle for 10 min stop crash server
setInterval(() => {
    const now = Date.now();
    for (const [ip, s] of ipState.entries()) {
        if (now - s.lastSeen > 10 * 60_000) {
            ipState.delete(ip);
        }
    }
}, 60_000);


const PORT = process.env.PORT ? Number(process.env.PORT) : 9000;

app.listen(PORT, () => {
    console.log(`Honeypot listening on port ${PORT}`);
});