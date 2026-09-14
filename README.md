// server.js
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const db = require("./database");

const app = express();

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
    console.error("ERROR: JWT_SECRET is missing.");
    process.exit(1);
}

app.use(cors());
app.use(express.json({ limit: "100kb" }));

function hashDeviceId(value) {
    return crypto
        .createHash("sha256")
        .update(String(value))
        .digest("hex");
}

function authenticate(req, res, next) {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
        return res.status(401).json({
            error: "Authentication required"
        });
    }

    const token = header.substring(7);

    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch {
        return res.status(401).json({
            error: "Invalid or expired token"
        });
    }
}

function calculateRisk(device) {
    let score = Number(device.risk_score || 0);

    if (device.tamper_detected) {
        score += 20;
    }

    return Math.min(score, 100);
}

app.get("/", (req, res) => {
    res.json({
        name: "DeviceGuard",
        version: "1.0.0",
        status: "online"
    });
});

app.get("/health", (req, res) => {
    res.json({
        status: "healthy",
        timestamp: new Date().toISOString()
    });
});

/*
  Development/admin login.
  Replace with a proper identity provider before production.
*/
app.post("/api/auth/login", (req, res) => {
    const { username, password } = req.body;

    if (
        username !== process.env.ADMIN_USERNAME ||
        password !== process.env.ADMIN_PASSWORD
    ) {
        return res.status(401).json({
            error: "Invalid credentials"
        });
    }

    const token = jwt.sign(
        {
            sub: username,
            role: "admin"
        },
        JWT_SECRET,
        {
            expiresIn: "8h"
        }
    );

    res.json({
        token,
        expires_in: "8h"
    });
});

/*
  Register a financed/company-managed device.
*/
app.post("/api/devices/register", authenticate, (req, res) => {
    const {
        device_id,
        imei,
        serial_number,
        owner_id
    } = req.body;

    if (!device_id) {
        return res.status(400).json({
            error: "device_id is required"
        });
    }

    try {
        db.prepare(`
            INSERT INTO devices
            (
                device_id,
                imei,
                serial_number,
                owner_id
            )
            VALUES (?, ?, ?, ?)
        `).run(
            hashDeviceId(device_id),
            imei || null,
            serial_number || null,
            owner_id || null
        );

        res.status(201).json({
            success: true,
            message: "Device enrolled"
        });

    } catch {
        res.status(409).json({
            error: "Device already enrolled"
        });
    }
});

/*
  Device status.
*/
app.get("/api/devices/:device_id", authenticate, (req, res) => {
    const device = db.prepare(`
        SELECT
            device_id,
            serial_number,
            owner_id,
            status,
            risk_score,
            tamper_detected,
            enrolled_at,
            updated_at
        FROM devices
        WHERE device_id = ?
    `).get(hashDeviceId(req.params.device_id));

    if (!device) {
        return res.status(404).json({
            error: "Device not found"
        });
    }

    res.json({
        ...device,
        tamper_detected: Boolean(device.tamper_detected)
    });
});

/*
  Device policy.
*/
app.get("/api/devices/:device_id/policy", authenticate, (req, res) => {
    const device = db.prepare(`
        SELECT
            status,
            risk_score,
            tamper_detected
        FROM devices
        WHERE device_id = ?
    `).get(hashDeviceId(req.params.device_id));

    if (!device) {
        return res.status(404).json({
            error: "Device not found"
        });
    }

    const risk = calculateRisk(device);

    res.json({
        status: device.status,
        risk_score: risk,
        tamper_detected: Boolean(device.tamper_detected),

        policy: {
            allow_device: device.status === "active",
            require_security_review: risk >= 50,
            report_security_event: Boolean(device.tamper_detected)
        }
    });
});

/*
  Change device status.
*/
app.patch("/api/devices/:device_id/status", authenticate, (req, res) => {
    const allowedStatuses = [
        "active",
        "overdue",
        "stolen",
        "fraud",
        "blocked"
    ];

    const { status } = req.body;

    if (!allowedStatuses.includes(status)) {
        return res.status(400).json({
            error: "Invalid status"
        });
    }

    const result = db.prepare(`
        UPDATE devices
        SET
            status = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE device_id = ?
    `).run(
        status,
        hashDeviceId(req.params.device_id)
    );

    if (result.changes === 0) {
        return res.status(404).json({
            error: "Device not found"
        });
    }

    res.json({
        success: true,
        status
    });
});

/*
  Receive a security event from an enrolled device.
*/
app.post("/api/devices/:device_id/events", authenticate, (req, res) => {
    const {
        event_type,
        severity = "info",
        details = {}
    } = req.body;

    const allowedEvents = [
        "root_detected",
        "bootloader_status_changed",
        "integrity_failure",
        "debugging_detected",
        "suspicious_reset",
        "device_rebooted",
        "security_check_passed"
    ];

    const allowedSeverity = [
        "info",
        "low",
        "medium",
        "high",
        "critical"
    ];

    if (!allowedEvents.includes(event_type)) {
        return res.status(400).json({
            error: "Unsupported event type"
        });
    }

    if (!allowedSeverity.includes(severity)) {
        return res.status(400).json({
            error: "Invalid severity"
        });
    }

    const deviceId = hashDeviceId(req.params.device_id);

    const device = db.prepare(`
        SELECT device_id
        FROM devices
        WHERE device_id = ?
    `).get(deviceId);

    if (!device) {
        return res.status(404).json({
            error: "Device not enrolled"
        });
    }

    db.prepare(`
        INSERT INTO security_events
        (
            device_id,
            event_type,
            severity,
            details
        )
        VALUES (?, ?, ?, ?)
    `).run(
        deviceId,
        event_type,
        severity,
        JSON.stringify(details)
    );

    const dangerousEvents = [
        "root_detected",
        "integrity_failure",
        "suspicious_reset"
    ];

    if (dangerousEvents.includes(event_type)) {
        db.prepare(`
            UPDATE devices
            SET
                risk_score = MIN(risk_score + 20, 100),
                tamper_detected = 1,
                updated_at = CURRENT_TIMESTAMP
            WHERE device_id = ?
        `).run(deviceId);
    }

    res.status(201).json({
        success: true,
        message: "Security event recorded"
    });
});

/*
  Security event history.
*/
app.get("/api/devices/:device_id/events", authenticate, (req, res) => {
    const events = db.prepare(`
        SELECT
            event_type,
            severity,
            details,
            created_at
        FROM security_events
        WHERE device_id = ?
        ORDER BY created_at DESC
        LIMIT 100
    `).all(hashDeviceId(req.params.device_id));

    res.json(events);
});

/*
  Dashboard summary.
*/
app.get("/api/dashboard/summary", authenticate, (req, res) => {
    const total = db.prepare(`
        SELECT COUNT(*) AS count
        FROM devices
    `).get().count;

    const active = db.prepare(`
        SELECT COUNT(*) AS count
        FROM devices
        WHERE status = 'active'
    `).get().count;

    const overdue = db.prepare(`
        SELECT COUNT(*) AS count
        FROM devices
        WHERE status = 'overdue'
    `).get().count;

    const stolen = db.prepare(`
        SELECT COUNT(*) AS count
        FROM devices
        WHERE status = 'stolen'
    `).get().count;

    const fraud = db.prepare(`
        SELECT COUNT(*) AS count
        FROM devices
        WHERE status = 'fraud'
    `).get().count;

    const blocked = db.prepare(`
        SELECT COUNT(*) AS count
        FROM devices
        WHERE status = 'blocked'
    `).get().count;

    const tampered = db.prepare(`
        SELECT COUNT(*) AS count
        FROM devices
        WHERE tamper_detected = 1
    `).get().count;

    res.json({
        total,
        active,
        overdue,
        stolen,
        fraud,
        blocked,
        tampered
    });
});

app.use((req, res) => {
    res.status(404).json({
        error: "Endpoint not found"
    });
});

app.listen(PORT, () => {
    console.log(`
========================================
          DEVICEGUARD API
========================================
Server: http://localhost:${PORT}

Status:
GET /health

Authentication:
POST /api/auth/login

Devices:
POST  /api/devices/register
GET   /api/devices/:device_id
GET   /api/devices/:device_id/policy
PATCH /api/devices/:device_id/status

Security:
POST /api/devices/:device_id/events
GET  /api/devices/:device_id/events

Dashboard:
GET /api/dashboard/summary
========================================
`);
});
