const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");
const PgSession = require("connect-pg-simple")(session);
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

app.set("trust proxy", 1);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// اتصال به PostgreSQL
if (!process.env.DATABASE_URL) {
    console.error("DATABASE_URL is missing!");
    process.exit(1);
}

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

// ایجاد جدول کاربران
async function initializeDatabase() {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT NOT NULL,
            username_lower TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `);

    // انتقال کاربران قدیمی، در صورت وجود فایل users.json
    const usersFile = path.join(__dirname, "users.json");

    if (fs.existsSync(usersFile)) {
        try {
            const oldUsers = JSON.parse(
                fs.readFileSync(usersFile, "utf8")
            );

            if (Array.isArray(oldUsers)) {
                for (const user of oldUsers) {
                    if (!user.username || !user.password) continue;

                    await pool.query(
                        `INSERT INTO users
                        (username, username_lower, password_hash)
                        VALUES ($1, $2, $3)
                        ON CONFLICT (username_lower) DO NOTHING`,
                        [
                            user.username,
                            user.username.toLowerCase(),
                            user.password
                        ]
                    );
                }

                console.log("Old users migration checked.");
            }
        } catch (error) {
            console.error("Old users migration error:", error);
        }
    }

    console.log("PostgreSQL database is ready.");
}

// نشست کاربران با ذخیره دائمی در دیتابیس
app.use(session({
    store: new PgSession({
        pool: pool,
        tableName: "user_sessions",
        createTableIfMissing: true
    }),

    secret: process.env.SESSION_SECRET || "pikso-development-secret",
    resave: false,
    saveUninitialized: false,
    rolling: true,

    cookie: {
        httpOnly: true,
        sameSite: "lax",
        secure: "auto",
        maxAge: 30 * 24 * 60 * 60 * 1000
    }
}));

// جلوگیری از نمایش فایل‌های حساس
app.use((req, res, next) => {
    const blocked = [
        "/users.json",
        "/server.js",
        "/package.json",
        "/package-lock.json"
    ];

    if (blocked.includes(req.path)) {
        return res.sendStatus(404);
    }

    next();
});

// فایل‌های سایت
app.use(express.static(__dirname));

// تست سرور
app.get("/api", (req, res) => {
    res.json({
        message: "PIKSO GAMES SERVER IS RUNNING!"
    });
});

// ثبت نام
app.post("/api/register", async (req, res) => {
    try {
        const { username, password } = req.body;

        if (
            typeof username !== "string" ||
            typeof password !== "string"
        ) {
            return res.status(400).json({
                message: "اطلاعات نامعتبر است."
            });
        }

        const cleanUsername = username.trim();

        if (cleanUsername.length < 3 || cleanUsername.length > 20) {
            return res.status(400).json({
                message: "نام کاربری باید بین ۳ تا ۲۰ کاراکتر باشد."
            });
        }

        if (password.length < 6) {
            return res.status(400).json({
                message: "رمز عبور باید حداقل ۶ کاراکتر باشد."
            });
        }

        const hashedPassword = await bcrypt.hash(password, 12);

        await pool.query(
            `INSERT INTO users
            (username, username_lower, password_hash)
            VALUES ($1, $2, $3)`,
            [
                cleanUsername,
                cleanUsername.toLowerCase(),
                hashedPassword
            ]
        );

        return res.status(201).json({
            message: "ثبت‌نام موفق بود! حالا وارد شو."
        });

    } catch (error) {
        if (error.code === "23505") {
            return res.status(409).json({
                message: "این نام کاربری قبلاً ثبت شده است."
            });
        }

        console.error("Register error:", error);

        return res.status(500).json({
            message: "خطای سرور در ثبت‌نام."
        });
    }
});

// ورود
app.post("/api/login", async (req, res) => {
    try {
        const { username, password } = req.body;

        if (
            typeof username !== "string" ||
            typeof password !== "string"
        ) {
            return res.status(400).json({
                message: "اطلاعات نامعتبر است."
            });
        }

        const result = await pool.query(
            `SELECT username, password_hash
             FROM users
             WHERE username_lower = $1`,
            [username.trim().toLowerCase()]
        );

        const user = result.rows[0];

        if (!user || !(await bcrypt.compare(password, user.password_hash))) {
            return res.status(401).json({
                message: "نام کاربری یا رمز عبور اشتباه است."
            });
        }

        req.session.regenerate(error => {
            if (error) {
                console.error(error);

                return res.status(500).json({
                    message: "خطا در ایجاد نشست کاربری."
                });
            }

            req.session.username = user.username;

            req.session.save(saveError => {
                if (saveError) {
                    console.error(saveError);

                    return res.status(500).json({
                        message: "خطا در ذخیره ورود."
                    });
                }

                return res.json({
                    message: "ورود موفق بود!",
                    redirect: "/dashboard.html"
                });
            });
        });

    } catch (error) {
        console.error("Login error:", error);

        return res.status(500).json({
            message: "خطای سرور در ورود."
        });
    }
});

// اطلاعات حساب
app.get("/api/me", (req, res) => {
    if (!req.session.username) {
        return res.status(401).json({
            message: "وارد حساب نشده‌اید."
        });
    }

    res.json({
        username: req.session.username
    });
});

// خروج
app.post("/api/logout", (req, res) => {
    req.session.destroy(error => {
        if (error) {
            console.error(error);

            return res.status(500).json({
                message: "خطا در خروج."
            });
        }

        res.clearCookie("connect.sid");

        return res.json({
            message: "با موفقیت خارج شدید."
        });
    });
});

// خطاها
app.use((error, req, res, next) => {
    console.error(error);

    res.status(500).json({
        message: "خطای داخلی سرور."
    });
});

// راه‌اندازی سرور پس از آماده شدن دیتابیس
async function startServer() {
    try {
        await initializeDatabase();

        app.listen(PORT, "0.0.0.0", () => {
            console.log("================================");
            console.log("PIKSO GAMES SERVER IS RUNNING");
            console.log("DATABASE: CONNECTED");
            console.log("PORT: " + PORT);
            console.log("================================");
        });

    } catch (error) {
        console.error("Server startup error:", error);
        process.exit(1);
    }
}

startServer();
