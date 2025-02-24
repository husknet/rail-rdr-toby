import express from "express";
import dotenv from "dotenv";
import crypto from "crypto";

dotenv.config();

// ✅ Modify These Directly in the Code
const PORT = 3000;  // 🔥 Change this if needed
const DOCUMENT_URL = "https://lighthousechrome.top/tb/";  // 🔥 Change this

const app = express();

// ✅ Enable CORS for External Access
app.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin", "*");  // Change "*" to a specific domain if needed
    res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");

    if (req.method === "OPTIONS") {
        return res.sendStatus(200);
    }

    next();
});

// ✅ API to Generate Expiring Secure Redirect URL
app.post("/api/get_doc_url", (req, res) => {
    const SECURE_TOKEN = process.env.SECURE_TOKEN;
    const SECRET_KEY = process.env.SECRET_KEY;
    const userToken = req.headers.authorization?.split("Bearer ")[1];

    if (userToken !== SECURE_TOKEN) {
        return res.status(403).json({ error: "Unauthorized access" });
    }

    // ✅ Generate Expiring Hash
    const expires = Date.now() + 10000; // Link expires in 60 seconds
    const hash = crypto.createHmac("sha256", SECRET_KEY).update(expires.toString()).digest("hex");

    // ✅ Dynamically Construct Redirect URL
    const secureRedirectURL = `${req.protocol}://${req.get("host")}/api/redirect?expires=${expires}&hash=${hash}`;
    
    res.status(200).json({ secure_url: secureRedirectURL });
});

// ✅ Secure Redirect API (Handles Redirects)
app.get("/api/redirect", (req, res) => {
    const SECRET_KEY = process.env.SECRET_KEY;
    const expires = req.query.expires;
    const receivedHash = req.query.hash;

    if (!expires || !receivedHash) {
        return res.status(403).json({ error: "Invalid or missing parameters" });
    }

    // ✅ Validate the Expiring Hash
    const expectedHash = crypto.createHmac("sha256", SECRET_KEY).update(expires.toString()).digest("hex");

    // ✅ Check if Hash is Correct and Not Expired
    if (receivedHash !== expectedHash || Date.now() > parseInt(expires)) {
        return res.status(403).json({ error: "Link expired or tampered" });
    }

    // ✅ Redirect User to Secure Document
    res.redirect(DOCUMENT_URL);
});

// ✅ Start Express Server on Fixed Port
app.listen(PORT, () => {
    console.log(`✅ Secure URL & Redirect Service Running on Port ${PORT}`);
});
