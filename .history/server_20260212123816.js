const express = require("express");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const requestLogger = require("./middleware/logger");
const authMiddleware = require("./middleware/auth"); 

const app = express();
const PORT = process.env.PORT || 3000;

const loginSessions = {};
const otpStore = {};

// --- MIDDLEWARE FIXES ---
app.use(express.json());
app.use(cookieParser()); // FIX: Must include cookieParser to read cookies in Task 3
if (requestLogger) app.use(requestLogger);

app.get("/", (req, res) => {
  res.json({ challenge: "Complete the Authentication Flow" });
});

// --- TASK 1: FIX LOGIN ---
app.post("/auth/login", (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Email/Password required" });

    const loginSessionId = Math.random().toString(36).substring(7);
    const otp = Math.floor(100000 + Math.random() * 900000);

    loginSessions[loginSessionId] = {
      email,
      createdAt: Date.now(),
      expiresAt: Date.now() + 2 * 60 * 1000,
    };
    otpStore[loginSessionId] = otp;

    // FIX: You must log the actual OTP so you can see it in the terminal
    console.log(`[OTP] Session ${loginSessionId} generated: ${otp}`);

    return res.status(200).json({ message: "OTP sent", loginSessionId });
  } catch (error) {
    return res.status(500).json({ message: "Login failed" });
  }
});

// --- TASK 2: FIX OTP VERIFICATION ---
app.post("/auth/verify-otp", (req, res) => {
  try {
    const { loginSessionId, otp } = req.body;
    const session = loginSessions[loginSessionId];

    if (!session || Date.now() > session.expiresAt) {
      return res.status(401).json({ error: "Invalid or expired session" });
    }

    // FIX: Using loose inequality (!=) or Number() check to handle string vs number inputs
    if (Number(otp) !== otpStore[loginSessionId]) {
      return res.status(401).json({ error: "Invalid OTP" });
    }

    // Set the cookie for Task 3
    res.cookie("session_token", loginSessionId, {
      httpOnly: true,
      secure: false, // Set to true if using HTTPS
      maxAge: 15 * 60 * 1000,
    });

    delete otpStore[loginSessionId];
    return res.status(200).json({ message: "OTP verified" });
  } catch (error) {
    return res.status(500).json({ message: "Verification failed" });
  }
});

// --- TASK 3: FIX TOKEN GENERATION ---
app.post("/auth/token", (req, res) => {
  try {
    // FIX: The assignment says to exchange the cookie for a JWT. 
    // Your code was looking at headers; it should look at cookies.
    const sessionToken = req.cookies.session_token;

    if (!sessionToken) {
      return res.status(401).json({ error: "Unauthorized - session cookie required" });
    }

    const session = loginSessions[sessionToken];
    if (!session) return res.status(401).json({ error: "Invalid session" });

    const secret = process.env.JWT_SECRET || "default-secret-key";
    const accessToken = jwt.sign(
      { email: session.email, sessionId: sessionToken },
      secret,
      { expiresIn: "15m" }
    );

    return res.status(200).json({ access_token: accessToken });
  } catch (error) {
    return res.status(500).json({ message: "Token generation failed" });
  }
});

// --- TASK 4: PROTECTED ROUTE ---
app.get("/protected", authMiddleware, (req, res) => {
  // Ensure your middleware calls next() so this block executes!
  return res.json({
    message: "Access granted",
    user: req.user,
    success_flag: `FLAG-${Buffer.from(req.user.email + "_COMPLETED_ASSIGNMENT").toString('base64')}`,
  });
});

app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));