const express = require("express");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const requestLogger = require("./middleware/logger");
const authMiddleware = require("./middleware/auth"); 

const app = express();
const PORT = process.env.PORT || 3000;
const APP_SECRET = process.env.APPLICATION_SECRET || "default-secret-key";

const loginSessions = {};
const otpStore = {};

app.use(express.json());
app.use(cookieParser()); 
app.use(requestLogger);

app.get("/", (req, res) => {
  res.json({ challenge: "Complete the Authentication Flow" });
});

// TASK 1: LOGIN
app.post("/auth/login", (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Email/Password required" });

    const loginSessionId = Math.random().toString(36).substring(7);
    const otp = Math.floor(100000 + Math.random() * 900000);

    loginSessions[loginSessionId] = {
      email,
      expiresAt: Date.now() + 2 * 60 * 1000,
    };
    otpStore[loginSessionId] = otp;

    console.log(`[OTP] Session ${loginSessionId} generated: ${otp}`);
    return res.status(200).json({ message: "OTP sent", loginSessionId });
  } catch (error) {
    return res.status(500).json({ message: "Login failed" });
  }
});

// TASK 2: VERIFY OTP
app.post("/auth/verify-otp", (req, res) => {
  try {
    const { loginSessionId, otp } = req.body;
    const session = loginSessions[loginSessionId];

    if (!session || Date.now() > session.expiresAt) {
      return res.status(401).json({ error: "Invalid or expired session" });
    }

    if (Number(otp) !== otpStore[loginSessionId]) {
      return res.status(401).json({ error: "Invalid OTP" });
    }

    res.cookie("session_token", loginSessionId, {
      httpOnly: true,
      maxAge: 15 * 60 * 1000,
    });

    return res.status(200).json({ message: "OTP verified" });
  } catch (error) {
    return res.status(500).json({ message: "Verification failed" });
  }
});

// TASK 3: TOKEN GENERATION
app.post("/auth/token", (req, res) => {
  try {
    const sessionToken = req.cookies.session_token;
    if (!sessionToken) return res.status(401).json({ error: "No session cookie" });

    const session = loginSessions[sessionToken];
    if (!session) return res.status(401).json({ error: "Invalid session" });

    const accessToken = jwt.sign(
      { email: session.email, sessionId: sessionToken },
      APP_SECRET,
      { expiresIn: "15m" }
    );

    return res.status(200).json({ access_token: accessToken });
  } catch (error) {
    return res.status(500).json({ message: "Token generation failed" });
  }
});

// TASK 4: PROTECTED ROUTE
app.get("/protected", authMiddleware, (req, res) => {
  const email = req.user.email;
  return res.json({
    message: "Access granted",
    user: req.user,
    success_flag: `FLAG-${Buffer.from(email + "_COMPLETED").toString('base64')}`,
  });
});

app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));