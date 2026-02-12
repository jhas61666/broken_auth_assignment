const jwt = require("jsonwebtoken");

module.exports = function (req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Unauthorized - No Token" });
  }

  try {
    const secret = process.env.APPLICATION_SECRET || "default-secret-key";
    const token = authHeader.replace("Bearer ", "");
    const decoded = jwt.verify(token, secret);
    req.user = decoded;
    
    next(); // Allows access to /protected
  } catch (error) {
    return res.status(401).json({ error: "Invalid token" });
  }
};