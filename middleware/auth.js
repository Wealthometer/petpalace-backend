import clerk from "@clerk/backend";

const { verifySignature } = clerk;

export const verifyToken = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Missing or invalid authorization header" })
    }

    const token = authHeader.substring(7)

    // Verify Clerk session
    const payload = await verifySignature({
      header: authHeader,
      body: "",
      secret: process.env.CLERK_SECRET_KEY,
    })

    // Extract user ID from token claims
    if (req.body && req.body.userId) {
      req.userId = req.body.userId
    } else {
      req.userId = payload.sub
    }

    next()
  } catch (error) {
    console.error("Token verification error:", error)
    res.status(401).json({ error: "Invalid or expired token" })
  }
}

export const requireAdmin = async (req, res, next) => {
  try {
    // In production, verify admin role from Clerk custom claims
    const adminIds = (process.env.ADMIN_USER_IDS || "").split(",").filter(Boolean)
    if (!adminIds.includes(req.userId)) {
      return res.status(403).json({ error: "Admin access required" })
    }
    next()
  } catch (error) {
    res.status(403).json({ error: "Admin verification failed" })
  }
}
