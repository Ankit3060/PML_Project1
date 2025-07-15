import jwt from "jsonwebtoken";
import User from "../Models/user.model.js";

export const isAuthenticated = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ 
        success: false, 
        message: "No token provided" 
        });
    }
    
    const token = authHeader.split(" ")[1];
    
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
        const user = await User.findById(decoded.id);
    
        if (!user) {
        return res.status(404).json({ 
            success: false, 
            message: "User not found" 
        });
        }
    
        req.user = user;
        next();
    } catch (error) {
        return res.status(401).json({ 
        success: false, 
        message: "Invalid or expired token" 
        });
    }
}