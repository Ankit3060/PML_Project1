import jwt from "jsonwebtoken";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const usersFilePath = path.join(__dirname, "../Data/users.json");

const readUsers = () => {
    if (!fs.existsSync(usersFilePath)) return [];
    const data = fs.readFileSync(usersFilePath);
    return JSON.parse(data);
};

export const isAuthenticated = (req, res, next) => {
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
        const users = readUsers();
        const user = users.find(u => u.id === decoded.id);

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
};
