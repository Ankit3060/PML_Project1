import express from "express";
import { registerUser, 
        loginUser, 
        logoutUser, 
        getUserDetails, 
        updateDetails,
        updatePassword,
        getAllUsers,
        deleteUser,
        getUserById,
        updateUser,
        createUser
    } from "../Controller/user.controller.js";
import { verifyApiKey } from "../Middleware/apiKeyAuth.js";
import { isAuthenticated } from "../Middleware/authentication.js";


const router = express.Router();

// router.post("/register",verifyApiKey ,registerUser);
router.post("/register",registerUser);
router.post("/login",loginUser);
router.get("/logout", isAuthenticated ,logoutUser);
router.get("/me", isAuthenticated ,getUserDetails);
router.put("/update", isAuthenticated ,updateDetails);
router.put("/update-password", isAuthenticated ,updatePassword);
router.get("/all", isAuthenticated ,getAllUsers);
router.delete("/delete/:id", isAuthenticated ,deleteUser);
router.get("/:id", isAuthenticated ,getUserById);
router.put("/update/:id", isAuthenticated ,updateUser);
router.post("/create", isAuthenticated ,createUser);

export default router;