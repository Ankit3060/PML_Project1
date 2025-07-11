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



const router = express.Router();

router.post("/register",verifyApiKey ,registerUser);
router.post("/login", verifyApiKey ,loginUser);
router.get("/logout", verifyApiKey ,logoutUser);
router.get("/me", verifyApiKey ,getUserDetails);
router.put("/update", verifyApiKey ,updateDetails);
router.put("/update-password", verifyApiKey ,updatePassword);
router.get("/all", verifyApiKey ,getAllUsers);
router.delete("/delete/:id", verifyApiKey ,deleteUser);
router.get("/:id", verifyApiKey ,getUserById);
router.put("/update/:id", verifyApiKey ,updateUser);
router.post("/create", verifyApiKey ,createUser);

export default router;