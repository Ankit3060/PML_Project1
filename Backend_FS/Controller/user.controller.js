import fs from "fs";
import path from "path";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const usersFilePath = path.join(__dirname, "../Data/users.json");


const readUsers = () => {
    if (!fs.existsSync(usersFilePath)) return [];
    const data = fs.readFileSync(usersFilePath);
    return JSON.parse(data);
};

const writeUsers = (users) => {
    fs.writeFileSync(usersFilePath, JSON.stringify(users, null, 2));
};

const validatePassword = (password) => {
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumber = /\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);
    return hasUpperCase && hasLowerCase && hasNumber && hasSpecialChar && password.length >= 8 && password.length <= 20;
};

const generateToken = (id) => {
    return jwt.sign(
        { id }, 
        process.env.JWT_SECRET_KEY, 
        { expiresIn: process.env.JWT_EXPIRE });
};


export const registerUser = async (req, res) => {
    try {
        const { firstName, lastName, email, phone, gender, password } = req.body;
        if (!firstName || !lastName || !email || !phone || !password || !gender) {
            return res.status(400).json({ success: false, message: "All fields are required" });
        }

        let users = readUsers();

        const existingUser = users.find(user => user.email === email);
        if (existingUser) {
            return res.status(400).json({ success: false, message: "User already exists" });
        }

        const existingPhoneNumber = users.find(user => user.phone === phone);
        if (existingPhoneNumber) {
            return res.status(400).json({ success: false, message: "Phone number already exists" });
        }

        if (!validatePassword(password)) {
            return res.status(400).json({ success: false, message: "Password must meet the criteria" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = {
            id: Date.now().toString(),
            firstName,
            lastName,
            email,
            phone,
            gender,
            password: hashedPassword,
            createdAt: new Date().toISOString(),
        };

        users.push(newUser);
        writeUsers(users);

        const token = generateToken(newUser.id);

        res.cookie("token", token, {
            expires: new Date(Date.now() + process.env.COOKIE_EXPIRE * 24 * 60 * 60 * 1000),
            httpOnly: true,
        });

        res.status(201).json({
            status : 200,
            success: true, 
            token,
            message: "User registered successfully" 
        });
    } catch (err) {
        res.status(500).json({ 
            success: false, 
            message: "Internal Server Error" 
        });
    }
};


export const loginUser = async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ success: false, message: "Email and password are required" });
        }

        let users = readUsers();
        const user = users.find(user => user.email === email);

        const isPasswordValid = await bcrypt.compare(password, user.password);

        if(!user || !isPasswordValid) {
            return res.status(400).json({ success: false, message: "Invalid email or password" });
        }

        const token = generateToken(user.id);

        res.cookie("token", token, {
            expires: new Date(Date.now() + process.env.COOKIE_EXPIRE * 24 * 60 * 60 * 1000),
            httpOnly: true,
        });

        res.status(200).json({ 
            status: 200,
            token,
            success: true, 
            message: "User logged in successfully" 
        });
    } catch (err) {
        res.status(500).json({ 
            success: false, 
            message: "Internal Server Error" 
        });
    }
};


export const logoutUser = async (req, res) => {
    try {
        res.cookie("token", "", {
            httpOnly: true,
            expires: new Date(Date.now()),
        }).json({ 
            status : 200,
            success: true, 
            message: "User logged out successfully" 
        });
    } catch (err) {
        res.status(500).json({ 
            success: false, 
            message: "Internal Server Error" 
        });
    }
};


export const getUserDetails = async (req, res) => {
    try {
        const users = readUsers();
        const user = users.find(u => u.id === req.user.id);

        if (!user) {
            return res.status(404).json({ success: false, message: "User not found" });
        }

        const { password, ...userData } = user;

        res.status(200).json({ 
            status : 200,
            success: true,
            user: userData 
        });
    } catch (err) {
        res.status(500).json({ 
            success: false, 
            message: "Internal Server Error" 
        });
    }
};


export const updateDetails = async (req, res) => {
    try {
        const { firstName, lastName, phone, gender, address, dob, qualification } = req.body;

        let users = readUsers();
        const userIndex = users.findIndex(u => u.id === req.user.id);

        if (userIndex === -1) {
            return res.status(404).json({ success: false, message: "User not found" });
        }

        // const isPhoneExisting = users.find(u=>u.phone===phone)
        // if(isPhoneExisting){
        //     return res.status(400).json({ 
        //         success: false, 
        //         message: "Phone number already exists" 
        //     });
        // }

        const user = users[userIndex];
        
        const updatingUser = {
            firstName: firstName,
            lastName: lastName,
            phone: phone,
            gender: gender,
            address: address,
            dob: dob ? new Date(dob).toISOString() : user.dob,
            qualification: qualification
        };

        const updatedUser = { ...user, ...updatingUser };

        users[userIndex] = updatedUser;
        writeUsers(users);

        const { password, ...userData } = updatedUser;

        res.status(200).json({ 
            status : 200,
            success: true, 
            message: "User details updated successfully", 
            user: userData 
        });
    } catch (err) {
        res.status(500).json({ 
            success: false, 
            message: "Internal Server Error" 
        });
    }
};


export const updatePassword = async (req, res) => {
    try {
        const { newPassword, confirmPassword } = req.body;

        if (!newPassword || !confirmPassword) {
            return res.status(400).json({ success: false, message: "Both passwords are required" });
        }

        if (newPassword !== confirmPassword) {
            return res.status(400).json({ success: false, message: "Passwords do not match" });
        }

        if (!validatePassword(newPassword)) {
            return res.status(400).json({ success: false, message: "Password does not meet security criteria" });
        }

        let users = readUsers();
        const userIndex = users.findIndex(u => u.id === req.user.id);

        if (userIndex === -1) {
            return res.status(404).json({ success: false, message: "User not found" });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        users[userIndex].password = hashedPassword;

        writeUsers(users);

        res.status(200).json({ 
            status : 200,
            success: true, 
            message: "Password updated successfully" 
        });
    } catch (err) {
        res.status(500).json({ 
            success: false, 
            message: "Internal Server Error" 
        });
    }
};


export const getAllUsers = async (req, res) => {
    try {

        let user = readUsers();
        user = user.map(({ password, ...rest }) => rest);

        res.status(200).json({ 
            status : 200,
            success: true, 
            users: user 
        });
    } catch (error) {
        res.status(500).json({ 
            success: false, 
            message: "Internal Server Error" 
        });
    }
}


export const getUserById = async (req, res) => {
    try {
        const { id } = req.params;
        let users = readUsers();
        const user = users.find(u => u.id === id);

        if (!user) {
            return res.status(404).json({ success: false, message: "User not found" });
        }

        const { password, ...userData } = user;

        res.status(200).json({ 
            status : 200,
            success: true, 
            user: userData 
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: "Internal Server Error"
        });
    }
}


export const deleteUser = async (req, res) =>{
    try {

        const {id} = req.params;
        let users = readUsers();
        const userIndex = users.findIndex(user => user.id === id);
        if(userIndex === -1) {
            return res.status(404).json({
                success: false,
                message: "User not found"
            });
        }

        const deletedUser = users.splice(userIndex, 1);
        writeUsers(users);

        res.status(200).json({
            success: true,
            message: "User deleted successfully",
            user: deletedUser
        });

    } catch (error) {
        res.status(500).json({
            success: false,
            message: "Internal Server Error"
        });
    }
}


export const updateUser = async (req,res) =>{
    try {
        const { id } = req.params;
        const {firstName, lastName, phone, gender, address, dob, qualification} = req.body;

        if(!firstName || !lastName || !phone || !gender || !address || !dob || !qualification) {
            return res.status(400).json({
                success: false,
                message: "All fields are required"
            });
        }

        let users = readUsers();
        const userIndex = users.findIndex(u => u.id === id);
        if(userIndex === -1) {
            return res.status(404).json({
                success: false,
                message: "User not found"
            });
        }

        const user = users[userIndex];

        const updatingUser = {
            firstName: firstName,
            lastName: lastName,
            phone: phone,
            gender: gender,
            address: address,
            dob: dob ? new Date(dob).toISOString() : user.dob,
            qualification: qualification
        }

        const updatedUser = { ...user, ...updatingUser };

        users[userIndex] = updatedUser;
        writeUsers(users);

        const { password, ...userData } = updatedUser;

        res.status(200).json({
            status: 200,
            success: true,
            message: "User updated successfully",
            user: userData
        });

    } catch (error) {
        res.status(500).json({
            success: false,
            message: "Internal Server Error"
        });
    }
}


export const createUser = async (req, res) => {
    try {

        const {firstName, lastName, email, phone, gender, password} = req.body;
        if (!firstName || !lastName || !email || !phone || !gender || !password) {
            return res.status(400).json({
                success: false,
                message: "All fields are required"
            });
        }

        let users = readUsers();
        const existingUser = users.find(user => user.email === email);
        if (existingUser) {
            return res.status(400).json({
                success: false,
                message: "User already exists with this email"
            });
        }

        const existingPhoneNumber = users.find(user => user.phone === phone);
        if (existingPhoneNumber) {
            return res.status(400).json({
                success: false,
                message: "Phone number already exists"
            });
        }
        if (!validatePassword(password)) {
            return res.status(400).json({
                success: false,
                message: "Password must meet the criteria"
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser ={
            id: Date.now().toString(),
            firstName,
            lastName,
            email,
            phone,
            gender,
            password: hashedPassword,
            createdAt: new Date().toISOString(),
        }

        users.push(newUser);
        writeUsers(users);

        const {password:_, ...user} = newUser;

        res.status(201).json({
            success: true,
            message: "User created successfully",
            user: user
        });

    } catch (error) {
        res.status(500).json({
            success: false,
            message: "Internal Server Error"
        });
        
    }
}