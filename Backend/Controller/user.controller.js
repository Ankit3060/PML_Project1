import { User } from "../Models/user.model.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

  const validatePassword = (password) => {

    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumber = /\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

    return hasUpperCase && hasLowerCase && hasNumber && hasSpecialChar;
  };


export const registerUser = async (req, res) => {
    try {
        const {firstName, lastName, email, phone, gender, password} = req.body;
        // console.log("requested data:", req.body);
        

        if(!firstName || !lastName || !email || !phone || !password || !gender) {
            return res.status(400).json({success: false, message: "All fields are required"});
        }

        const existingUser = await User.findOne({email});
        if(existingUser) {
            return res.status(400).json({success: false, message: "User already exists"});
        }

        if(password.length < 8 || password.length > 20 || !validatePassword(password)) {
            return res.status(400).json({success: false, message: "Password must be between 8 to 20 characters incluuding at least one uppercase, lowercase, number, and special character"});
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = await User.create({
            firstName,
            lastName,
            email,
            phone,
            gender,
            password: hashedPassword
        });

        const token = newUser.generateToken();

        res.cookie("token", token, {
            expires: new Date(Date.now() + process.env.COOKIE_EXPIRE * 24 * 60 * 60 * 1000), 
            httpOnly: true,
        })

        res.status(201).json({
            status:200,
            success: true,
            message: "User registered successfully",
        });
        
    } catch (error) {
        // console.log("Registration Error:", error);
        res.status(500).json({
            success:false,
            message:"Internal Server Error"
        });
    }
}


export const loginUser = async (req, res) => {
    try {
        const {email, password} = req.body;

        if(!email || !password) {
            return res.status(400).json({success: false, message: "Email and password are required"});
        }

        const user = await User.findOne({email}).select("+password");

        if(!user) {
            return res.status(400).json({success: false, message: "Invalid email or password"});
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if(!isPasswordValid) {
            return res.status(400).json({success: false, message: "Invalid email or password"});
        }

        if(!validatePassword(password)) {
            return res.status(400).json({success: false, message: "Password must be between 8 to 20 characters including at least one uppercase, lowercase, number, and special character"});
        }

        const token = user.generateToken();

        res.cookie("token", token, {
            expires: new Date(Date.now() + process.env.COOKIE_EXPIRE * 24 * 60 * 60 * 1000), 
            httpOnly: true,
        });

        res.status(200).json({
            status:200,
            success: true,
            message: "User logged in successfully",
        });
    } catch (error) {
        res.status(500).json({
            success:false,
            message:"Internal Server Error"
        });
    }
}


export const logoutUser = async (req, res) => {
    try {
        res.cookie("token","",{
            httpOnly: true,
            expires: new Date(Date.now())
        }).json({
            status:200,
            success: true,
            message: "User logged out successfully"
        });
    } catch (error) {
        res.status(500).json({
            success:false,
            message:"Internal Server Error"
        });
    }
}


export const getUserDetails = async (req, res) => {
    try {
        const token = req.cookies.token;

        if (!token) {
            return res.status(401).json({ success: false, message: "Not authenticated" });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
        const user = await User.findById(decoded.id);

        if (!user) {
            return res.status(404).json({ success: false, message: "User not found" });
        }

        res.status(200).json({
            status:200,
            success: true,
            user 
        });
    } catch (error) {
        res.status(500).json({
            success:false,
            message:"Internal Server Error"
        });
    }
}


export const updateDetails = async (req, res) => {
    try {
        const { firstName, lastName, phone, gender, address, dob, qualification } = req.body;

        const token = req.cookies.token;
        if (!token) {
            return res.status(401).json({ success: false, message: "Not authenticated" });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
        const user = await User.findById(decoded.id);

        if (!user) {
            return res.status(404).json({ success: false, message: "User not found" });
        }

        user.firstName = firstName!=undefined ? firstName : user.firstName;
        // user.lastName = lastName || user.lastName;
        user.lastName = lastName != undefined ? lastName : user.lastName;
        user.phone = phone != undefined ? phone : user.phone;
        user.gender = gender != undefined ? gender : user.gender;
        user.address = address != undefined ? address : user.address;
        user.dob = dob ? new Date(dob) : user.dob;
        user.qualification = qualification != undefined ? qualification : user.qualification;

        await user.save();

        res.status(200).json({
            status : 200,
            success: true,
            message: "User details updated successfully",
            user
        });
    } catch (error) {
        console.error("Update Error:", error);
        res.status(500).json({
            success: false,
            message: "Internal Server Error"
        });
    }
};


export const updatePassword = async (req, res) => {
    try {
        const {newPassword, confirmPassword } = req.body;

        const token = req.cookies.token;

        if (!token) {
            return res.status(401).json({ success: false, message: "Not authenticated" });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
        const user = await User.findById(decoded.id).select("+password");
        if (!user) {
            return res.status(404).json({ success: false, message: "User not found" });
        }
        if (!newPassword || !confirmPassword ) {
            return res.status(400).json({ success: false, message: "New password and confirm password are required" });
        }
        if (newPassword !== confirmPassword) {
            return res.status(400).json({ success: false, message: "Passwords do not match" });
        }

        if(!validatePassword(newPassword)) {
            return res.status(400).json({success: false, message: "Password must be between 8 to 20 characters including at least one uppercase, lowercase, number, and special character"});
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        user.password = hashedPassword;
        await user.save();

        res.status(200).json({
            status:200,
            success: true,
            message: "Password updated successfully"
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: "Internal Server Error"
        });
    }
}


export const getAllUsers = async (req,res) =>{
    try {
        const token = req.cookies.token;
        if (!token) {
            return res.status(401).json({ success: false, message: "Not authenticated" });
        }

        const user = await User.find({}).select("-password -createdAt -updatedAt");
        if (!user) {
            return res.status(404).json({ success: false, message: "No users found" });
        }

        res.status(200).json({
            status: 200,
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
        const token = req.cookies.token;
        if (!token) {
            return res.status(401).json({ success: false, message: "Not authenticated" });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
        if(!decoded){
            return res.status(401).json({ success: false, message: "Invalid token" });
        }

        const { id } = req.params;
        const user = await User.findById(id).select("-password -createdAt -updatedAt");
        if (!user) {
            return res.status(404).json({ success: false, message: "No users found" });
        }

        res.status(200).json({
            status: 200,
            success: true,
            users: user
        });
    } catch (error) {
        res.status(500).json({
            success : false,
            message: "Internal Server Error"
        })
    }
}


export const deleteUser = async (req, res) => {
    try {
        const {id} = req.params;

        const token = req.cookies.token;
        if (!token) {
            return res.status(401).json({ success: false, message: "Not authenticated" });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
        if( !decoded || !decoded.id) {
            return res.status(401).json({ success: false, message: "Invalid token" });
        }

        const user = await User.findById(id);
        if (!user) {
            return res.status(404).json({ success: false, message: "User not found" });
        }

        await user.deleteOne();
        res.status(200).json({
            status: 200,
            success: true,
            message: "User deleted successfully"
        });


    } catch (error) {
        console.error("Delete Error:", error);
        res.status(500).json({
            success: false,
            message: "Internal Server Error"
        });
    }
}


export const updateUser = async (req, res) => {
    try {
        const { id } = req.params;
        const { firstName, lastName, phone, gender, dob, address, qualification } = req.body;

        if(!firstName || !lastName || !phone || !gender || !dob || !address || !qualification) {
            return res.status(400).json({ success: false, message: "All fields are required" });
        }

        const token = req.cookies.token;
        if (!token) {
            return res.status(401).json({ success: false, message: "Not authenticated" });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
        if (!decoded || !decoded.id) {
            return res.status(401).json({ success: false, message: "Invalid token" });
        }

        const user = await User.findById(id);
        if (!user) {
            return res.status(404).json({ success: false, message: "User not found" });
        }

        user.firstName = firstName;
        user.lastName = lastName;
        user.phone = phone;
        user.gender = gender;
        user.dob = new Date(dob);
        user.address = address;
        user.qualification = qualification;

        await user.save();

        res.status(200).json({
            status: 200,
            success: true,
            user
        });
    } catch (error) {
        console.error("Update User Error:", error);
        res.status(500).json({
            success: false,
            message: "Internal Server Error"
        });
        
    }
}


export const createUser = async (req, res) => {
    try {
        const token = req.cookies.token;
        if (!token) {
            return res.status(401).json({ success: false, message: "Not authenticated" });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
        if (!decoded) {
            return res.status(401).json({ success: false, message: "Invalid token" });
        }

        const { firstName, lastName, email, phone, gender, password } = req.body;
        if (!firstName || !lastName || !email || !phone || !gender || !password) {
            return res.status(400).json({ success: false, message: "All fields are required" });
        }

        const existingUser = await User.findOne({ email});
        if (existingUser) {
            return res.status(400).json({ success: false, message: "User already exists" });
        }

        if (password.length < 8 || password.length > 20 || !validatePassword(password)) {
            return res.status(400).json({ success: false, message: "Password must be between 8 to 20 characters including at least one uppercase, lowercase, number, and special character" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = await User.create({
            firstName,
            lastName,
            email,
            phone,
            gender,
            password: hashedPassword
        })

        res.status(201).json({
            status: 201,
            success: true,
            message: "User created successfully",
            user: newUser
        });

    } catch (error) {
        console.error("Create User Error:", error);
        res.status(500).json({
            success: false,
            message: "Internal Server Error"
        });
    }
}