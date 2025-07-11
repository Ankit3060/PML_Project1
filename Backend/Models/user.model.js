import mongoose from "mongoose";
import jwt from "jsonwebtoken";

const userSchema = new mongoose.Schema({
    firstName: {
        type: String,
        required: false
    },
    lastName: {
        type: String,
        required: false
    },
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
    },
    password: {
        type: String,
        required: true,
        select: false
    },
    phone: {
        type: Number,
        required: false,
        unique: true
    },
    gender:{
        type: String,
        enum: ["Male", "Female", "Other"],
        default: "Other"
    },
    address: {
        type: String,
        required: false,
    },
    dob: {
        type: Date,
        required: false,
        // max : [Date.now, "cannot choose future date"],
    // validate: {
    //   validator: function (value) {
    //     return value <= new Date();
    //   },
    //   message: 'Date of Birth cannot be in the future.'
    // }
    // min: '1900-01-01',
    // max: '2007-01-01'

    },
    qualification: {
        type: String,
        required: false,
    },
    memberSince: {
        type: Date,
        default: Date.now
    }
},{
    timestamps: true
});



userSchema.methods.generateToken = function () {
    return jwt.sign(
        { id: this._id }, 
        process.env.JWT_SECRET_KEY, 
        { expiresIn: process.env.JWT_EXPIRE });
}


export const User = mongoose.model("User", userSchema);