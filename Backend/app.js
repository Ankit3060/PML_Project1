import express,{urlencoded} from "express";
import cookieParser from "cookie-parser";
import { config } from "dotenv";
import cors from "cors";
import { connectDB } from "./Database/db.js";
import userRouter from "./Routes/user.router.js";

export const app = express();

config({path: "./Config/config.env"});

app.use(cors({
    origin : [process.env.FRONTEND_URL],
    methods : ["GET", "POST", "DELETE", "PUT"],
    credentials : true
}));

app.use(cookieParser());
app.use(urlencoded({extended: true}));
app.use(express.json());


app.use("/api/v1/user",userRouter);

connectDB();


