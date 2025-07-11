import mongoose from "mongoose";

export const connectDB = async () => {
    mongoose.connect(process.env.MONGO_URI,{
        dbName : "PML_PROJECT_1"
    }).then(()=>{
        console.log("DB Connected Successfully");
    }).catch((err)=>{
        console.log("Error in connecting the DB",err);
    })
}