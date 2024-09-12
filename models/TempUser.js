import mongoose from "mongoose";

const TempUserSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, trim: true },
  password: { type: String, required: true, trim: true },
  otp: { type: String, required: true, trim: true},
  tc: { type: Boolean, required: true }
})

const TempUserModel = mongoose.model("TempUser", TempUserSchema)

export default TempUserModel