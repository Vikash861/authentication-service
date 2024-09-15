import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, trim: true },
  password: { type: String, required: true, trim: true },
  otp: { type: String, default: null },
  otp_expiry: { type: Date, default: null },
  tc: { type: Boolean, required: true }
})

const UserModel = mongoose.model("user", userSchema)

export default UserModel