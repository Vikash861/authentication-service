import mongoose, { Schema, Document } from "mongoose";

export interface ITempUser extends Document {
  name: string;
  email: string;
  password: string;
  otp: string;
  otp_expiry: Date | null;
  tc: boolean;
}

const TempUserSchema: Schema = new Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, trim: true },
  password: { type: String, required: true, trim: true },
  otp: { type: String, required: true, trim: true },
  otp_expiry: { type: Date, default: null },
  tc: { type: Boolean, required: true }
});


const TempUserModel = mongoose.model<ITempUser>("TempUser", TempUserSchema);

export default TempUserModel;
