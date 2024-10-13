import mongoose, { Schema, Document } from "mongoose";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

export interface IUser extends Document {
  name: string;
  email: string;
  password: string;
  otp?: string | null;
  otp_expiry?: Date | null;
  refreshToken?: string;
  tc: boolean;
  logoutAt?: Date | null;
  isPasswordCorrect(password: string): Promise<boolean>;
  generateAccessToken(): string;
  generateRefreshToken(): string;
  generateAccessAndRefreshToken(): Promise<{ accessToken: string; refreshToken: string }>;
}

const userSchema: Schema<IUser> = new Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, trim: true },
  password: { type: String, required: true, trim: true },
  otp: { type: String, default: null },
  otp_expiry: { type: Date, default: null },
  refreshToken: { type: String },
  tc: { type: Boolean, required: true },
  logoutAt: { type: Date, default: null },
});

userSchema.methods.isPasswordCorrect = async function (password: string): Promise<boolean> {
  return await bcrypt.compare(password, this.password);
};

userSchema.methods.generateAccessToken = function (): string {
  return jwt.sign(
    {
      _id: this._id,
      email: this.email,
    },
    process.env.ACCESS_TOKEN_SECRET as string,
    {
      expiresIn: process.env.ACCESS_TOKEN_EXPIRY,
    }
  );
};

userSchema.methods.generateRefreshToken = function (): string {
  return jwt.sign(
    {
      _id: this._id,
    },
    process.env.REFRESH_TOKEN_SECRET as string,
    {
      expiresIn: process.env.REFRESH_TOKEN_EXPIRY,
    }
  );
};

userSchema.methods.generateAccessAndRefreshToken = async function (): Promise<{
  accessToken: string;
  refreshToken: string;
}> {
  const accessToken = this.generateAccessToken();
  const refreshToken = this.generateRefreshToken();
  this.refreshToken = refreshToken;
  await this.save();
  return { accessToken, refreshToken };
};

const UserModel = mongoose.model<IUser>("User", userSchema);

export default UserModel;
