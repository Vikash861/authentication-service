import UserModel, { IUser } from '../models/User.js'
import bcrypt from 'bcrypt'
import jwt, { JwtPayload } from 'jsonwebtoken';
import generateOTP from '../utils/otpGenerator.js'
import sendOTPEmail from '../utils/sendOtpEmail.js'
import { Request, Response } from 'express';
import { CustomRequest } from '../middlewares/auth-middleware.js';

interface IUserRequest extends Request {
  user: IUser
}


interface DecodedToken extends JwtPayload {
  _id: string;
}


class genericController {

  static changeUserPassword = async (req: CustomRequest, res: Response): Promise<Response> => {
    const { password, password_confirmation }: { password: string; password_confirmation: string } = req.body;

    if (!password || !password_confirmation) {
      return res.status(400).json({
        status: "failed",
        message: "All fields are required",
      });
    }

    if (password !== password_confirmation) {
      return res.status(400).json({
        status: "failed",
        message: "New Password and Confirm New Password don't match",
      });
    }

    try {

      const newHashPassword = await bcrypt.hash(password, 10);
      await UserModel.findByIdAndUpdate(req.user?._id, { password: newHashPassword });

      return res.status(200).json({
        status: "success",
        message: "Password changed successfully",
      });
    } catch (error) {
      console.error("Error changing password:", error);
      return res.status(500).json({
        status: "error",
        message: "Internal server error",
      });
    }
  };


  static loggedUser = async (req: CustomRequest, res: Response): Promise<Response> => {
    return res.send({ user: req.user });
  };

  static logout = async (req: CustomRequest, res: Response): Promise<Response> => {
    try {

      if(!req.user){
        return res.status(401).json({ status: "failed", message: "Unauthorized request" });
      }

      await UserModel.findByIdAndUpdate(
        req.user._id,
        {
          $unset: {
            refreshToken: 1
          },
          $set: {
            logoutAt: new Date()
          }
        },
        {
          new: true
        }
      );

      const options: { httpOnly: boolean; secure: boolean } = {
        httpOnly: true,
        secure: true
      };

      return res
        .status(200)
        .clearCookie("accessToken", options)
        .clearCookie("refreshToken", options)
        .send({ status: "success", message: "user logged out" });
    } catch (error) {
      console.error(error);
      return res.status(500).send({ status: "failed", message: "unable to log out user" });
    }
  };

  static refreshToken = async (req: Request, res: Response): Promise<Response> => {
    try {
      const incomingRefreshToken: string | undefined = req.cookies.refreshToken || req.body.refreshToken;
      if (!incomingRefreshToken) {
        return res.status(401).send({ status: "failed", message: "Unauthorized request" });
      }

      const secret = process.env.REFRESH_TOKEN_SECRET;
      if (!secret) {
        console.error('Missing refresh token secret');
        return res.status(500).send({ status: "failed", message: "Server error" });
      }

      const decodedToken = jwt.verify(incomingRefreshToken, secret) as DecodedToken;
      const user = await UserModel.findById(decodedToken?._id);

      if (!user || incomingRefreshToken !== user.refreshToken) {
        return res.status(401).send({ status: "failed", message: "Invalid or expired refresh token" });
      }

      const { accessToken, refreshToken } = await user.generateAccessAndRefreshToken();
      const options = { httpOnly: true, secure: true };

      return res
        .status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", refreshToken, options)
        .send({
          status: "success",
          message: "Access Token refreshed",
          accessToken,
          refreshToken
        });
    } catch (error) {
      console.error(error);
      return res.status(500).send({ status: "failed", message: "Unable to refresh token" });
    }
  };

  static resendOtp = async (req: Request, res: Response): Promise<Response> => {
    const { email }: { email: string } = req.body;

    if (!email) {
      return res.status(400).json({ status: "failed", message: "Email is required" });
    }

    try {
      const user: IUser | null = await UserModel.findOne({ email });

      if (!user) {
        return res.status(404).json({ status: "failed", message: "User not found. Try to register" });
      }

      const otp: string = generateOTP();
      const salt: string = await bcrypt.genSalt(10);
      const hashedOtp: string = await bcrypt.hash(otp, salt);

      user.otp = hashedOtp;
      user.otp_expiry = new Date(Date.now() + 5 * 60000);
      await user.save();

      await sendOTPEmail(email, 'Resend OTP', `Your OTP is ${otp}`);

      return res.status(200).send({
        status: "success",
        message: "OTP sent to your email. Verify it to complete login.",
      });
    } catch (error) {
      console.error("Error in resending OTP:", error);
      return res.status(500).json({ status: "failed", message: "An error occurred. Please try again later." });
    }
  };


}

export default genericController