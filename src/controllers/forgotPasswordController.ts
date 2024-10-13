import generateOTP from '../utils/otpGenerator.js'
import findUserByEmail from "../utils/findUserByEmail.js";
import bcrypt from 'bcrypt'
import sendOTPEmail from '../utils/sendOtpEmail.js';
import jwt from 'jsonwebtoken';
import { Request, Response } from 'express';
import { IUser } from '../models/User.js';

class ForgotPasswordController {

  static forgotPassword = async (req: Request, res: Response): Promise<Response> => {
    const { email }: { email?: string } = req.body;

    if (!email) {
      return res.status(400).json({
        status: "failed",
        message: "Email is required",
      });
    }
  
    try {
      const user: IUser | null = await findUserByEmail(email);

      if (!user) {
        return res.status(404).json({
          status: "failed",
          message: "User not found. Please register first",
        });
      }
      
      const otp: string = generateOTP();
      const salt: string = await bcrypt.genSalt(10);
      user.otp = await bcrypt.hash(otp, salt);
      user.otp_expiry = new Date(Date.now() + 5 * 60000); 
      await user.save();

      await sendOTPEmail(email, 'Forgot Password OTP', `Your forgot password OTP is ${otp}`);
  
      return res.status(200).json({
        status: "success",
        message: "OTP sent to your email.",
      });
  
    } catch (error: unknown) {
      console.error('Error in forgotPassword:', error) 
      return res.status(500).json({
        status: "failed",
        message: "Unable to send OTP",
      });
    }
  };

  static verifyForgotPasswordOtp = async (req: Request, res: Response): Promise<Response> => {
    const { email, otp }: { email: string; otp: string } = req.body;
  
  
    if (!email || !otp) {
      return res.status(400).json({
        status: "failed",
        message: "Missing required fields",
      });
    }
  
    try {
      const user: IUser | null = await findUserByEmail(email);
  
     
      if (!user) {
        return res.status(404).json({
          status: "failed",
          message: "User not found. Please register first",
        });
      }

      if (!user.otp || !(await bcrypt.compare(otp, user.otp))) {
        return res.status(400).json({
          status: "failed",
          message: "Invalid OTP",
        });
      }
      
      if (!user.otp_expiry || user.otp_expiry.getTime() < Date.now()) {
        return res.status(410).json({
          status: "failed",
          message: "OTP has expired",
        });
      }
      user.otp = null;
      user.otp_expiry = null;
      await user.save();
  
      const resetToken = jwt.sign(
        { email: user.email },
        process.env.JWT_SECRET as string,
        { expiresIn: '10m' }
      );
  
      const options = {
        httpOnly: true,
        secure: true,
      };
  
      return res.status(200)
        .cookie("resetToken", resetToken, options)
        .json({
          status: "success",
          message: "OTP verified, try to reset password",
          resetToken,
        });
  
    } catch (error: unknown) {
      console.error('Error in verifyForgotPasswordOtp:', error);
      return res.status(500).json({
        status: "failed",
        message: "Error verifying OTP. Try Forgot password again",
      });
    }
  };
  
  static setNewPassword = async (req: Request, res: Response): Promise<Response> => {
    const { password, confirm_password }: { password: string; confirm_password: string } = req.body;
  
    if (!password || !confirm_password) {
      return res.status(400).json({
        status: "failed",
        message: "Please provide both Password and Confirm Password",
      });
    }
  
    if (password !== confirm_password) {
      return res.status(400).json({
        status: "failed",
        message: "Password and Confirm Password don't match",
      });
    }
  
    try {

      const token = req.cookies?.resetToken || req.header("Authorization")?.replace("Bearer ", "");
      if (!token) {
        return res.status(401).json({
          status: "failed",
          message: "Unauthorized Request",
        });
      }

      const decodedToken = jwt.verify(token, process.env.JWT_SECRET as string) as { email: string };
      const user = await findUserByEmail(decodedToken.email);
  
      if (!user) {
        return res.status(400).json({
          status: "failed",
          message: "User not found",
        });
      }

      const salt = await bcrypt.genSalt(10);
      user.password = await bcrypt.hash(password, salt);
      await user.save();
  
      return res.status(200).json({
        status: "success",
        message: "Password updated successfully",
      });
  
    } catch (error) {
      console.error('Error in setNewPassword:', error);
      return res.status(500).json({
        status: "failed",
        message: "Error updating password",
      });
    }
  };
  

}


export default ForgotPasswordController;