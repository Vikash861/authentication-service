import { Request, Response } from 'express';
import UserModel from '../models/User.js';
import TempUserModel, { ITempUser } from '../models/TempUser.js';
import bcrypt from 'bcrypt';
import generateOTP from '../utils/otpGenerator.js';
import sendOTPEmail from '../utils/sendOtpEmail.js';

interface TokenOptions {
  httpOnly: boolean;
  secure: boolean;
}

class RegisterController {
  
  static userRegistration = async (req: Request, res: Response): Promise<Response> => {
    const { name, email, password, password_confirmation, tc }:
      { name: string; email: string; password: string; password_confirmation: string; tc: boolean } = req.body;

    if (name && email && password && password_confirmation && tc) {
      if (password === password_confirmation) {
        try {
          const user = await UserModel.findOne({ email: email });
          if (user) {
            return res.status(409).send({ status: "failed", message: "Email already exists please try to login" });
          }
          await TempUserModel.deleteMany({ email });

          const otp = generateOTP();
          const salt = await bcrypt.genSalt(10);
          const hashPassword = await bcrypt.hash(password, salt);
          const hashedOtp = await bcrypt.hash(otp, salt);

          const tempUser = new TempUserModel({
            name,
            email,
            password: hashPassword,
            otp: hashedOtp,
            otp_expiry: Date.now() + 5 * 60000,
            tc
          });

          await tempUser.save();

          await sendOTPEmail(email, 'Registration OTP', `Your OTP for registration is ${otp}`);

          return res.status(200).send({ status: "success", message: "OTP sent to your email. Verify it to complete registration." });
        } catch (error) {
          console.log(error);
          return res.status(500).send({ status: "failed", message: "Unable to send OTP. Please verify your Email" });
        }
      } else {
        return res.send({ status: "failed", message: "Password and Confirm Password don't match" });
      }
    } else {
      return res.send({ status: "failed", message: "All fields are required" });
    }
  };

  static verifyOtp = async (req: Request, res: Response): Promise<Response> => {
    const { email, otp }: { email: string; otp: string } = req.body;

    if (!email || !otp) {
      return res.status(400).send({ status: "failed", message: "Missing required fields" });
    }

    try {
      const tempUser: ITempUser | null = await TempUserModel.findOne({ email });

      if (!tempUser) {
        const isRegistered = await UserModel.findOne({ email });
        if (isRegistered) {
          return res.status(409).send({ status: "failed", message: "User already registered. Try to login." });
        } else {
          return res.status(404).send({ status: "failed", message: "User not registered. Please try to register first." });
        }
      }

      const otpMatch = await bcrypt.compare(otp, tempUser.otp);
      if (!otpMatch) {
        return res.status(400).send({ status: "failed", message: "Invalid OTP. Please provide a valid OTP." });
      }

      if (tempUser.otp_expiry && tempUser.otp_expiry.getTime() < Date.now()) {
        return res.status(410).send({ status: "failed", message: "OTP has expired. Please try to register again." });
      }

      const user = new UserModel({
        name: tempUser.name,
        email: tempUser.email,
        password: tempUser.password,
        tc: tempUser.tc
      });

      const { accessToken, refreshToken } = await user.generateAccessAndRefreshToken();

      await user.save();

      await TempUserModel.deleteOne({ email });

      const options: TokenOptions = {
        httpOnly: true,
        secure: true
      };

      return res.status(201)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", refreshToken, options)
        .send({ status: "success", message: "Registration successful", accessToken, refreshToken });
    } catch (error) {
      console.log(error);
      return res.status(500).send({ status: "failed", message: "Unable to verify OTP" });
    }
  };

}

export default RegisterController;
