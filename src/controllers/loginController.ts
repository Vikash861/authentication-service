import UserModel, { IUser } from '../models/User.js'
import bcrypt from 'bcrypt'
import generateOTP from '../utils/otpGenerator.js'
import sendOTPEmail from '../utils/sendOtpEmail.js'
import { Request, Response } from 'express'


interface TokenOptions {
  httpOnly: boolean;
  secure: boolean;
}

class loginController {

  static userLogin = async (req: Request, res: Response): Promise<Response> => {
    try {

      const { email, password }: { email: string; password: string } = req.body;

      if (email && password) {

        const user: IUser | null = await UserModel.findOne({ email });

        if (user != null) {
          const passwordMatch: boolean = await user.isPasswordCorrect(password);

          if (passwordMatch) {
            const otp: string = generateOTP();
            const salt: string = await bcrypt.genSalt(10);
            const hashedOtp: string = await bcrypt.hash(otp, salt);

            user.otp = hashedOtp;
            user.otp_expiry = new Date(Date.now() + 5 * 60000);
            await user.save();

            await sendOTPEmail(email, 'Login Otp', `Your Login OTP is ${otp}`);

            return res.status(200).send({
              status: "success",
              message: "OTP sent to your email. Verify it to complete login."
            });
          } else {
            return res.status(401).send({ status: "failed", message: "Email or Password is not valid" });
          }
        } else {
          return res.status(404).send({ status: "failed", message: "You are not a Registered User" });
        }
      } else {
        return res.status(400).send({ status: "failed", message: "All Fields are Required" });
      }
    } catch (error) {
      console.error("Error during login:", error);
      return res.status(500).send({ status: "failed", message: "Unable to Login" });
    }
  };

  static verifyLoginOtp = async (req: Request, res: Response): Promise<Response> => {
    const { email, otp }: { email: string; otp: string } = req.body;

    if (!email || !otp) {
      return res.status(400).send({ status: "failed", message: "Missing required fields" });
    }

    try {
      const user: IUser | null = await UserModel.findOne({ email });

      if (!user) {
        return res.status(400).send({ status: "failed", message: "User not registered. Please sign up." });
      }

      if (!user.otp) {
        return res.status(400).send({ status: "failed", message: "Otp not found please login again" });
      }

      const otpMatch = await bcrypt.compare(otp, user.otp);
      if (!otpMatch) {
        return res.status(401).send({ status: "failed", message: "Invalid Otp" });
      }

      if (user.otp_expiry && user.otp_expiry.getTime() < Date.now()) {
        return res.status(400).send({ status: "failed", message: "OTP has expired, please try resend otp" });
      }

      // cleaning up logoutAt, otp and expiration from user
      await UserModel.updateOne(
        { _id: user._id },
        { $unset: { logoutAt: 1 }, $set: { otp: null, otp_expiry: null } }
      );

      const options: TokenOptions = {
        httpOnly: true,
        secure: true,
      };

      const { accessToken, refreshToken } = await user.generateAccessAndRefreshToken();
      return res
        .status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", refreshToken, options)
        .send({ status: "success", message: "Login successful", accessToken, refreshToken });
    } catch (error) {
      console.error(error);
      return res.status(500).send({ status: "failed", message: "Unable to verify OTP" });
    }
  };

}


export default loginController;