import UserModel from '../models/User.js'
import TempUserModel from '../models/TempUser.js'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import transporter from '../config/emailConfig.js'
import generateOTP from '../utils/otpGenerator.js'
import sendOTPEmail from '../utils/sendOtpEmail.js'

class UserController {

  static genericController = async (req, res) => {
    const { password, password_confirmation } = req.body
    if (password && password_confirmation) {
      if (password !== password_confirmation) {
        res.send({ "status": "failed", "message": "New Password and Confirm New Password doesn't match" })
      } else {
        const salt = await bcrypt.genSalt(10)
        const newHashPassword = await bcrypt.hash(password, salt)
        await UserModel.findByIdAndUpdate(req.user._id, { $set: { password: newHashPassword } })
        res.send({ "status": "success", "message": "Password changed succesfully" })
      }
    } else {
      res.send({ "status": "failed", "message": "All Fields are Required" })
    }
  }

  static loggedUser = async (req, res) => {
    res.send({ "user": req.user })
  }

  static logout = async (req, res) => {
    try {
      await UserModel.findByIdAndUpdate(
          req.user._id,
          {
            $unset: {
              refreshToken: 1
            }
          },
          {
            new: true
          }
      )
      const options = {
        httpOnly: true,
        secure: true
      }
      return res.status(200).clearCookie("accessToken", options).clearCookie("refreshToken", options).send({"status": "success", "message": "user logged out"})
    }catch (error){
      console.error(error)
      return res.status(500).send({"status": "failed", "message":"unable to logged out user"})
    }
  }

  static refreshToken = async (req, res) => {
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken;

    if (!incomingRefreshToken) {
      return res.status(401).send({"status": "failed", "message": "unauthorized request"})
    }

    try{
      const decodedToken = jwt.verify(
          incomingRefreshToken,
          process.env.REFRESH_TOKEN_SECRET
      )

      const user = await UserModel.findById(decodedToken?._id)

      if (!user) {
        return res.status(401).send({"status": "failed", "message": "unauthorized refresh Token"})
      }

      if (incomingRefreshToken !== user?.refreshToken) {
        return res.status(401).send({"status":"failed", "message": "Refresh token is expired or used"})
      }

      const options = {
        httpOnly: true,
        secure: true
      }

      const {accessToken, refreshToken} = await user.generateAccessAndRefreshToken()

      return res.status(200)
          .cookie("accessToken", accessToken, options)
          .cookie("refreshToken", refreshToken, options)
          .send({"status": "success", "message": "Access Token refreshed", "accessToken": accessToken, "refreshToken": refreshToken})

    }catch (error){
      console.error(error)
      return res.status(500).send({"status": "failed", "message": "Unable to refresh token"})
    }

  }

  static resendOtp = async (req, res) => {

    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ "status": "failed", "message": "Email is required" });
    }

    try {

      const user = await UserModel.findOne({ email });
  
      if (!user) {
        return res.status(404).json({ "status": "failed", "message": "User not found. try to register" });
      }
  
      const otp = generateOTP();
      const salt = await bcrypt.genSalt(10);
      const hashedOtp = await bcrypt.hash(otp, salt);
  
      user.otp = hashedOtp;
      user.otp_expiry = Date.now() + 5 * 60000;
      await user.save(); 

      await sendOTPEmail(email, 'Resend OTP', `Your OTP is ${otp}`);

      return res.status(200)
        .send({ "status": "success", "message": "OTP sent to your email. Verify it to complete login.", });
  
    } catch (error) {
      console.error("Error in resending OTP:", error);
      return res.status(500).json({ "status": "failed", "message": "An error occurred. Please try again later." });
    }

  }
  

}

export default genericController