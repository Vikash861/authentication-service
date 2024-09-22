import generateOTP from '../utils/otpGenerator.js'
import transporter from '../config/emailConfig.js'
import findUserByEmail from "../utils/findUserByEmail.js";
import bcrypt from 'bcrypt'
import sendOTPEmail from '../utils/sendOtpEmail.js';

class ForgotPasswordController {

  static forgotPassword = async (req, res) => {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ "status": "failed", "message": "Please provide Email" });
    }

    try {
      const user = await findUserByEmail(email);
      if (!user) {
        return res.status(404).json({ "status": "failed", "message": "User not found. Please register first" });
      }

      const otp = generateOTP();
      const salt = await bcrypt.genSalt(10);
      user.otp = await bcrypt.hash(otp, salt);
      user.otp_expiry = Date.now() + 5 * 60000;
      await user.save();

      await transporter.sendMail(mailOptions);

      await sendOTPEmail(email, 'Forgot Password OTP', `Your forgot password OTP is ${otp}`)

      res.status(200).send({ "status": "success", "message": "OTP sent to your email." });

    } catch (error) {
      console.error(error);
      res.status(500).send({ "status": "failed", "message": "Unable to send OTP" });
    }

  };

  static verifyForgotPasswordOtp = async (req, res) => {
    const { email, otp } = req.body;
  
    if (!email || !otp) {
      return res.status(400).json({ "status": "failed", "message": "Missing required fields" });
    }

    try {
      const user = await findUserByEmail(email);

      const isOtpValid = await bcrypt.compare(otp, user.otp);;
      if (!isOtpValid) {
        return res.status(400).json({ "status": "failed", "message": "Invalid OTP" });
      }

      if (user.otp_expiry < Date.now()) {
        return res.status(410).json({ "status": "failed", "message": "OTP has expired" });
      }

      // Clear OTP after successful verification
      user.otp = null;
      user.otp_expiry = null;
      await user.save();

      const {accessToken, refreshToken} = await user.generateAccessAndRefreshToken();

      const options = {
        httpOnly: true,
        secure: true,
      }

      return res.status(200).cookie("accessToken", accessToken, options)
      .cookie("refreshToken", refreshToken, options)
      .json({
        "status": "success",
        "message": "OTP verified, use the token to reset your password.",
        "accessToken": accessToken,
        "refreshToken": refreshToken
      });


    } catch (error) {
      console.error(error);
      res.status(500).send({ "status": "failed", "message": "Error verifying OTP" });
    }
  };

  static setNewPassword = async (req, res) => {
    const { password, confirm_password } = req.body;
    const { email } = req.user;
    
    if (!password || !confirm_password) {
      return res.status(400).json({ "status": "failed", "message": "Please provide Password and Confirm Password" });
    }

    if (password !== confirm_password) {
      return res.status(400).json({ "status": "failed", "message": "Password and Confirm Password don't match" });
    }

    try {

      const user = await findUserByEmail(email);
      if (!user) {
        return res.status(400).json({ "status": "failed", "message": "User not found" });
      }
      
      // Hash and update the new password
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);
      user.password = hashedPassword;
      await user.save();

      return res.status(200)
      .json({ "status": "success", "message": "Password updated successfully" });

    } catch (error) {
      console.error(error);
      return res.status(500)
      .json({ "status": "failed", "message": "Error updating password" });
    }
    
  };

}


export default ForgotPasswordController;