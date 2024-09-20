import generateOTP from '../utils/otpGenerator.js'
import transporter from '../config/emailConfig.js'
import findUserByEmail from "../utils/findUserByEmail.js";
import bcrypt from 'bcrypt'

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

      const mailOptions = {
        from: process.env.EMAIL,
        to: email,
        subject: 'Your OTP Code',
        text: `Your OTP code is ${otp}`
      };

      await transporter.sendMail(mailOptions);

      const accessToken = await user.getAccessToken();
      const options = {
        httpOnly: 'true',
        secure: 'true',
      }
      res.status(200).cookie("accessToken", accessToken, options).send({ "status": "success", "message": "OTP sent to your email. Verify it to complete login.", "accessToken": accessToken });

    } catch (error) {
      console.error(error);
      res.status(500).send({ "status": "failed", "message": "Unable to send OTP" });
    }

  };

  static verifyForgotPasswordOtp = async (req, res) => {
    const { otp } = req.body;
    const token = req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ", "")
    if (!token) {
      return res.status(401).send({ "status": "failed", "message": "Unauthorized request" })
    }
    const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET)
    const email = decodedToken?.email;

    if (!otp) {
      return res.status(400).json({ "status": "failed", "message": "OTP not provided" });
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

      const accessToken = await user.getAccessToken();

      const options = {
        httpOnly: true,
        secure: true,
      }

      return res.status(200).cookie("accessToken", accessToken, options).json({
        "status": "success",
        "message": "OTP verified, use the token to reset your password.",
        "accessToken": accessToken
      });


    } catch (error) {
      console.error(error);
      res.status(500).send({ "status": "failed", "message": "Error verifying OTP" });
    }
  };

  static setNewPassword = async (req, res) => {
    const { password, confirm_password } = req.body;
    const token = req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ", "")
    if (!token) {
      return res.status(401).send({ "status": "failed", "message": "Unauthorized request" })
    }
    const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET)
    const email = decodedToken?.email;

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

      return res.status(200).json({ "status": "success", "message": "Password updated successfully" });

    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        return res.status(401).json({ "status": "failed", "message": "Access token expired, please request a new OTP" });
      }
      console.error(error);
      return res.status(500).json({ "status": "failed", "message": "Error updating password" });
    }
  };

}


export default ForgotPasswordController;