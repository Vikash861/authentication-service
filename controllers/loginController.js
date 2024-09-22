import UserModel from '../models/User.js'
import TempUserModel from '../models/TempUser.js'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import transporter from '../config/emailConfig.js'
import generateOTP from '../utils/otpGenerator.js'
import sendOTPEmail from '../utils/sendOtpEmail.js'


class loginController {

    static userLogin = async (req, res) => {
        try {
            const { email, password } = req.body;
            if (email && password) {
                const user = await UserModel.findOne({ email: email });
                if (user != null) {
                    const passwordMatch = await user.isPasswordCorrect(password);
                    if ((user.email === email) && passwordMatch) {

                        const otp = generateOTP();
                        const salt = await bcrypt.genSalt(10)
                        const hashedOtp = await bcrypt.hash(otp, salt)
                        user.otp = hashedOtp;
                        user.otp_expiry = Date.now() + 5 * 60000;

                        await user.save();

                        await sendOTPEmail(email, 'Login Otp', `Your Login Otp is ${otp}`)

                        return res.status(200).send({ "status": "success", "message": "OTP sent to your email. Verify it to complete login."});

                    } else {
                        return res.status(401).send({ "status": "failed", "message": "Email or Password is not valid" });
                    }
                } else {
                    return res.status(404).send({ "status": "failed", "message": "You are not a Registered User" });
                }
            } else {
                return res.status(400).send({ "status": "failed", "message": "All Fields are Required" });
            }
        } catch (error) {
            console.log(error);
            res.status(500).send({ "status": "failed", "message": "Unable to Login" });
        }
    };

    static verifyLoginOtp = async (req, res) => {
        const { email, otp } = req.body;

        if (!email || !otp) {
            return res.status(400).send({ "status": "failed", "message": "Missing required fields" });
        }

        try {
            const user = await UserModel.findOne({ email });

            if (!user) {
                return res.status(400).send({ "status": "failed", "message": "User not registered. Please sign up." });
            }

            const otpMatch = await bcrypt.compare(otp, user.otp);
            if (!otpMatch) {
                return res.status(401).send({ "status": "failed", "message": "Invalid Otp" });
            }

            if (user.otp_expiry < Date.now()) {
                return res.status(400).send({ "status": "failed", "message": "OTP has expired please try resend otp" });
            }

            // cleaning up otp and expiration from user
            user.otp = null;
            user.otp_expiry = null;
            await user.save();

            const options = {
                httpOnly: true,
                secure: true
            }

            const { accessToken, refreshToken } = await user.generateAccessAndRefreshToken();
            return res.status(200)
            .cookie("accessToken", accessToken, options)
            .cookie("refreshToken", refreshToken, options)
            .send({ "status": "success", "message": "Login successful", "accessToken": accessToken, "refreshToken": refreshToken });
        } catch (error) {
            console.log(error);
            return res.status(500).send({ "status": "failed", "message": "Unable to verify OTP" });
        }
    };

}


export default loginController;