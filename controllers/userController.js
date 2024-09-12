import UserModel from '../models/User.js'
import TempUserModel from '../models/TempUser.js'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import transporter from '../config/emailConfig.js'
import generateOTP from '../utils/otpGenerator.js'

class UserController {

  static userRegistration = async (req, res) => {
    const { name, email, password, password_confirmation, tc } = req.body
    const user = await UserModel.findOne({ email: email })
    if (user) {
      return res.send({ "status": "failed", "message": "Email already exists please try to login" })
    }

    if (name && email && password && password_confirmation && tc) {
      if (password === password_confirmation) {
        try {

          const otp = generateOTP()
          const salt = await bcrypt.genSalt(10)
          const hashPassword = await bcrypt.hash(password, salt)
          const tempUser = new TempUserModel({
            name: name,
            email: email,
            password: hashPassword,
            otp: otp,
            otpExpiration: Date.now() + 5 * 60000,
            tc: tc
          })
          await tempUser.save()
          // Send OTP to User's Email
          const mailOptions = {
            from: process.env.EMAIL,
            to: email,
            subject: 'Your OTP Code',
            text: `Your OTP code is ${otp}`
          };

          await transporter.sendMail(mailOptions);
          return res.status(200).send({ "status": "success", "message": "OTP sent to your email. Verify it to complete registration." });
        } catch (error) {
          console.log(error)
          res.send({ "status": "failed", "message": "Unable to send OTP" })
        }
      } else {
        res.send({ "status": "failed", "message": "Password and Confirm Password doesn't match" })
      }
    } else {
      res.send({ "status": "failed", "message": "All fields are required" })
    }

  }

  static verifyOtp = async (req, res) => {
    const { email, otp } = req.body;

    const tempUser = await TempUserModel.findOne({ email });

    if (!tempUser) {
      const isRegistered = await UserModel.findOne({ email });
      if (isRegistered) {
        return res.send({ "status": "failed", "message": "User already registered try to login" });
      } else {
        return res.send({ "status": "failed", "message": "User not registered. please try to" });
      }
    }

    if (tempUser.otp !== otp) {
      return res.send({ "status": "failed", "message": "Invalid or expired OTP" });
    }

    if (tempUser.otpExpiration < Date.now()) {
      return res.send({ "status": "failed", "message": "Otp has been expired" });
    }

    try {
      // Register user
      const user = new UserModel({
        name: tempUser.name,
        email: tempUser.email,
        password: tempUser.password,
        tc: tempUser.tc
      });
      // cleaning up the temporary user object
      await user.save();
      await TempUserModel.deleteOne({ email });
      // Generate JWT Token
      const token = jwt.sign({ userID: user._id }, process.env.JWT_SECRET_KEY, { expiresIn: '5d' });
      return res.status(201).send({ "status": "success", "message": "Registration successful", "token": token });
    } catch (error) {
      console.log(error);
      return res.send({ "status": "failed", "message": "Unable to verify OTP" });
    }
  }

  static userLogin = async (req, res) => {
    try {
      const { email, password } = req.body;
      if (email && password) {
        const user = await UserModel.findOne({ email: email });
        if (user != null) {
          const passwordMatch = await bcrypt.compare(password, user.password);
          if ((user.email === email) && password) {

            const otp = otpGenerator.generate(6, { digits: true, alphabets: false, upperCase: false, specialChars: false });

            user.otp = otp;
            user.otpExpiration = Date.now() + 5 * 60000;
            await user.save();

            const transporter = nodemailer.createTransport({
              service: 'gmail',
              auth: {
                user: process.env.EMAIL,
                pass: process.env.PASSWORD
              }
            });

            const mailOptions = {
              from: process.env.EMAIL,
              to: email,
              subject: 'Your OTP Code',
              text: `Your OTP code is ${otp}`
            };

            await transporter.sendMail(mailOptions);

            res.send({ "status": "success", "message": "OTP sent to your email. Verify it to complete login." });
          } else {
            res.send({ "status": "failed", "message": "Email or Password is not valid" });
          }
        } else {
          res.send({ "status": "failed", "message": "You are not a Registered User" });
        }
      } else {
        res.send({ "status": "failed", "message": "All Fields are Required" });
      }
    } catch (error) {
      console.log(error);
      res.send({ "status": "failed", "message": "Unable to Login" });
    }
  };

  static verifyLoginOtp = async (req, res) => {
    const { email, otp } = req.body;
  
    try {
      const user = await UserModel.findOne({ email });
  
      if (!user) {
        return res.send({ "status": "failed", "message": "User not registered. Please sign up." });
      }
      
      if (user.otp !== otp) {
        return res.send({ "status": "failed", "message": "Invalid Otp" });
      }
  
      if (user.otpExpiration < Date.now()) {
        return res.send({ "status": "failed", "message": "OTP has expired" });
      }
  

      const token = jwt.sign({ userID: user._id }, process.env.JWT_SECRET_KEY, { expiresIn: '5d' });
  
      // cleaning up otp and expiration from user
      user.otp = null;
      user.otpExpiration = null;
      await user.save();
  
      return res.status(200).send({ "status": "success", "message": "Login successful", "token": token });
    } catch (error) {
      console.log(error);
      return res.send({ "status": "failed", "message": "Unable to verify OTP" });
    }
  };
  
  static changeUserPassword = async (req, res) => {
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

  static sendUserPasswordResetEmail = async (req, res) => {
    const { email } = req.body
    if (email) {
      const user = await UserModel.findOne({ email: email })
      if (user) {
        const secret = user._id + process.env.JWT_SECRET_KEY
        const token = jwt.sign({ userID: user._id }, secret, { expiresIn: '15m' })
        const link = `http://127.0.0.1:3000/api/user/reset/${user._id}/${token}`
        console.log(link)
        // Send Email
        let info = await transporter.sendMail({
          from: process.env.EMAIL_FROM,
          to: user.email,
          subject: "Authenticaton - Password Reset Link",
          html: `<a href=${link}>Click Here</a> to Reset Your Password`
        })
        res.send({ "status": "success", "message": "Password Reset Email Sent... Please Check Your Email" })
      } else {
        res.send({ "status": "failed", "message": "Email doesn't exists" })
      }
    } else {
      res.send({ "status": "failed", "message": "Email Field is Required" })
    }
  }

  static userPasswordReset = async (req, res) => {
    const { password, password_confirmation } = req.body
    const { id, token } = req.params
    const user = await UserModel.findById(id)
    const new_secret = user._id + process.env.JWT_SECRET_KEY
    try {
      jwt.verify(token, new_secret)
      if (password && password_confirmation) {
        if (password !== password_confirmation) {
          res.send({ "status": "failed", "message": "New Password and Confirm New Password doesn't match" })
        } else {
          const salt = await bcrypt.genSalt(10)
          const newHashPassword = await bcrypt.hash(password, salt)
          await UserModel.findByIdAndUpdate(user._id, { $set: { password: newHashPassword } })
          res.send({ "status": "success", "message": "Password Reset Successfully" })
        }
      } else {
        res.send({ "status": "failed", "message": "All Fields are Required" })
      }
    } catch (error) {
      console.log(error)
      res.send({ "status": "failed", "message": "Invalid Token" })
    }
  }

}

export default UserController