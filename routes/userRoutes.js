import express from 'express';
const router = express.Router();
import genericController from '../controllers/genericController.js';
import checkUserAuth from '../middlewares/auth-middleware.js';
import ForgotPasswordController from '../controllers/forgotPasswordController.js';
import regisgterController from '../controllers/registerController.js';
import loginController from '../controllers/loginController.js';

// Route Level Middleware - To Protect Route
router.use('/set-new-password', checkUserAuth)
router.use('/changepassword', checkUserAuth)
router.use('/loggeduser', checkUserAuth)
router.use('/logout', checkUserAuth)

// Public Routes
router.post('/register', regisgterController.userRegistration)
router.post('/verify-otp', regisgterController.verifyOtp)
router.post('/login', loginController.userLogin)
router.post('/verify-login-otp', loginController.verifyLoginOtp)
router.post('/forgot-password', ForgotPasswordController.forgotPassword)
router.post('/verify-forgot-password-otp', ForgotPasswordController.verifyForgotPasswordOtp)
router.post('/refresh-token', genericController.refreshToken)
router.post('/resend-otp', genericController.resendOtp)
// Protected Route
router.post('/set-new-password', ForgotPasswordController.setNewPassword)
router.post('/changepassword', genericController.changeUserPassword)
router.get('/loggeduser', genericController.loggedUser)
router.post('/logout', genericController.logout)



export default router