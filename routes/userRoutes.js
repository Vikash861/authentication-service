import express from 'express';
const router = express.Router();
import UserController from '../controllers/userController.js';
import checkUserAuth from '../middlewares/auth-middleware.js';
import ForgotPasswordController from '../controllers/forgotPasswordController.js';

// ROute Level Middleware - To Protect Route
router.use('/changepassword', checkUserAuth)
router.use('/loggeduser', checkUserAuth)

// Public Routes
router.post('/register', UserController.userRegistration)
router.post('/verify-otp', UserController.verifyOtp)
router.post('/login', UserController.userLogin)
router.post('/verify-login-otp', UserController.verifyLoginOtp)
router.post('/forgot-password', ForgotPasswordController.forgotPassword)
router.post('/verify-forgot-password-otp', ForgotPasswordController.verifyForgotPasswordOtp)
router.post('/set-new-password', ForgotPasswordController.setNewPassword)
router.post('/send-reset-password-email', UserController.sendUserPasswordResetEmail)
router.post('/reset-password/:id/:token', UserController.userPasswordReset)

// Protected Routes
router.post('/changepassword', UserController.changeUserPassword)
router.get('/loggeduser', UserController.loggedUser)


export default router