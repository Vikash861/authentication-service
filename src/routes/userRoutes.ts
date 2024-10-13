import express, { Request, Response, NextFunction } from 'express';
import genericController from '../controllers/genericController.js';
import checkUserAuth from '../middlewares/auth-middleware.js';
import ForgotPasswordController from '../controllers/forgotPasswordController.js';
import regisgterController from '../controllers/registerController.js';
import loginController from '../controllers/loginController.js';
import { CustomRequest } from '../middlewares/auth-middleware.js';

const router = express.Router();

// Apply the auth middleware to these routes
router.use('/changepassword', checkUserAuth);
router.use('/loggeduser', checkUserAuth);
router.use('/logout', checkUserAuth);

// Public Routes
router.post('/register', (req: Request, res: Response) => { regisgterController.userRegistration(req, res) });
router.post('/verify-otp', (req: Request, res: Response) => { regisgterController.verifyOtp(req, res) });
router.post('/login', (req: Request, res: Response) => { loginController.userLogin(req, res) });
router.post('/verify-login-otp', (req: Request, res: Response) => { loginController.verifyLoginOtp(req, res) });
router.post('/forgot-password', (req: Request, res: Response) => { ForgotPasswordController.forgotPassword(req, res) });
router.post('/verify-forgot-password-otp', (req: Request, res: Response) => { ForgotPasswordController.verifyForgotPasswordOtp(req, res) });
router.post('/refresh-token', (req: Request, res: Response) => { genericController.refreshToken(req, res) });
router.post('/resend-otp', (req: Request, res: Response) => { genericController.resendOtp(req, res) });
router.post('/set-new-password', (req: Request, res: Response) => { ForgotPasswordController.setNewPassword(req, res) });

// Protected Routes (Using CustomRequest type)
router.post('/changepassword', (req: CustomRequest, res: Response) => { genericController.changeUserPassword(req, res) });
router.get('/loggeduser', (req: CustomRequest, res: Response) => { genericController.loggedUser(req, res) });
router.post('/logout', (req: CustomRequest, res: Response) => { genericController.logout(req, res) });

export default router;
