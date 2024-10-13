import { Request, Response, NextFunction } from 'express';
import jwt, { JwtPayload } from 'jsonwebtoken';
import UserModel, { IUser } from '../models/User.js';

export interface CustomRequest extends Request {
  user?: IUser; 
}

const checkUserAuth = async (req: CustomRequest, res: Response, next: NextFunction): Promise<void> => {
  try {
    const token: string | undefined = req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ", "");

    if (!token) {
      res.status(401).send({ status: "failed", message: "Unauthorized request" });
      return
    }

    const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET as string) as JwtPayload;

    const user = await UserModel.findById(decodedToken._id).select("-password -refreshToken");

    if (!user) {
      res.status(403).send({ status: "failed", message: "User not found" });
      return
    }

    if (user.logoutAt && decodedToken.iat && decodedToken.iat * 1000 < new Date(user.logoutAt).getTime()) {
      res.status(403).send({ status: "failed", message: "You're being logged out. Please login again." });
      return
    }

    req.user = user;
    next();
  } catch (error) {
    console.error(error);
    res.status(401).send({ status: "failed", message: "Invalid access token" });
    return
  }
};

export default checkUserAuth;
