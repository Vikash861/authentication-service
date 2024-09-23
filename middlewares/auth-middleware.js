import jwt from 'jsonwebtoken'
import UserModel from '../models/User.js'

const checkUserAuth = async (req, res, next) => {
  try {
    const token = req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ", "");
    if (!token) {
      return res.status(401).send({ status: "failed", message: "Unauthorized request" });
    }

    const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    const user = await UserModel.findById(decodedToken._id).select("-password -refreshToken");

    if (user.logoutAt && decodedToken.iat * 1000 < new Date(user.logoutAt).getTime()) {
      return res.status(401).send({ status: "failed", message: "You're being logged out. please login again" });
    }

    req.user = user;
    next();
  } catch (error) {
    console.error(error);
    res.status(401).send({ status: "failed", message: "Invalid access token" });
  }

}

export default checkUserAuth