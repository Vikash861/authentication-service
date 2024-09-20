import jwt from 'jsonwebtoken'
import UserModel from '../models/User.js'

var checkUserAuth = async (req, res, next) => {
  try {
    const token = req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ", "")

    if (!token) {
      return res.status(401).send({"status":"failed", "message":"Unauthorized request"})
    }

    const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET)

    const user = await UserModel.findById(decodedToken?._id).select("-password -refreshToken -otp -otp_expiry")

    if (!user) {
      res.status(401).send({"status":"failed", "message":"Invalid Access Token"})
    }

    req.user = user;
    next()
  } catch (error) {
    res.status(401).send({ "status": "failed", "message": "Unauthorized User" })
  }

}

export default checkUserAuth