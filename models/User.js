import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, trim: true },
  password: { type: String, required: true, trim: true },
  otp: { type: String, default: null },
  otp_expiry: { type: Date, default: null },
  refreshToken: { type: String },
  tc: { type: Boolean, required: true }
})

userSchema.methods.isPasswordCorrect = async function(password){
  return await bcrypt.compare(password, this.password)
}

userSchema.methods.generateAccessToken = function(){
  return jwt.sign(
      {
          _id: this._id,
          email: this.email,
      },
      process.env.ACCESS_TOKEN_SECRET,
      {
          expiresIn: process.env.ACCESS_TOKEN_EXPIRY
      }
  )
}

userSchema.methods.generateRefreshToken = function(){
  return jwt.sign(
      {
          _id: this._id,
      },
      process.env.REFRESH_TOKEN_SECRET,
      {
          expiresIn: process.env.REFRESH_TOKEN_EXPIRY
      }
  )
}

userSchema.methods.generateAccessAndRefreshToken = async function () {
  const accessToken = this.generateAccessToken()
  const refreshToken = this.generateRefreshToken()
  this.refreshToken = refreshToken
  await this.save()
  return { accessToken, refreshToken }
}


const UserModel = mongoose.model("user", userSchema)

export default UserModel