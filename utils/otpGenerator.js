import { generate } from "otp-generator";

function generateOTP() {
    const otp = Math.floor(100000 + Math.random() * 900000);
    return otp.toString();
  }
  
export default generateOTP;