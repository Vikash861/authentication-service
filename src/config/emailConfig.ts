import dotenv from 'dotenv'
import nodemailer, {Transporter} from 'nodemailer'

dotenv.config()

interface EmailConfig{
  host:string
  port:number
  secure: boolean
  auth: {
    user: string
    pass: string
  }
}

const emailConfig: EmailConfig = {
  host: process.env.EMAIL_HOST as string,
  port: Number(process.env.EMAIL_PORT),
  secure: process.env.EMAIL_SECURE === 'true',
  auth: {
    user: process.env.EMAIL_USER as string,
    pass: process.env.EMAIL_PASS as string,
  },
}


const transporter: Transporter = nodemailer.createTransport(emailConfig)

export default transporter