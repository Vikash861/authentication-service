import transporter from '../config/emailConfig.js';
import { SentMessageInfo } from 'nodemailer';

interface IMailOptions{
    from: string;
    to: string;
    subject: string;
    text: string;
}


const sendOTPEmail = async (email: string, subject: string, content: string): Promise<SentMessageInfo> => {
    const mailOptions:IMailOptions = {
        from: process.env.EMAIL as string,
        to: email,
        subject: subject,
        text: content
    };
    return transporter.sendMail(mailOptions);
}

export default sendOTPEmail;
