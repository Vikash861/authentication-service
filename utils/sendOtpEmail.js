import transporter from '../config/emailConfig.js'

const sendOTPEmail = async (email, subject, content) => {
    const mailOptions = {
      from: process.env.EMAIL,
      to: email,
      subject: subject,
      text: content
    };
    return transporter.sendMail(mailOptions);
}

export default sendOTPEmail;