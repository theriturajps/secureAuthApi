const transporter = require('../config/mailer');
const { AppError } = require('../middleware/errorMiddleware');

const sendEmail = async (options) => {
	try {
		const mailOptions = {
			from: {
				name: "SecureAuth",
				address: process.env.SMTP_USER,
			},
			to: options.email,
			subject: options.subject,
			text: options.message,
			html: options.html
		};

		await transporter.sendMail(mailOptions);
	} catch (err) {
		console.error('Error sending email:', err);
		throw new AppError('There was an error sending the email. Try again later!', 500);
	}
};

const getEmailTemplate = (user, content, subject) => {
	return `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; border: 1px solid #e0e0e0; border-radius: 8px;">
        <div style="background-color: #0084ff; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0;">
            <h2>${subject}</h2>
        </div>
        <div style="padding: 20px;">
            <p>Dear ${user.email},</p>
            ${content}
            <p style="margin-top: 30px;">Thank You,<br><strong>SecureAuth Team</strong></p>
        </div>
        <div style="background-color: #f5f5f5; padding: 10px; text-align: center; font-size: 12px; color: #666; border-radius: 0 0 8px 8px;">
            <p>This is an automated message. Please do not reply.</p>
        </div>
    </div>
    `;
};

const sendVerificationEmail = async (user, otp) => {
	const subject = 'Email Verification';
	const content = `
        <p>Please use the following OTP to verify your email address:</p>
        <div style="background-color: #f5f5f5; padding: 15px; margin: 20px 0; text-align: center; font-size: 24px; font-weight: bold; letter-spacing: 2px;">
            ${otp}
        </div>
        <p>This OTP will expire in <strong>10 minutes</strong>.</p>
        <p>If you didn't request this, please ignore this email.</p>
    `;

	await sendEmail({
		email: user.email,
		subject,
		message: `Your verification OTP is ${otp}`,
		html: getEmailTemplate(user, content, subject)
	});
};

const sendPasswordResetOTP = async (user, otp) => {
	const subject = 'Password Reset OTP';
	const content = `
        <p>We received a request to reset your password. Here's your OTP:</p>
        <div style="background-color: #f5f5f5; padding: 15px; margin: 20px 0; text-align: center; font-size: 24px; font-weight: bold; letter-spacing: 2px;">
            ${otp}
        </div>
        <p>This OTP will expire in <strong>10 minutes</strong>.</p>
        <p>If you didn't request a password reset, please secure your account.</p>
    `;

	await sendEmail({
		email: user.email,
		subject,
		message: `Your password reset OTP is ${otp}`,
		html: getEmailTemplate(user, content, subject)
	});
};

module.exports = {
	sendEmail,
	sendVerificationEmail,
	sendPasswordResetOTP
};