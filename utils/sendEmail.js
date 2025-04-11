const transporter = require('../config/mailer');
const { AppError } = require('../middleware/errorMiddleware');

const sendEmail = async (options) => {
	try {
		if (!options.email) {
			throw new Error('Recipient email is required');
		}

		const mailOptions = {
			from: {
				name: "secureAuth",
				address: process.env.SMTP_USER,
			},
			to: options.email,
			subject: options.subject || 'No Subject',
			text: options.message || '',
			html: options.html || ''
		};

		await transporter.sendMail(mailOptions);
		return true;
	} catch (err) {
		console.error('Error sending email:', err);
		throw new AppError('There was an error sending the email. Try again later!', 500);
	}
};

const getSimpleEmailTemplate = (user, content) => {
	return `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="margin-bottom: 20px;">
            <p>Dear ${user.email || 'User'},</p>
            ${content}
            <p>Thank You,<br><strong>secureAuth Team</strong></p>
        </div>
        <div style="background-color: #0084ff; color: #fff; padding: 10px; text-align: center; font-size: 12px;">
            <strong>Note:</strong> This is a system generated email. Please do not reply.
        </div>
    </div>
    `;
};

const sendVerificationEmail = async (user, otp) => {
	const subject = 'Email Verification';
	const message = `Your OTP for email verification is ${otp}. It will expire in 10 minutes.`;

	const content = `
        <p>Please use this OTP to verify your email address:</p>
        <p style="font-size: 18px; font-weight: bold; color: #0084ff;">${otp}</p>
        <p><em>This code will expire in 10 minutes.</em></p>
    `;

	await sendEmail({
		email: user.email,
		subject,
		message,
		html: getSimpleEmailTemplate(user, content)
	});
};

const sendPasswordResetOTP = async (user, otp) => {
	const subject = 'Password Reset OTP';
	const message = `Your OTP for password reset is ${otp}. It will expire in 10 minutes.`;

	const content = `
        <p>Please use this OTP to reset your password:</p>
        <p style="font-size: 18px; font-weight: bold; color: #0084ff;">${otp}</p>
        <p><em>This code will expire in 10 minutes.</em></p>
        <p>If you did not request a password reset, please ignore this email and your password will remain unchanged.</p>
    `;

	await sendEmail({
		email: user.email,
		subject,
		message,
		html: getSimpleEmailTemplate(user, content)
	});
};

const sendEmailChangeNotification = async (user, newEmail) => {
	const subject = 'Email Change Notification';
	const message = `Your email has been changed to ${newEmail}. If you did not make this change, please contact support immediately.`;

	const content = `
        <p>Your email address has been successfully changed to:</p>
        <p style="font-size: 18px; font-weight: bold; color: #0084ff;">${newEmail}</p>
        <p><em>If you did not make this change, please contact support immediately.</em></p>
    `;

	await sendEmail({
		email: newEmail,
		subject,
		message,
		html: getSimpleEmailTemplate(user, content)
	});
}

module.exports = {
	sendEmail,
	sendVerificationEmail,
	sendPasswordResetOTP,
	sendEmailChangeNotification
};