const transporter = require('../config/mailer');
const { AppError } = require('../middleware/errorMiddleware');

const sendEmail = async (options) => {
	try {
		const mailOptions = {
			from: process.env.SMTP_USER,
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

const sendVerificationEmail = async (user, otp) => {
	const subject = 'Email Verification';
	const message = `Your OTP for email verification is ${otp}. It will expire in 10 minutes.`;

	await sendEmail({
		email: user.email,
		subject,
		message,
		html: `<p>Your OTP for email verification is <strong>${otp}</strong>. It will expire in 10 minutes.</p>`
	});
};

const sendPasswordResetOTP = async (user, otp) => {
	const subject = 'Password Reset OTP';
	const message = `Your OTP for password reset is ${otp}. It will expire in 10 minutes.`;

	await sendEmail({
		email: user.email,
		subject,
		message,
		html: `<p>Your OTP for password reset is <strong>${otp}</strong>. It will expire in 10 minutes.</p>`
	});
};

module.exports = {
	sendEmail,
	sendVerificationEmail,
	sendPasswordResetOTP
};