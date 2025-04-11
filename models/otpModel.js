const mongoose = require('mongoose');

const otpSchema = new mongoose.Schema({
	email: { type: String, required: true },
	newEmail: { type: String },
	otp: { type: String, required: true },
	purpose: {
		type: String,
		enum: ['verification', 'password-reset', 'email-update'],
		default: 'verification',
		required: true
	},
	expiresAt: {
		type: Date,
		default: () => new Date(Date.now() + 10 * 60 * 1000), // 10 minutes from now
		index: { expires: '10m' }
	},
	createdAt: { type: Date, default: Date.now }
});

const OTP = mongoose.model('OTP', otpSchema);

module.exports = OTP;