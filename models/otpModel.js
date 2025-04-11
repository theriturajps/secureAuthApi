const mongoose = require('mongoose');

const otpSchema = new mongoose.Schema({
	email: { type: String, required: true },
	newEmail: { type: String },
	otp: { type: String, required: true },
	purpose: {
		type: String,
		enum: ['verification', 'password-reset', 'email-update'],
		default: 'verification'
	},
	attempts: { type: Number, default: 0 },
	createdAt: { type: Date, default: Date.now, expires: '10m' } // 10 minutes
});

const OTP = mongoose.model('OTP', otpSchema);

module.exports = OTP;