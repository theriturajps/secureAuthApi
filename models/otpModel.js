const mongoose = require('mongoose');

const otpSchema = new mongoose.Schema({
	email: { type: String, required: true }, // Current email
	newEmail: { type: String }, // New email (for email updates)
	otp: { type: String, required: true },
	purpose: { type: String, enum: ['verification', 'password-reset', 'email-update'], default: 'verification' },
	createdAt: { type: Date, default: Date.now, expires: '600' } // 10 minutes
});

const OTP = mongoose.model('OTP', otpSchema);

module.exports = OTP;