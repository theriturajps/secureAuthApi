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
	expiresAt: {
		type: Date,
		default: () => new Date(Date.now() + 10 * 60 * 1000), // 10 minutes from now
		index: { expires: 0 } // TTL index
	}
});

// Create TTL index
otpSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const OTP = mongoose.model('OTP', otpSchema);

module.exports = OTP;