const mongoose = require('mongoose');

const otpSchema = new mongoose.Schema({
	email: {
		type: String,
		required: true,
		index: true // Add index for better performance
	},
	newEmail: {
		type: String
	},
	otp: {
		type: String,
		required: true
	},
	purpose: {
		type: String,
		enum: ['verification', 'password-reset', 'email-update'],
		default: 'verification',
		index: true // Add index for better query performance
	},
	createdAt: {
		type: Date,
		default: Date.now,
		expires: '600' // 10 minutes expiry
	}
});

otpSchema.index({ email: 1, purpose: 1 });

const OTP = mongoose.model('OTP', otpSchema);

module.exports = OTP;