const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const { isValidEmail } = require('../utils/validation');

const userSchema = new mongoose.Schema({
	username: {
		type: String,
		required: [true, 'Please provide a username'],
		unique: true,
		trim: true,
		minlength: [3, 'Username must be at least 3 characters'],
		maxlength: [20, 'Username must be less than 20 characters']
	},
	bio: {
		type: String,
		trim: true,
		maxlength: [60, 'Bio must be less than 60 characters'],
		default: 'Welcome! This is my bio.'
	},
	name: {
		type: String,
		trim: true,
		default: ''
	},
	profileImageUrl: {
		type: String,
		default: ''
	},
	email: {
		type: String,
		required: [true, 'Please provide an email'],
		unique: true,
		lowercase: true,
		validate: {
			validator: function (email) {
				return isValidEmail(email);
			},
			message: 'Please provide a valid email'
		}
	},
	password: {
		type: String,
		required: [true, 'Please provide a password'],
		minlength: [8, 'Password must be at least 8 characters'],
		select: false
	},
	passwordChangedAt: Date,
	isVerified: {
		type: Boolean,
		default: false
	},
	role: {
		type: String,
		enum: ['user', 'admin', 'moderator'],
		default: 'user'
	},
	refreshToken: {
		type: String
	}
}, {
	timestamps: true
});

// Hash password before saving
userSchema.pre('save', async function (next) {
	if (!this.isModified('password')) return next();

	this.password = await bcrypt.hash(this.password, 12);
	next();
});

// Update passwordChangedAt when password is modified
userSchema.pre('save', function (next) {
	if (!this.isModified('password') || this.isNew) return next();

	this.passwordChangedAt = Date.now() - 1000;
	next();
});

// Method to compare passwords
userSchema.methods.comparePassword = async function (candidatePassword, userPassword) {
	return await bcrypt.compare(candidatePassword, userPassword);
};

// Check if password was changed after token was issued
userSchema.methods.changedPasswordAfter = function (JWTTimestamp) {
	if (this.passwordChangedAt) {
		const changedTimestamp = parseInt(this.passwordChangedAt.getTime() / 1000, 10);
		return JWTTimestamp < changedTimestamp;
	}
	return false;
};

const User = mongoose.model('User', userSchema);

module.exports = User;