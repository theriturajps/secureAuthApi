const User = require('../models/User');
const OTP = require('../models/otpModel');
const jwt = require('jsonwebtoken');
const AppError = require('../middleware/errorMiddleware').AppError;
const { signToken, createSendToken, generateOTP } = require('../utils/generateToken');
const { sendVerificationEmail, sendPasswordResetOTP } = require('../utils/sendEmail');

exports.signup = async (req, res, next) => {
	try {
		const { username, email, password, passwordConfirm } = req.body;

		// Check if user exists
		const existingUser = await User.findOne({ $or: [{ email }, { username }] });
		if (existingUser) {
			return next(new AppError('Email or username already in use!', 400));
		}

		const newUser = await User.create({
			username,
			email,
			password,
			passwordConfirm
		});

		// Generate OTP
		const otp = generateOTP();
		await OTP.create({ email, otp });

		// Send verification email
		await sendVerificationEmail(newUser, otp);

		res.status(201).json({
			status: 'success',
			message: 'OTP sent to email for verification!'
		});
	} catch (err) {
		next(err);
	}
};

exports.verifyEmail = async (req, res, next) => {
	try {
		const { email, otp } = req.body;

		if (!email || !otp) {
			return next(new AppError('Both email and OTP are required', 400));
		}

		// Find the most recent OTP for the email
		const otpRecord = await OTP.findOne({ email, purpose: 'verification' }).sort({ createdAt: -1 });

		if (!otpRecord) {
			return next(new AppError('No OTP found for this email', 400));
		}

		if (otpRecord.otp !== otp) {
			return next(new AppError('Invalid OTP!', 400));
		}

		// Update user verification status
		const user = await User.findOneAndUpdate(
			{ email },
			{ isVerified: true },
			{ new: true }
		);

		if (!user) {
			return next(new AppError('User not found!', 404));
		}

		// Delete the OTP record
		await OTP.deleteOne({ _id: otpRecord._id });

		// Log the user in
		await createSendToken(user, 200, res);
	} catch (err) {
		next(err);
	}
};

exports.login = async (req, res, next) => {
	try {
		const { username, password } = req.body;

		// 1) Check if username and password exist
		if (!username || !password) {
			return next(new AppError('Please provide username and password!', 400));
		}

		// 2) Check if user exists and password is correct
		const user = await User.findOne({ username }).select('+password');

		if (!user || !(await user.comparePassword(password, user.password))) {
			return next(new AppError('Incorrect username or password!', 401));
		}

		// 3) Check if user is verified
		if (!user.isVerified) {
			// Generate new OTP for unverified user
			const otp = generateOTP();
			await OTP.create({
				email: user.email,
				otp,
				purpose: 'verification'
			});

			// Send verification email
			await sendVerificationEmail(user, otp);

			return next(new AppError('Please verify your email to login! A new OTP has been sent.', 401));
		}

		// 4) If everything ok, send token to client
		await createSendToken(user, 200, res);
	} catch (err) {
		next(err);
	}
};

exports.logout = async (req, res, next) => {
	try {
		// Delete refresh token from database
		const user = await User.findById(req.user._id);

		if (user) {
			user.refreshToken = undefined;
			await user.save({ validateBeforeSave: false });
		}

		// Clear the cookies
		res.clearCookie('accessToken');

		res.status(200).json({
			status: 'success',
			message: 'Logged out successfully!',
			data: null
		});
	} catch (err) {
		next(err);
	}
};

exports.forgotPassword = async (req, res, next) => {
	try {
		const { email } = req.body;

		// 1) Get user based on POSTed email
		const user = await User.findOne({ email });
		if (!user) {
			return next(new AppError('There is no user with that email address.', 404));
		}

		// 2) Generate OTP
		const otp = generateOTP();
		await OTP.create({
			email,
			otp,
			purpose: 'password-reset'
		});

		// 3) Send it to user's email
		await sendPasswordResetOTP(user, otp);

		res.status(200).json({
			status: 'success',
			message: 'OTP sent to email!',
			otp: {
				expiresIn: `The OTP expires in 10 minutes.`
			}
		});
	} catch (err) {
		next(err);
	}
};

exports.verifyPasswordResetOTP = async (req, res, next) => {
	try {
		const { email, otp } = req.body;

		if (!email || !otp) {
			return next(new AppError('Both email and OTP are required', 400));
		}

		// Find the most recent OTP for the email with password-reset purpose
		const otpRecord = await OTP.findOne({
			email,
			purpose: 'password-reset'
		}).sort({ createdAt: -1 });

		if (!otpRecord) {
			return next(new AppError('No OTP found for password reset', 400));
		}

		if (otpRecord.otp !== otp) {
			return next(new AppError('Invalid OTP!', 400));
		}

		const userRecord = await User.findOne({ email }).select('-password');
		if (!userRecord) {
			return next(new AppError('User not found!', 404));
		}

		// Delete the OTP record
		await OTP.deleteOne({ _id: otpRecord._id });

		// Generate a temporary token for password reset
		const tempToken = jwt.sign(
			{ id: userRecord._id, email: userRecord.email, purpose: 'password-reset' },
			process.env.JWT_SECRET,
			{ expiresIn: '10m' }
		);

		userRecord.refreshToken = tempToken; // Store the tempToken in refreshToken field
		await userRecord.save({ validateBeforeSave: false });

		const cookieOptions = {
			expires: new Date(Date.now() + 10 * 60 * 1000), // 10 minutes
			httpOnly: true,
			secure: process.env.NODE_ENV === 'production',
			sameSite: 'strict'
		};

		res.cookie('tempToken', tempToken, cookieOptions);

		res.status(200).json({
			status: 'success',
			message: 'OTP verified!',
			token: {
				tempToken
			}
		});
	} catch (err) {
		next(err);
	}
};

exports.resetPassword = async (req, res, next) => {
	try {
		const { newPassword, newPasswordConfirm } = req.body;
		const tempToken = req.cookies?.tempToken || req.body.tempToken;

		// Check for missing fields
		if (!newPassword || !newPasswordConfirm) {
			return next(new AppError('Please provide newPassword and newPasswordConfirm!', 400));
		}

		// Check if passwords match
		if (newPassword !== newPasswordConfirm) {
			return next(new AppError('Passwords do not match!', 400));
		}

		// Check if tempToken is present
		if (!tempToken) {
			return next(new AppError('Reset token is required!', 400));
		}

		// 1) Verify tempToken
		let decoded;
		try {
			decoded = jwt.verify(tempToken, process.env.JWT_SECRET);
		} catch (err) {
			return next(new AppError('Invalid or expired token!', 401));
		}

		// 2) Find user
		const user = await User.findById(decoded.id);
		if (!user) {
			return next(new AppError('User not found!', 404));
		}

		// 3) Check if token matches the stored refresh token
		if (user.refreshToken !== tempToken) {
			return next(new AppError('Invalid token match!', 401));
		}

		// 4) Update password
		user.password = newPassword;
		user.passwordConfirm = newPasswordConfirm;

		// Save with validation
		await user.save();

		// 5) Clear refresh token and cookie
		user.refreshToken = undefined;
		await user.save({ validateBeforeSave: false });

		res.clearCookie('tempToken');

		// 6) Send success response
		res.status(200).json({
			status: 'success',
			message: 'Password has been reset successfully!',
		});
	} catch (err) {
		next(err);
	}
};

exports.refreshToken = async (req, res, next) => {
	try {
		const refreshToken = req.user.refreshToken; // Get the refresh token from the request

		if (!refreshToken) {
			return next(new AppError('Please provide a refresh token!', 400));
		}

		// 1) Verify refresh token
		const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);

		// 2) Check if user still exists and has this refresh token
		const currentUser = await User.findOne({
			_id: decoded.id,
			refreshToken: refreshToken
		});

		if (!currentUser) {
			return next(new AppError('Invalid refresh token!', 401));
		}

		// 3) Generate new access token
		const { accessToken, refreshToken: newRefreshToken } = signToken(currentUser._id, currentUser.email);

		// 4) Update refresh token in database
		currentUser.refreshToken = newRefreshToken;
		await currentUser.save({ validateBeforeSave: false });

		// 5) Set new access token in cookie
		const cookieOptions = {
			expires: new Date(
				Date.now() + process.env.COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000 // 7 days
			),
			httpOnly: true,
			secure: process.env.NODE_ENV === 'production',
			sameSite: 'strict'
		};

		res.cookie('accessToken', accessToken, cookieOptions);

		res.status(200).json({
			status: 'success',
			accessToken
		});
	} catch (err) {
		next(err);
	}
};